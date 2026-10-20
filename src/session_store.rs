//! Bounded, per-session durable stream-management slots. Socket handles are never stored.
//!
//! Recovery is deliberately strict: malformed, oversized, or inconsistent committed
//! slots fail startup instead of silently losing acknowledged session state. Uncommitted
//! UUID temporary files are discarded; the last renamed JSON slot remains authoritative.
use crate::sessions::Session;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const SLOT_LIMIT: usize = 8 * 1024 * 1024;
const TOTAL_LIMIT: usize = 256 * 1024 * 1024;
const SESSION_LIMIT: usize = 4096;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Record {
    version: u8,
    pub jid: String,
    pub owner: String,
    pub connection: String,
    pub client_id: Option<String>,
    pub push_identifier: Option<String>,
    pub first_push_sent: bool,
    pub available: bool,
    pub priority: i8,
    pub presence: Option<String>,
    pub carbons: bool,
    pub csi: crate::csi::DurableBuffer,
    pub roster_interested: bool,
    pub resume_id: String,
    pub handled: u32,
    pub sent: u32,
    pub acked: u32,
    pub ack_limit: usize,
    pub pending: std::collections::VecDeque<String>,
    pub deadline_ms: u64,
    pub timeout_ms: u64,
}
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
impl Record {
    fn from_session(s: &Session) -> Result<Self> {
        ensure!(!s.closed && s.sm, "session is not resumable");
        let remaining = s
            .expires
            .map(|v| v.saturating_duration_since(Instant::now()))
            .unwrap_or(s.timeout);
        Ok(Self {
            version: 1,
            jid: s.jid.clone(),
            owner: s.owner.clone(),
            connection: s.connection.clone(),
            client_id: s.client_id.clone(),
            push_identifier: s.push_identifier.clone(),
            first_push_sent: s.first_push_sent,
            available: s.available,
            priority: s.priority,
            presence: s.presence.clone(),
            carbons: s.carbons,
            csi: s.csi.durable(),
            roster_interested: s.roster_interested,
            resume_id: s
                .resume_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing resume token"))?,
            handled: s.handled,
            sent: s.sent,
            acked: s.acked,
            ack_limit: s.ack_limit,
            pending: s.pending.clone(),
            deadline_ms: now_ms()
                .saturating_add(remaining.as_millis().min(u64::MAX as u128) as u64),
            timeout_ms: s.timeout.as_millis().min(u64::MAX as u128) as u64,
        })
    }
    pub fn session(self) -> Session {
        Session {
            jid: self.jid,
            owner: self.owner,
            connection: self.connection,
            client_id: self.client_id,
            push_identifier: self.push_identifier,
            first_push_sent: self.first_push_sent,
            sender: None,
            available: self.available,
            priority: self.priority,
            presence: self.presence,
            carbons: self.carbons,
            csi: crate::csi::Buffer::from_durable(self.csi),
            roster_interested: self.roster_interested,
            sm: true,
            resume_id: Some(self.resume_id),
            handled: self.handled,
            sent: self.sent,
            acked: self.acked,
            ack_limit: self.ack_limit,
            ack_requested: false,
            pending: self.pending,
            expires: Some(
                Instant::now() + Duration::from_millis(self.deadline_ms.saturating_sub(now_ms())),
            ),
            timeout: Duration::from_millis(self.timeout_ms),
            closed: false,
            close_condition: None,
            cancel: Default::default(),
            durable: None,
        }
    }
}
#[derive(Debug)]
pub(crate) struct Store {
    root: PathBuf,
    _lock: File,
    slots: Mutex<BTreeMap<String, (String, usize)>>,
}
fn store(session: &Session) -> Result<Option<Arc<Store>>> {
    session
        .durable
        .as_ref()
        .map(|weak| {
            weak.upgrade()
                .ok_or_else(|| anyhow::anyhow!("durable session hub was dropped"))
        })
        .transpose()
}
pub(crate) fn enable(s: &Session) -> Result<()> {
    if let Some(store) = store(s)?
        && s.resume_id.is_some()
    {
        store.write(s, None)?;
    }
    Ok(())
}
pub(crate) fn checkpoint(s: &Session) -> Result<()> {
    if let Some(store) = store(s)?
        && s.resume_id.is_some()
    {
        store.write(s, Some(&s.connection))?;
    }
    Ok(())
}
pub(crate) fn claim(old: &Session, new: &Session) -> Result<()> {
    if let Some(store) = store(old)?
        && old.resume_id.is_some()
    {
        store.write(new, Some(&old.connection))?;
    }
    Ok(())
}
pub(crate) fn remove(s: &Session) -> Result<()> {
    if let Some(store) = store(s)?
        && let Some(id) = &s.resume_id
    {
        store.remove(id, &s.connection)?;
    }
    Ok(())
}
impl Store {
    pub fn open(path: &Path) -> Result<(Arc<Self>, Vec<Record>)> {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.join("store.lock"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            lock.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        lock.try_lock()
            .map_err(|error| anyhow::anyhow!("stream management store already in use: {error}"))?;
        let store = Arc::new(Self {
            root: path.into(),
            _lock: lock,
            slots: Default::default(),
        });
        let mut recovered = vec![];
        let mut total = 0usize;
        let entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        // A crash before rename can leave an incomplete slot. Only canonical UUID
        // regular files belong to our writer; preserve unknown names and symlinks.
        for entry in &entries {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = name.strip_suffix(".tmp") {
                let owned = safe_id(id).is_ok()
                    && uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id);
                if owned && entry.file_type()?.is_file() {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        File::open(path)?.sync_all()?;
        for entry in entries {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".json") {
                continue;
            }
            ensure!(
                entry.file_type()?.is_file(),
                "invalid stream management slot"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
            }
            let len = entry.metadata()?.len() as usize;
            ensure!(len <= SLOT_LIMIT, "stream management slot too large");
            total = total.saturating_add(len);
            ensure!(
                total <= TOTAL_LIMIT && recovered.len() < SESSION_LIMIT,
                "stream management store limit"
            );
            let mut bytes = vec![];
            File::open(entry.path())?
                .take(SLOT_LIMIT as u64 + 1)
                .read_to_end(&mut bytes)?;
            let record: Record = serde_json::from_slice(&bytes)?;
            ensure!(
                record.version == 1
                    && record.pending.len() <= 4096
                    && record.sent.wrapping_sub(record.acked) as usize == record.pending.len()
                    && crate::protocol::bare(&record.jid) == record.owner
                    && record.jid.contains('/'),
                "invalid durable session"
            );
            ensure!(
                name == format!("{}.json", safe_id(&record.resume_id)?),
                "invalid slot token"
            );
            if record.deadline_ms <= now_ms() {
                fs::remove_file(entry.path())?;
                continue;
            }
            store
                .slots
                .lock()
                .unwrap()
                .insert(record.resume_id.clone(), (record.connection.clone(), len));
            recovered.push(record);
        }
        File::open(path)?.sync_all()?;
        Ok((store, recovered))
    }
    fn write(&self, s: &Session, expected: Option<&str>) -> Result<()> {
        let record = Record::from_session(s)?;
        ensure!(
            record.pending.len() <= 4096,
            "stream management queue limit"
        );
        let bytes = serde_json::to_vec(&record)?;
        ensure!(bytes.len() <= SLOT_LIMIT, "stream management slot limit");
        let name = safe_id(&record.resume_id)?;
        let mut slots = self.slots.lock().unwrap();
        if let Some(expected) = expected {
            ensure!(
                slots
                    .get(&record.resume_id)
                    .is_some_and(|v| v.0 == expected),
                "retired stream transport"
            );
        } else {
            ensure!(
                !slots.contains_key(&record.resume_id),
                "duplicate stream token"
            );
        }
        ensure!(
            slots.len() < SESSION_LIMIT || slots.contains_key(&record.resume_id),
            "stream management session limit"
        );
        let total: usize = slots.values().map(|v| v.1).sum();
        let previous = slots.get(&record.resume_id).map_or(0, |v| v.1);
        ensure!(
            total - previous + bytes.len() <= TOTAL_LIMIT,
            "stream management storage limit"
        );
        let tmp = self.root.join(format!("{name}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(tmp, self.root.join(format!("{name}.json")))?;
        File::open(&self.root)?.sync_all()?;
        slots.insert(record.resume_id, (record.connection, bytes.len()));
        Ok(())
    }
    fn remove(&self, id: &str, connection: &str) -> Result<()> {
        let mut slots = self.slots.lock().unwrap();
        if slots.get(id).is_none_or(|v| v.0 != connection) {
            return Ok(());
        }
        fs::remove_file(self.root.join(format!("{}.json", safe_id(id)?)))?;
        File::open(&self.root)?.sync_all()?;
        slots.remove(id);
        Ok(())
    }
}
fn safe_id(id: &str) -> Result<&str> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
        "invalid resume token"
    );
    Ok(id)
}
