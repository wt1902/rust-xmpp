//! Bounded, per-session durable stream-management slots. Socket handles are never stored.
//!
//! Recovery is deliberately strict: malformed, oversized, or inconsistent committed
//! slots fail startup instead of silently losing acknowledged session state. Uncommitted
//! UUID temporary files are discarded; checksummed redo journals are authoritative.
//! The readable JSON files are exports and are repaired from redo before loading.
use crate::sessions::Session;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    failed: std::sync::atomic::AtomicBool,
    retired: Mutex<Vec<String>>,
    journals: Mutex<BTreeMap<String, u64>>,
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
        regular_or_missing(&path.join("store.lock"))?;
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
            failed: std::sync::atomic::AtomicBool::new(false),
            retired: Default::default(),
            journals: Default::default(),
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
                let id = id.strip_suffix(".wal").unwrap_or(id);
                let owned = safe_id(id).is_ok()
                    && uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id);
                if owned && entry.file_type()?.is_file() {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        File::open(path)?.sync_all()?;
        // Redo precedes JSON validation: the export may be stale or torn.
        for entry in &entries {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = name.strip_suffix(".wal") {
                safe_id(id)?;
                ensure!(
                    entry.file_type()?.is_file(),
                    "invalid stream management journal"
                );
                let snapshot = replay(&entry.path())?;
                // A process crash can leave a complete, checksummed append
                // only in page cache. Make its adoption durable before any
                // recovered slot is exposed to bootstrap or resume consumers.
                OpenOptions::new()
                    .write(true)
                    .open(entry.path())?
                    .sync_data()?;
                {
                    let mut journals = store.journals.lock().unwrap();
                    journals.insert(id.to_string(), entry.metadata()?.len());
                    ensure!(
                        journals.len() <= SESSION_LIMIT + 64
                            && journals.values().sum::<u64>() <= JOURNAL_TOTAL_LIMIT,
                        "stream management aggregate journal limit"
                    );
                }
                if let Some(record) = &snapshot {
                    validate_record(record, id)?;
                }
                store.export(
                    id,
                    snapshot
                        .as_ref()
                        .map(serde_json::to_vec)
                        .transpose()?
                        .as_deref(),
                )?;
                if snapshot.is_none() {
                    store.retired.lock().unwrap().push(id.to_string());
                }
            }
        }
        let entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
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
            let id = name.strip_suffix(".json").unwrap();
            validate_record(&record, id)?;
            if record.deadline_ms <= now_ms() {
                store.commit(id, None)?;
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
        store.collect_retired()?;
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
                !slots.contains_key(&record.resume_id)
                    && !self.retired.lock().unwrap().contains(&record.resume_id),
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
        self.commit(name, Some(&bytes))?;
        slots.insert(record.resume_id, (record.connection, bytes.len()));
        Ok(())
    }
    fn remove(&self, id: &str, connection: &str) -> Result<()> {
        let mut slots = self.slots.lock().unwrap();
        if slots.get(id).is_none_or(|v| v.0 != connection) {
            return Ok(());
        }
        self.commit(safe_id(id)?, None)?;
        slots.remove(id);
        Ok(())
    }
    // A journal failure may have reached stable storage. Fence this store rather
    // than allowing an in-memory rollback to overwrite an uncertain commit.
    fn commit(&self, id: &str, bytes: Option<&[u8]>) -> Result<()> {
        use std::sync::atomic::Ordering;
        ensure!(
            !self.failed.load(Ordering::SeqCst),
            "stream management store failed"
        );
        let result = self.commit_inner(id, bytes);
        if result.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        result
    }
    fn commit_inner(&self, id: &str, bytes: Option<&[u8]>) -> Result<()> {
        let path = self.root.join(format!("{id}.wal"));
        regular_or_missing(&path)?;
        if !path.try_exists()? {
            // The baseline embeds the previously committed JSON, so recovery
            // never depends on an export modified without a subsequent fsync.
            let old = self.root.join(format!("{id}.json"));
            let baseline = if old.try_exists()? {
                regular_or_missing(&old)?;
                let mut baseline = Vec::new();
                File::open(old)?
                    .take(SLOT_LIMIT as u64 + 1)
                    .read_to_end(&mut baseline)?;
                ensure!(baseline.len() <= SLOT_LIMIT, "stream management slot limit");
                let record: Record = serde_json::from_slice(&baseline)?;
                validate_record(&record, id)?;
                Some(baseline)
            } else {
                None
            };
            let baseline_frame = frame(true, baseline.as_deref())?;
            if self.journals.lock().unwrap().values().sum::<u64>()
                + JOURNAL_MAGIC.len() as u64
                + baseline_frame.len() as u64
                > JOURNAL_TOTAL_LIMIT
            {
                self.compact_journals()?;
            }
            self.reset_journal(id, baseline.as_deref())?;
        }
        // Rotation is amortized over at least several small commits. Sync the
        // exported snapshot and its rename BEFORE replacing the redo history.
        let len = fs::metadata(&path)?.len();
        if len >= JOURNAL_ROTATE {
            let old = replay(&path)?;
            let old = old.as_ref().map(serde_json::to_vec).transpose()?;
            self.checkpoint_journal(id, old.as_deref())?;
        }
        let frame = frame(false, bytes)?;
        if self.journals.lock().unwrap().values().sum::<u64>() + frame.len() as u64
            > JOURNAL_TOTAL_LIMIT
        {
            // An aggregate cap prevents many small slots each growing a full
            // per-slot rotation budget. Compaction is rare and amortized over
            // hundreds of MiB of durable appends.
            self.compact_journals()?;
        }
        let mut journal = private_options().append(true).open(&path)?;
        let new_len = journal.metadata()?.len() + frame.len() as u64;
        journal.write_all(&frame)?;
        journal.sync_data()?;
        self.journals
            .lock()
            .unwrap()
            .insert(id.to_string(), new_len);
        // This remains readable for diagnostics and wire assertions, but only
        // the journal is authoritative after a crash.
        if self.export(id, bytes).is_err() {
            // The durable commit succeeded. Its caller must advance memory to
            // the same state rather than rolling it back. Fence future writes;
            // startup will reconstruct the export from redo.
            self.failed.store(true, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        if bytes.is_none() {
            let mut retired = self.retired.lock().unwrap();
            retired.push(id.to_string());
            let collect = retired.len() >= 64;
            drop(retired);
            if collect && self.collect_retired().is_err() {
                self.failed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        Ok(())
    }
    fn compact_journals(&self) -> Result<()> {
        let ids: Vec<String> = self.journals.lock().unwrap().keys().cloned().collect();
        for id in ids {
            let snapshot = replay(&self.root.join(format!("{id}.wal")))?;
            let snapshot = snapshot.as_ref().map(serde_json::to_vec).transpose()?;
            self.checkpoint_journal(&id, snapshot.as_deref())?;
        }
        Ok(())
    }
    fn collect_retired(&self) -> Result<()> {
        let mut retired = self.retired.lock().unwrap();
        if retired.is_empty() {
            return Ok(());
        }
        // Deletions become durable before their redo tombstones disappear.
        File::open(&self.root)?.sync_all()?;
        for id in retired.iter() {
            let path = self.root.join(format!("{id}.wal"));
            if path.try_exists()? {
                fs::remove_file(path)?;
            }
            self.journals.lock().unwrap().remove(id);
        }
        File::open(&self.root)?.sync_all()?;
        retired.clear();
        Ok(())
    }
    fn checkpoint_journal(&self, id: &str, bytes: Option<&[u8]>) -> Result<()> {
        self.export(id, bytes)?;
        if bytes.is_some() {
            File::open(self.root.join(format!("{id}.json")))?.sync_all()?;
        }
        File::open(&self.root)?.sync_all()?;
        self.reset_journal(id, bytes)
    }
    fn reset_journal(&self, id: &str, baseline: Option<&[u8]>) -> Result<()> {
        let tmp = self.root.join(format!("{id}.wal.tmp"));
        regular_or_missing(&tmp)?;
        let mut file = private_options().create(true).truncate(true).open(&tmp)?;
        private_permissions(&file)?;
        file.write_all(JOURNAL_MAGIC)?;
        file.write_all(&frame(true, baseline)?)?;
        file.sync_all()?;
        let len = file.metadata()?.len();
        fs::rename(tmp, self.root.join(format!("{id}.wal")))?;
        File::open(&self.root)?.sync_all()?;
        self.journals.lock().unwrap().insert(id.to_string(), len);
        Ok(())
    }
    fn export(&self, id: &str, bytes: Option<&[u8]>) -> Result<()> {
        let dest = self.root.join(format!("{id}.json"));
        if let Some(bytes) = bytes {
            let tmp = self.root.join(format!("{id}.tmp"));
            regular_or_missing(&tmp)?;
            let mut file = private_options().create(true).truncate(true).open(&tmp)?;
            private_permissions(&file)?;
            file.write_all(bytes)?;
            fs::rename(tmp, dest)?;
        } else if dest.try_exists()? {
            fs::remove_file(dest)?;
        }
        Ok(())
    }
}
/// Materialize the authoritative redo state as durable legacy JSON snapshots.
///
/// This is an offline handoff operation: it acquires the same exclusive store
/// lock as a persistent Hub and fails while a live owner exists. Recovery and
/// expiry run first. All current JSON data and directory entries become durable
/// before any redo journal is removed. A failed checkpoint may leave redundant
/// journals, but never removes the only durable copy of an acknowledged state.
/// The caller should additionally hold its server-wide data-directory lock.
pub fn checkpoint_exports(path: &Path) -> Result<usize> {
    let (store, records) = Store::open(path)?;
    for record in &records {
        let json = path.join(format!("{}.json", safe_id(&record.resume_id)?));
        regular_or_missing(&json)?;
        File::open(json)?.sync_all()?;
    }
    File::open(path)?.sync_all()?;
    let journals: Vec<String> = store.journals.lock().unwrap().keys().cloned().collect();
    for id in journals {
        let journal = path.join(format!("{id}.wal"));
        regular_or_missing(&journal)?;
        fs::remove_file(journal)?;
    }
    File::open(path)?.sync_all()?;
    Ok(records.len())
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

const JOURNAL_MAGIC: &[u8; 8] = b"XMPPSM01";
const JOURNAL_ROTATE: u64 = 16 * 1024 * 1024;
const JOURNAL_TOTAL_LIMIT: u64 = (TOTAL_LIMIT * 2) as u64;
const FRAME_LIMIT: usize = SLOT_LIMIT + 1024;
#[derive(Serialize, Deserialize)]
struct JournalEntry<T> {
    baseline: bool,
    snapshot: Option<T>,
}
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}
fn private_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
fn frame(baseline: bool, bytes: Option<&[u8]>) -> Result<Vec<u8>> {
    // The snapshot was already validated and serialized by write() or replay().
    // Copy its JSON directly into the frame rather than parsing and serializing
    // the entire pending queue again on every checkpoint.
    if let Some(bytes) = bytes {
        ensure!(bytes.len() <= SLOT_LIMIT, "stream management slot limit");
    }
    let mut payload = Vec::with_capacity(bytes.map_or(4, |snapshot| snapshot.len()) + 32);
    payload.extend_from_slice(if baseline {
        b"{\"baseline\":true,\"snapshot\":"
    } else {
        b"{\"baseline\":false,\"snapshot\":"
    });
    payload.extend_from_slice(bytes.unwrap_or(b"null"));
    payload.push(b'}');
    ensure!(
        payload.len() <= FRAME_LIMIT,
        "stream management journal frame limit"
    );
    let len = payload.len() as u32;
    let mut result = Vec::with_capacity(payload.len() + 40);
    result.extend_from_slice(&len.to_le_bytes());
    result.extend_from_slice(&(!len).to_le_bytes());
    result.extend_from_slice(&Sha256::digest(&payload));
    result.extend_from_slice(&payload);
    Ok(result)
}
fn replay(path: &Path) -> Result<Option<Record>> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    private_permissions(&file)?;
    ensure!(
        file.metadata()?.len() <= JOURNAL_ROTATE + (FRAME_LIMIT + 40) as u64 + 8,
        "stream management journal limit"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(JOURNAL_ROTATE + FRAME_LIMIT as u64 + 49)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.starts_with(JOURNAL_MAGIC),
        "invalid stream management journal header"
    );
    let mut offset = 8;
    let mut first = true;
    let mut latest_payload = None;
    while offset < bytes.len() {
        if bytes.len() - offset < 8 {
            break;
        }
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let complement = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        ensure!(
            len == !complement && len as usize <= FRAME_LIMIT,
            "corrupt stream management journal frame"
        );
        let end = offset + 40 + len as usize;
        if end > bytes.len() {
            break;
        }
        let payload = &bytes[offset + 40..end];
        ensure!(
            Sha256::digest(payload).as_slice() == &bytes[offset + 8..offset + 40],
            "stream management journal checksum mismatch"
        );
        // Historical snapshots were validated before their original commit.
        // Check every byte and the full JSON syntax again, without allocating
        // old pending queues or serializing superseded snapshots during replay.
        let entry: JournalEntry<serde::de::IgnoredAny> = serde_json::from_slice(payload)?;
        ensure!(
            entry.baseline == first,
            "invalid stream management journal baseline"
        );
        latest_payload = Some(payload);
        first = false;
        offset = end;
    }
    ensure!(!first, "incomplete stream management journal baseline");
    let latest: JournalEntry<Record> = serde_json::from_slice(latest_payload.unwrap())?;
    if let Some(record) = &latest.snapshot {
        let id = path.file_stem().unwrap().to_string_lossy();
        validate_record(record, &id)?;
        ensure!(
            serde_json::to_vec(record)?.len() <= SLOT_LIMIT,
            "stream management slot limit"
        );
    }
    if offset < bytes.len() {
        file.set_len(offset as u64)?;
        file.sync_all()?;
    }
    Ok(latest.snapshot)
}
fn validate_record(record: &Record, id: &str) -> Result<()> {
    ensure!(
        record.version == 1
            && record.pending.len() <= 4096
            && record.sent.wrapping_sub(record.acked) as usize == record.pending.len()
            && crate::protocol::bare(&record.jid) == record.owner
            && record.jid.contains('/'),
        "invalid durable session"
    );
    ensure!(safe_id(&record.resume_id)? == id, "invalid slot token");
    Ok(())
}

fn regular_or_missing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(metadata.is_file(), "invalid stream management file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
