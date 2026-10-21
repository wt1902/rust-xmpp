//! Prosody internal archives: Lua `.list` records; binary `.lidx` is a rebuildable cache.
use crate::{
    storage::{self, LuaValue as V},
    wire::escape,
};
use anyhow::{Result, anyhow, bail};
use std::{
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{Arc, Mutex, OnceLock, Weak},
};
type LockMap = std::collections::HashMap<std::path::PathBuf, Weak<Mutex<()>>>;
static LIFECYCLE: std::sync::RwLock<()> = std::sync::RwLock::new(());
/// Account purge barrier. Callback must not invoke archive methods.
pub fn with_exclusive_access<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let _guard = LIFECYCLE
        .write()
        .map_err(|_| anyhow!("archive lifecycle lock poisoned"))?;
    f()
}
static LOCKS: OnceLock<Mutex<LockMap>> = OnceLock::new();
fn archive_lock(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
) -> Result<Arc<Mutex<()>>> {
    let path = storage::path(root, host, user, store);
    let key = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(LockMap::new()))
        .lock()
        .map_err(|_| anyhow!("archive lock map poisoned"))?;
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    if locks.len() > 1024 {
        locks.retain(|_, v| v.strong_count() > 0);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    Ok(lock)
}
#[derive(Clone, Debug)]
pub struct Entry {
    pub id: String,
    pub when: f64,
    pub peer: String,
    pub xml: String,
}
fn string(v: &V) -> Result<String> {
    if let V::String(s) = v {
        Ok(String::from_utf8(s.clone())?)
    } else {
        bail!("expected archive string")
    }
}
fn s(x: &str) -> V {
    V::String(x.as_bytes().to_vec())
}
fn table() -> V {
    V::Table(vec![])
}

pub fn timestamp(value: f64) -> Result<String> {
    let seconds = value.floor() as i64;
    let nanos = ((value - seconds as f64) * 1e9).round() as u32;
    Ok(
        chrono::DateTime::from_timestamp(seconds, nanos.min(999999999))
            .ok_or_else(|| anyhow!("invalid timestamp"))?
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
    )
}
pub fn parse_time(value: &str) -> Result<f64> {
    let t = chrono::DateTime::parse_from_rfc3339(value)?;
    Ok(t.timestamp() as f64 + t.timestamp_subsec_nanos() as f64 / 1e9)
}
fn from_xml(n: roxmltree::Node<'_, '_>) -> Result<V> {
    let mut v = table();
    v.set("name", s(n.tag_name().name()));
    let mut attr = table();
    if let Some(ns) = n.tag_name().namespace() {
        attr.set("xmlns", s(ns));
    }
    for a in n.attributes() {
        let key = if let Some(ns) = a.namespace() {
            if ns == "http://www.w3.org/XML/1998/namespace" {
                format!("xml:{}", a.name())
            } else {
                format!("{}\u{1}{}", ns, a.name())
            }
        } else {
            a.name().into()
        };
        attr.set(&key, s(a.value()));
    }
    v.set("attr", attr);
    let mut idx = 1;
    for c in n.children() {
        let child = if c.is_element() {
            from_xml(c)?
        } else if c.is_text() {
            s(c.text().unwrap_or(""))
        } else {
            continue;
        };
        v.set_key(V::Integer(idx), child);
        idx += 1;
    }
    Ok(v)
}
fn to_xml(v: &V, root: bool) -> Result<String> {
    if matches!(v, V::String(_)) {
        return Ok(escape(&string(v)?));
    }
    let name = string(
        v.get("name")
            .ok_or_else(|| anyhow!("archive stanza missing name"))?,
    )?;
    // Parse constructed XML below, preventing malformed names or injected markup.
    let mut out = format!("<{name}");
    let mut ns_idx = 0;
    if let Some(V::Table(attrs)) = v.get("attr") {
        for (k, val) in attrs {
            let k = string(k)?;
            if root && (k == "stamp" || k == "stamp_legacy") {
                continue;
            }
            let value = escape(&string(val)?);
            if let Some((ns, key)) = k.split_once('\u{1}').or_else(|| k.split_once('|')) {
                if ns == "http://www.w3.org/XML/1998/namespace" {
                    out.push_str(&format!(" xml:{key}='{value}'"));
                } else {
                    ns_idx += 1;
                    out.push_str(&format!(
                        " xmlns:a{ns_idx}='{}' a{ns_idx}:{key}='{value}'",
                        escape(ns)
                    ));
                }
            } else {
                out.push_str(&format!(" {k}='{value}'"));
            }
        }
    }
    out.push('>');
    let mut i = 1;
    while let Some(child) = v.get_key(&V::Integer(i)) {
        out.push_str(&to_xml(child, false)?);
        i += 1;
    }
    out.push_str(&format!("</{name}>"));
    Ok(out)
}
pub fn load(root: &Path, host: &str, user: &str) -> Result<Vec<Entry>> {
    load_store(root, host, Some(user), "archive")
}
/// Scan one consistent archive snapshot with memory bounded by one record.
/// Prosody itself indexes record boundaries by lines beginning with `item`.
pub fn scan_store<F: FnMut(Entry) -> Result<()>>(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    visit: F,
) -> Result<()> {
    let _life = LIFECYCLE
        .read()
        .map_err(|_| anyhow!("archive lifecycle lock poisoned"))?;
    let lock = archive_lock(root, host, user, store)?;
    let _guard = lock.lock().map_err(|_| anyhow!("archive lock poisoned"))?;
    scan_unlocked(root, host, user, store, visit)
}
// The native file remains directly readable by Prosody. While this sidecar exists,
// its complete frames define the committed suffix: do not edit a live native file
// in place or replace it until checkpoint_all has durably retired the journal.
const REDO_MAGIC: &[u8; 8] = b"XARRED01";
const REDO_HEADER: usize = 96;
const REDO_LIMIT: u64 = 1024 * 1024;
const REDO_FRAMES: usize = 128;
#[derive(Clone)]
struct RedoState {
    length: u64,
    bytes: u64,
    frames: usize,
}
#[derive(Clone, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    identity: (u64, u64),
    #[cfg(unix)]
    changed: (i64, i64),
}
fn identity(meta: &std::fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        (0, 0)
    }
}
fn stamp(p: &Path) -> Result<FileStamp> {
    let m = std::fs::metadata(p)?;
    Ok(FileStamp {
        len: m.len(),
        modified: m.modified().ok(),
        identity: identity(&m),
        #[cfg(unix)]
        changed: {
            use std::os::unix::fs::MetadataExt;
            (m.ctime(), m.ctime_nsec())
        },
    })
}
type RedoCache = std::collections::HashMap<std::path::PathBuf, (FileStamp, FileStamp, RedoState)>;
static REDO_CACHE: OnceLock<Mutex<RedoCache>> = OnceLock::new();
fn remember_redo(p: &Path, state: &RedoState) -> Result<()> {
    let native = stamp(p)?;
    let journal = stamp(&p.with_extension("rredo"))?;
    let mut cache = REDO_CACHE
        .get_or_init(|| Mutex::new(RedoCache::new()))
        .lock()
        .map_err(|_| anyhow!("archive redo cache poisoned"))?;
    if cache.len() >= 1024 {
        cache.clear();
    }
    cache.insert(p.to_path_buf(), (native, journal, state.clone()));
    Ok(())
}
fn digest(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}
fn baseline_anchor(file: &mut std::fs::File, length: u64) -> Result<[u8; 32]> {
    let count = length.min(4096);
    file.seek(SeekFrom::Start(length - count))?;
    let mut bytes = vec![0; count as usize];
    file.read_exact(&mut bytes)?;
    Ok(digest(&bytes))
}
/// Native fsync precedes journal replacement. Either old or new header can
/// survive a crash, and both refer to an already durable native baseline.
fn checkpoint_redo(p: &Path) -> Result<RedoState> {
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(p)?;
    file.sync_all()?;
    let meta = file.metadata()?;
    let length = meta.len();
    let (dev, ino) = identity(&meta);
    let mut header = Vec::with_capacity(REDO_HEADER);
    header.extend_from_slice(REDO_MAGIC);
    for n in [length, dev, ino] {
        header.extend_from_slice(&n.to_le_bytes());
    }
    header.extend_from_slice(&baseline_anchor(&mut file, length)?);
    header.extend_from_slice(&digest(&header));
    storage::atomic_write(&p.with_extension("rredo"), &header)?;
    let state = RedoState {
        length,
        bytes: REDO_HEADER as u64,
        frames: 0,
    };
    remember_redo(p, &state)?;
    Ok(state)
}
fn recover_legacy_append(p: &Path) -> Result<()> {
    let journal = p.with_extension("rappend");
    match std::fs::read(&journal) {
        Ok(data) => {
            anyhow::ensure!(data.len() == 8, "invalid archive append journal");
            let length = u64::from_le_bytes(data.try_into().unwrap());
            let f = std::fs::OpenOptions::new().write(true).open(p)?;
            anyhow::ensure!(
                f.metadata()?.len() >= length,
                "archive shorter than recovery offset"
            );
            f.set_len(length)?;
            f.sync_all()?;
            std::fs::remove_file(journal)?;
            std::fs::File::open(p.parent().unwrap())?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn recover_redo(p: &Path) -> Result<Option<RedoState>> {
    recover_legacy_append(p)?;
    let journal = p.with_extension("rredo");
    let jm = match stamp(&journal) {
        Ok(m) => m,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let nm = stamp(p).ok();
    if let Some(native) = &nm {
        let cache = REDO_CACHE
            .get_or_init(|| Mutex::new(RedoCache::new()))
            .lock()
            .map_err(|_| anyhow!("archive redo cache poisoned"))?;
        if let Some((n, j, state)) = cache.get(p)
            && n == native
            && j == &jm
        {
            return Ok(Some(state.clone()));
        }
    }
    // One oversized record is allowed, but the journal never grows without bound.
    anyhow::ensure!(
        jm.len <= REDO_LIMIT + MAX_RECORD_BYTES as u64 + REDO_HEADER as u64 + 72,
        "archive redo journal exceeds bound"
    );
    let data = std::fs::read(&journal)?;
    anyhow::ensure!(
        data.len() >= REDO_HEADER && &data[..8] == REDO_MAGIC,
        "invalid archive redo header"
    );
    anyhow::ensure!(
        digest(&data[..64]) == data[64..96],
        "archive redo header checksum mismatch"
    );
    let number = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    let base = number(8);
    // Inodes change when an archive is copied/restored. The journal remains
    // authoritative across that change; identity is only a cache stamp.
    anyhow::ensure!(nm.is_some() || base == 0, "missing archive redo baseline");
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(p)?;
    anyhow::ensure!(
        file.metadata()?.len() >= base,
        "archive shorter than redo baseline"
    );
    anyhow::ensure!(
        baseline_anchor(&mut file, base)? == data[32..64],
        "archive redo baseline changed in place"
    );
    let mut pos = REDO_HEADER;
    let mut frames = Vec::new();
    let mut length = base;
    while pos < data.len() {
        if data.len() - pos < 72 {
            break;
        }
        anyhow::ensure!(
            digest(&data[pos..pos + 8]) == data[pos + 8..pos + 40],
            "archive redo frame length checksum mismatch"
        );
        let size = number(pos);
        anyhow::ensure!(
            size > 0 && size <= MAX_RECORD_BYTES as u64,
            "invalid archive redo frame length"
        );
        let end = pos + 72 + size as usize;
        if end > data.len() {
            break;
        }
        let payload = &data[pos + 72..end];
        anyhow::ensure!(
            digest(payload) == data[pos + 40..pos + 72],
            "archive redo frame checksum mismatch"
        );
        frames.push((length, payload));
        anyhow::ensure!(
            frames.len() <= REDO_FRAMES,
            "archive redo frame count exceeds bound"
        );
        length = length
            .checked_add(size)
            .ok_or_else(|| anyhow!("archive redo offset overflow"))?;
        pos = end;
    }
    // Native indexes are rebuildable. A crash may have resurrected an unlink
    // from the append path; invalidate it again before exposing recovered data.
    match std::fs::remove_file(p.with_extension("lidx")) {
        Ok(()) => std::fs::File::open(p.parent().unwrap())?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    // A complete frame can survive a process crash in page cache even if its
    // writer never completed sync. Durably adopt all validated frames before
    // exposing them or allowing later recovery to truncate the native file.
    let redo = std::fs::OpenOptions::new().write(true).open(&journal)?;
    if pos < data.len() {
        redo.set_len(pos as u64)?;
    }
    redo.sync_all()?;
    // Validate the complete journal before changing native data. Replaying is
    // idempotent, including after a second crash midway through recovery.
    let mut changed = file.metadata()?.len() != length;
    for (offset, payload) in &frames {
        file.seek(SeekFrom::Start(*offset))?;
        let mut native = vec![0; payload.len()];
        let equal = file.read_exact(&mut native).is_ok() && native.as_slice() == *payload;
        if !equal {
            file.seek(SeekFrom::Start(*offset))?;
            file.write_all(payload)?;
            changed = true;
        }
    }
    if changed {
        file.set_len(length)?;
        file.sync_all()?;
    }
    let state = RedoState {
        length,
        bytes: pos as u64,
        frames: frames.len(),
    };
    if nm.is_none() {
        return checkpoint_redo(p).map(Some);
    }
    remember_redo(p, &state)?;
    Ok(Some(state))
}
fn recover_append(p: &Path) -> Result<()> {
    recover_redo(p)?;
    Ok(())
}
/// Durable handoff to a native writer. Call after stopping archive users and
/// before letting Prosody modify `.list` files in place. Abrupt shutdown leaves
/// redo recovery active; unjournaled native suffixes are then uncommitted.
pub fn checkpoint_all(root: &Path) -> Result<usize> {
    with_exclusive_access(|| {
        let mut pending = vec![root.to_path_buf()];
        let mut count = 0;
        while let Some(dir) = pending.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            for entry in entries {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    pending.push(entry.path());
                } else if kind.is_file() && entry.path().extension().is_some_and(|e| e == "rredo") {
                    let path = entry.path().with_extension("list");
                    prepare_rewrite(&path)?;
                    count += 1;
                }
            }
        }
        Ok(count)
    })
}
/// Retire redo before an atomic snapshot replacement. The old native snapshot
/// is synced first, so a crash after unlink and before rename retains every
/// committed record. After rename there is no old redo to resurrect deletions.
fn retire_redo(p: &Path) -> Result<()> {
    std::fs::File::open(p)?.sync_all()?;
    std::fs::remove_file(p.with_extension("rredo"))?;
    std::fs::File::open(p.parent().unwrap())?.sync_all()?;
    REDO_CACHE
        .get_or_init(|| Mutex::new(RedoCache::new()))
        .lock()
        .map_err(|_| anyhow!("archive redo cache poisoned"))?
        .remove(p);
    Ok(())
}
/// True when the redo journal no longer matches its native baseline after an
/// external in-place write or replacement. In that state the journal is no
/// longer authoritative and must not be replayed over the native file.
fn is_untrusted_redo(error: &anyhow::Error) -> bool {
    let text = format!("{error:#}");
    text.contains("archive redo baseline changed in place")
        || text.contains("archive shorter than redo baseline")
        || text.contains("missing archive redo baseline")
        || text.contains("archive redo journal exceeds bound")
}
/// Retire redo before an atomic snapshot replacement or with an explicit offline
/// handoff (storage-checkpoint). A journal whose baseline was externally
/// rewritten in place can no longer be trusted: because the caller is about to
/// replace the native file (rewrite) or to hand control of it to a native
/// writer (checkpoint), the current durably synced native becomes authoritative
/// and the untrusted journal is retired rather than failing the operation.
fn prepare_rewrite(p: &Path) -> Result<()> {
    match recover_redo(p) {
        Ok(Some(_)) => retire_redo(p),
        Ok(None) => Ok(()),
        Err(error) if is_untrusted_redo(&error) => {
            // The journal no longer matches its baseline. Treat the native file
            // as authoritative, sync it, and retire the untrusted journal.
            retire_redo(p)
        }
        Err(error) => Err(error),
    }
}
fn scan_unlocked<F: FnMut(Entry) -> Result<()>>(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    mut visit: F,
) -> Result<()> {
    let path = storage::path(root, host, user, store).with_extension("list");
    recover_append(&path)?;
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut record = Vec::new();
    let decoder = RecordDecoder::new()?;
    let mut decode = |data: &[u8]| -> Result<()> {
        if let Some(entry) = decoder.decode(data)? {
            visit(entry)?;
        }
        Ok(())
    };
    loop {
        line.clear();
        let n = (&mut reader)
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        anyhow::ensure!(
            line.len() <= MAX_RECORD_BYTES,
            "archive record line exceeds 16 MiB"
        );
        if line.starts_with(b"item") && !record.is_empty() {
            decode(&record)?;
            record.clear();
        }
        record.extend_from_slice(&line);
        anyhow::ensure!(
            record.len() <= MAX_RECORD_BYTES,
            "archive record exceeds 16 MiB"
        );
    }
    decode(&record)
}
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

/// One bounded Lua sandbox shared by the scan and endpoint readers.
struct RecordDecoder {
    lua: mlua::Lua,
    env: mlua::Table,
}
impl RecordDecoder {
    fn new() -> Result<Self> {
        let lua = crate::lua::bounded_vm().map_err(|e| anyhow!(e.to_string()))?;
        let env = lua.create_table().map_err(|e| anyhow!(e.to_string()))?;
        Ok(Self { lua, env })
    }
    fn decode(&self, data: &[u8]) -> Result<Option<Entry>> {
        anyhow::ensure!(
            data.len() <= MAX_RECORD_BYTES,
            "archive record exceeds 16 MiB"
        );
        if data.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        let count = std::rc::Rc::new(std::cell::Cell::new(0));
        self.lua
            .set_hook(
                mlua::HookTriggers::new().every_nth_instruction(1000),
                move |_, _| {
                    count.set(count.get() + 1);
                    if count.get() > 2000 {
                        return Err(mlua::Error::runtime("archive record instruction limit"));
                    }
                    Ok(mlua::VmState::Continue)
                },
            )
            .map_err(|e| anyhow!(e.to_string()))?;
        let mut chunk = b"local function item(v) return v end; return ".to_vec();
        chunk.extend(data);
        let value = self
            .lua
            .load(&chunk)
            .set_mode(mlua::chunk::ChunkMode::Text)
            .set_environment(self.env.clone())
            .eval::<mlua::Value>()
            .map_err(|e| anyhow!(e.to_string()))?;
        let entry = decode_entry(&storage::from_lua(value)?)?;
        self.lua.gc_collect().map_err(|e| anyhow!(e.to_string()))?;
        Ok(Some(entry))
    }
}

/// Read just the first and last native records of a consistent archive snapshot.
/// This metadata operation deliberately does not validate intervening records.
/// Neither a missing nor a stale native binary index causes a history scan.
pub fn edges_store(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
) -> Result<Option<(Entry, Entry)>> {
    let _life = LIFECYCLE
        .read()
        .map_err(|_| anyhow!("archive lifecycle lock poisoned"))?;
    let lock = archive_lock(root, host, user, store)?;
    let _guard = lock.lock().map_err(|_| anyhow!("archive lock poisoned"))?;
    let path = storage::path(root, host, user, store).with_extension("list");
    recover_append(&path)?;
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let decoder = RecordDecoder::new()?;
    let first = match first_record(&mut BufReader::new(&mut file), &decoder)? {
        Some(entry) => entry,
        None => return Ok(None),
    };
    let length = file.metadata()?.len();
    let mut window = 8192u64.min(length);
    loop {
        let start = length - window;
        // Include one preceding byte to distinguish a real line boundary from
        // an `item` prefix coincidentally at the beginning of the seek window.
        let read_start = start.saturating_sub(1);
        file.seek(SeekFrom::Start(read_start))?;
        let mut tail = vec![0; (length - read_start) as usize];
        file.read_exact(&mut tail)?;
        let boundary = (0..tail.len()).rev().find(|&i| {
            (i > 0 && tail[i - 1] == b'\n' || i == 0 && read_start == 0)
                && tail[i..].starts_with(b"item")
        });
        if let Some(boundary) = boundary {
            let last = decoder
                .decode(&tail[boundary..])?
                .ok_or_else(|| anyhow!("empty archive endpoint"))?;
            return Ok(Some((first, last)));
        }
        anyhow::ensure!(
            start > 0 && window < MAX_RECORD_BYTES as u64,
            "archive last record exceeds 16 MiB or has no native item boundary"
        );
        window = (window * 2).min(MAX_RECORD_BYTES as u64).min(length);
    }
}

fn first_record<R: BufRead>(reader: &mut R, decoder: &RecordDecoder) -> Result<Option<Entry>> {
    let mut record = Vec::new();
    loop {
        // Inspect only the next line's marker before reading its contents: the
        // second record may be enormous or malformed and is irrelevant here.
        let mut prefix = Vec::new();
        let n = (&mut *reader).take(4).read_until(b'\n', &mut prefix)?;
        if n == 0 {
            return decoder.decode(&record);
        }
        if prefix.starts_with(b"item") && !record.is_empty() {
            if let Some(entry) = decoder.decode(&record)? {
                return Ok(Some(entry));
            }
            record.clear();
        }
        record.extend_from_slice(&prefix);
        anyhow::ensure!(
            record.len() <= MAX_RECORD_BYTES,
            "archive record exceeds 16 MiB"
        );
        if !prefix.ends_with(b"\n") {
            let remaining = (MAX_RECORD_BYTES - record.len() + 1) as u64;
            (&mut *reader)
                .take(remaining)
                .read_until(b'\n', &mut record)?;
            anyhow::ensure!(
                record.len() <= MAX_RECORD_BYTES,
                "archive record exceeds 16 MiB"
            );
        }
    }
}
fn load_unlocked(root: &Path, host: &str, user: Option<&str>, store: &str) -> Result<Vec<Entry>> {
    let mut out = vec![];
    scan_unlocked(root, host, user, store, |e| {
        out.push(e);
        Ok(())
    })?;
    Ok(out)
}
pub fn load_store(root: &Path, host: &str, user: Option<&str>, store: &str) -> Result<Vec<Entry>> {
    let _life = LIFECYCLE
        .read()
        .map_err(|_| anyhow!("archive lifecycle lock poisoned"))?;
    let lock = archive_lock(root, host, user, store)?;
    let _guard = lock.lock().map_err(|_| anyhow!("archive lock poisoned"))?;
    load_unlocked(root, host, user, store)
}
fn decode_entry(v: &V) -> Result<Entry> {
    let when = match v.get("when") {
        Some(V::Number(x)) => *x,
        Some(V::Integer(x)) => *x as f64,
        _ => parse_time(&string(
            v.get("attr")
                .and_then(|a| a.get("stamp"))
                .ok_or_else(|| anyhow!("archive timestamp missing"))?,
        )?)?,
    };
    let xml = to_xml(v, true)?;
    roxmltree::Document::parse(&xml)?;
    Ok(Entry {
        id: string(v.get("key").ok_or_else(|| anyhow!("archive id missing"))?)?,
        when,
        peer: v.get("with").map(string).transpose()?.unwrap_or_default(),
        xml,
    })
}
fn encode_entry(e: &Entry) -> Result<String> {
    let doc = roxmltree::Document::parse(&e.xml)?;
    let mut value = from_xml(doc.root_element())?;
    value.set("key", s(&e.id));
    value.set("when", V::Number(e.when));
    value.set("with", s(&e.peer));
    let mut attr = value.get("attr").cloned().unwrap_or_else(table);
    attr.set("stamp", s(&timestamp(e.when)?));
    value.set("attr", attr);
    let serialized = storage::serialize(&value)?;
    let expr = serialized
        .strip_prefix("return ")
        .ok_or_else(|| anyhow!("bad serializer"))?
        .trim_end()
        .trim_end_matches(';');
    Ok(format!("item({expr});\n"))
}
/// Replace a generic Prosody archive atomically, invalidating its binary cache.
pub fn save_store(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    entries: &[Entry],
) -> Result<()> {
    let _life = LIFECYCLE
        .read()
        .map_err(|_| anyhow!("archive lifecycle lock poisoned"))?;
    let lock = archive_lock(root, host, user, store)?;
    let _guard = lock.lock().map_err(|_| anyhow!("archive lock poisoned"))?;
    save_unlocked(root, host, user, store, entries)
}
fn save_unlocked(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    entries: &[Entry],
) -> Result<()> {
    let mut data = String::new();
    for e in entries {
        data.push_str(&encode_entry(e)?);
    }
    let p = storage::path(root, host, user, store).with_extension("list");
    prepare_rewrite(&p)?;
    match std::fs::remove_file(p.with_extension("lidx")) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    storage::atomic_write(&p, data.as_bytes())
}
pub fn append_store(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    entry: Entry,
) -> Result<String> {
    let _life = LIFECYCLE
        .read()
        .map_err(|_| anyhow!("archive lifecycle lock poisoned"))?;
    let lock = archive_lock(root, host, user, store)?;
    let _guard = lock.lock().map_err(|_| anyhow!("archive lock poisoned"))?;
    let mut exists = false;
    scan_unlocked(root, host, user, store, |e| {
        exists |= e.id == entry.id;
        Ok(())
    })?;
    let id = entry.id.clone();
    if exists {
        let mut entries = load_unlocked(root, host, user, store)?;
        entries.retain(|v| v.id != entry.id);
        entries.push(entry);
        save_unlocked(root, host, user, store, &entries)?;
    } else {
        append_unlocked(root, host, user, store, &entry)?;
    }
    Ok(id)
}
/// Append an entry whose identifier is newly generated. O(record size), no archive scan.
/// Call append_store instead if replacing an existing identifier is required.
pub fn append_new(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    entry: Entry,
) -> Result<String> {
    let _life = LIFECYCLE
        .read()
        .map_err(|_| anyhow!("archive lifecycle lock poisoned"))?;
    let lock = archive_lock(root, host, user, store)?;
    let _guard = lock.lock().map_err(|_| anyhow!("archive lock poisoned"))?;
    append_unlocked(root, host, user, store, &entry)?;
    Ok(entry.id)
}
fn append_unlocked(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    entry: &Entry,
) -> Result<()> {
    let data = encode_entry(entry)?;
    anyhow::ensure!(
        data.len() <= MAX_RECORD_BYTES,
        "archive record exceeds 16 MiB"
    );
    let path = storage::path(root, host, user, store).with_extension("list");
    std::fs::create_dir_all(path.parent().unwrap())?;
    let state = recover_redo(&path)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path)?;
    let mut state = match state {
        Some(state) => state,
        None => checkpoint_redo(&path)?,
    };
    if state.bytes >= REDO_LIMIT || state.frames >= REDO_FRAMES {
        state = checkpoint_redo(&path)?;
    }
    match std::fs::remove_file(path.with_extension("lidx")) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let mut frame = Vec::with_capacity(72 + data.len());
    frame.extend_from_slice(&(data.len() as u64).to_le_bytes());
    frame.extend_from_slice(&digest(&(data.len() as u64).to_le_bytes()));
    frame.extend_from_slice(&digest(data.as_bytes()));
    frame.extend_from_slice(data.as_bytes());
    // Invalidate the cache before any write, including error paths. A failed
    // sync is indeterminate and must be recovered, never blindly rolled back.
    REDO_CACHE
        .get_or_init(|| Mutex::new(RedoCache::new()))
        .lock()
        .map_err(|_| anyhow!("archive redo cache poisoned"))?
        .remove(&path);
    file.seek(SeekFrom::Start(state.length))?;
    file.write_all(data.as_bytes())?;
    let mut journal = std::fs::OpenOptions::new()
        .append(true)
        .open(path.with_extension("rredo"))?;
    journal.write_all(&frame)?;
    journal.sync_all()?;
    state.length += data.len() as u64;
    state.bytes += frame.len() as u64;
    state.frames += 1;
    remember_redo(&path, &state)?;
    Ok(())
}
/// Owner is localpart, peer is bare JID. Caller enforces archive preferences.
pub fn archive_message(
    root: &Path,
    domain: &str,
    owner: &str,
    peer: &str,
    xml: &str,
    time: f64,
) -> Result<String> {
    append_new(
        root,
        domain,
        Some(owner),
        "archive",
        Entry {
            id: uuid::Uuid::new_v4().to_string(),
            when: time,
            peer: peer.into(),
            xml: xml.into(),
        },
    )
}

/// Delete all entries older than cutoff, preserving archive format and invalidating index.
pub fn expire_before(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    cutoff: f64,
) -> Result<usize> {
    let _life = LIFECYCLE
        .read()
        .map_err(|_| anyhow!("archive lifecycle lock poisoned"))?;
    let lock = archive_lock(root, host, user, store)?;
    let _guard = lock.lock().map_err(|_| anyhow!("archive lock poisoned"))?;
    retain_unlocked(root, host, user, store, |e| e.when >= cutoff)
}
/// Remove acknowledged records atomically relative to concurrent appends.
pub fn delete_ids(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    ids: &[String],
) -> Result<()> {
    let _life = LIFECYCLE
        .read()
        .map_err(|_| anyhow!("archive lifecycle lock poisoned"))?;
    let lock = archive_lock(root, host, user, store)?;
    let _guard = lock.lock().map_err(|_| anyhow!("archive lock poisoned"))?;
    let wanted: std::collections::HashSet<&str> = ids.iter().map(String::as_str).collect();
    retain_unlocked(root, host, user, store, |e| !wanted.contains(e.id.as_str()))?;
    Ok(())
}
fn retain_unlocked<F: FnMut(&Entry) -> bool>(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    mut retain: F,
) -> Result<usize> {
    let path = storage::path(root, host, user, store).with_extension("list");
    recover_append(&path)?;
    if !path.exists() {
        return Ok(0);
    }
    let parent = path.parent().unwrap();
    let temp = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<usize> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&temp)?;
        let mut removed = 0;
        scan_unlocked(root, host, user, store, |e| {
            if retain(&e) {
                file.write_all(encode_entry(&e)?.as_bytes())?;
            } else {
                removed += 1;
            }
            Ok(())
        })?;
        if removed == 0 {
            return Ok(0);
        }
        file.sync_all()?;
        prepare_rewrite(&path)?;
        match std::fs::remove_file(path.with_extension("lidx")) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        std::fs::rename(&temp, &path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(removed)
    })();
    let _ = std::fs::remove_file(&temp);
    result
}

#[cfg(test)]
mod redo_rewrite_tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        append_new(
            root.path(),
            "example.org",
            Some("alice"),
            "archive",
            Entry {
                id: "committed-before-rewrite".into(),
                when: 42.,
                peer: String::new(),
                xml: "<message><body>durable</body></message>".into(),
            },
        )
        .unwrap();
        let path = storage::path(root.path(), "example.org", Some("alice"), "archive")
            .with_extension("list");
        (root, path)
    }

    #[test]
    fn crash_gap_after_redo_retirement_before_native_rename_keeps_old_snapshot() {
        let (root, path) = fixture();
        let expected = std::fs::read(&path).unwrap();
        prepare_rewrite(&path).unwrap();
        // Crash boundary: redo unlink and directory sync completed, replacement
        // has not happened. Restart must retain the complete durable old list.
        assert!(!path.with_extension("rredo").exists());
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        let rows = load(root.path(), "example.org", "alice").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "committed-before-rewrite");
    }

    #[test]
    fn crash_gap_after_native_rename_has_no_old_redo_to_resurrect_deletions() {
        let (root, path) = fixture();
        prepare_rewrite(&path).unwrap();
        storage::atomic_write(&path, b"").unwrap();
        // Crash boundary: the atomic replacement committed. Recovery sees the
        // new snapshot directly and cannot replay the removed old record.
        assert!(!path.with_extension("rredo").exists());
        assert!(
            load(root.path(), "example.org", "alice")
                .unwrap()
                .is_empty()
        );
    }

    /// Build an archive large enough to have rolled its redo journal, so the
    /// baseline is non-empty (`base > 0`) and the anchor guard is meaningful.
    fn rolled_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        // One more than REDO_FRAMES forces a redo rotation at frame 128, which
        // snapshots the current native length as the new non-empty baseline.
        for i in 0..=REDO_FRAMES as u64 {
            append_new(
                root.path(),
                "example.org",
                Some("alice"),
                "archive",
                Entry {
                    id: format!("roll-{i}"),
                    when: i as f64,
                    peer: String::new(),
                    xml: "<message><body>x</body></message>".into(),
                },
            )
            .unwrap();
        }
        let path = storage::path(root.path(), "example.org", Some("alice"), "archive")
            .with_extension("list");
        // Recovery must see a non-empty baseline (rotation happened).
        let data = std::fs::read(path.with_extension("rredo")).unwrap();
        let base = u64::from_le_bytes(data[8..16].try_into().unwrap());
        assert!(base > 0, "fixture should have rolled a non-empty baseline");
        (root, path)
    }

    /// An external writer that rewrote the native archive in place over the
    /// committed baseline without a handoff leaves the redo journal untrusted.
    fn corrupt_baseline(path: &std::path::Path) -> u64 {
        let data = std::fs::read(path.with_extension("rredo")).unwrap();
        let base = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let mut native = std::fs::read(path).unwrap();
        // Flip the trailing bytes of the committed baseline so its anchor changes.
        let start = (base.saturating_sub(64)) as usize;
        for i in start..native.len().min(base as usize) {
            native[i] ^= 0x5a;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(path)
            .unwrap();
        std::io::Write::write_all(&mut file, &native).unwrap();
        file.sync_all().unwrap();
        base
    }

    #[test]
    fn runtime_append_fails_closed_on_untrusted_redo_baseline() {
        let (root, path) = rolled_fixture();
        corrupt_baseline(&path);
        // A live append must fail closed (not silently overwrite the native
        // file): the journal no longer matches its baseline.
        let err = append_new(
            root.path(),
            "example.org",
            Some("alice"),
            "archive",
            Entry {
                id: "post-corruption".into(),
                when: 100000.,
                peer: String::new(),
                xml: "<message><body>new</body></message>".into(),
            },
        )
        .expect_err("live append must fail on an untrusted redo baseline");
        assert!(
            is_untrusted_redo(&err),
            "expected an untrusted-baseline error, got: {err:#}"
        );
        // The journal is preserved for explicit offline handoff.
        assert!(path.with_extension("rredo").exists());
    }

    #[test]
    fn offline_checkpoint_retires_untrusted_redo_baseline() {
        let (root, path) = rolled_fixture();
        let base = corrupt_baseline(&path);
        assert!(base > 0);
        assert!(path.with_extension("rredo").exists());
        // An external rewrite removed the trusted baseline; an explicit offline
        // handoff accepts the current synced native as authoritative and retires
        // the untrusted journal so the archive becomes writable again.
        let retired = checkpoint_all(root.path()).unwrap();
        assert_eq!(retired, 1);
        assert!(
            !path.with_extension("rredo").exists(),
            "offline checkpoint must retire the untrusted journal"
        );
        // The archive accepts new appends: with the journal retired the current
        // (now authoritative) native length becomes the fresh baseline.
        let id = append_new(
            root.path(),
            "example.org",
            Some("alice"),
            "archive",
            Entry {
                id: "after-handoff".into(),
                when: 200000.,
                peer: String::new(),
                xml: "<message><body>new</body></message>".into(),
            },
        )
        .unwrap();
        assert_eq!(id, "after-handoff");
        // The original baseline tail was externally rewritten, so the native
        // holds whatever the external writer put there; checkpoint only retires
        // the journal (handoff), it does not try to re-encode damaged records.
        // A fresh valid journal is (re)created on the next append.
        assert!(path.with_extension("rredo").exists());
    }
}
