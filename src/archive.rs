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
fn recover_append(p: &Path) -> Result<()> {
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
    recover_append(&p)?;
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
    let path = storage::path(root, host, user, store).with_extension("list");
    let parent = path.parent().unwrap();
    std::fs::create_dir_all(parent)?;
    recover_append(&path)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path)?;
    let length = file.metadata()?.len();
    let journal = path.with_extension("rappend");
    storage::atomic_write(&journal, &length.to_le_bytes())?;
    match std::fs::remove_file(path.with_extension("lidx")) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let result = (|| -> Result<()> {
        file.write_all(data.as_bytes())?;
        file.sync_all()?;
        std::fs::remove_file(&journal)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        recover_append(&path)?;
    }
    result
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
