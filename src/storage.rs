//! Lossless, bounded Prosody internal key/value persistence.
use anyhow::{Result, bail, ensure};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
static TRANSACTION: Mutex<()> = Mutex::new(());
const LIMIT: usize = 16 * 1024 * 1024;
#[derive(Clone, Debug)]
pub enum LuaValue {
    Nil,
    Bool(bool),
    Integer(i64),
    Number(f64),
    String(Vec<u8>),
    Table(Vec<(LuaValue, LuaValue)>),
}
impl PartialEq for LuaValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Nil, Self::Nil) => true,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Integer(a), Self::Integer(b)) => a == b,
            (Self::Number(a), Self::Number(b)) => a == b,
            (Self::Integer(a), Self::Number(b)) | (Self::Number(b), Self::Integer(a)) => {
                b.is_finite()
                    && b.fract() == 0.0
                    && *b >= i64::MIN as f64
                    && *b < (i64::MAX as f64)
                    && *a == *b as i64
            }
            (Self::String(a), Self::String(b)) => a == b,
            (Self::Table(a), Self::Table(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .all(|(k, v)| b.iter().any(|(k2, v2)| k == k2 && v == v2))
            }
            _ => false,
        }
    }
}
impl Default for LuaValue {
    fn default() -> Self {
        Self::Table(vec![])
    }
}
impl From<&str> for LuaValue {
    fn from(v: &str) -> Self {
        Self::String(v.as_bytes().to_vec())
    }
}
impl From<String> for LuaValue {
    fn from(v: String) -> Self {
        Self::String(v.into_bytes())
    }
}
impl LuaValue {
    pub fn table() -> Self {
        Self::default()
    }
    pub fn get_key(&self, k: &Self) -> Option<&Self> {
        if let Self::Table(t) = self {
            t.iter().find(|(a, _)| a == k).map(|(_, v)| v)
        } else {
            None
        }
    }
    pub fn get(&self, k: &str) -> Option<&Self> {
        self.get_key(&k.into())
    }
    pub fn set_key(&mut self, k: Self, v: Self) {
        if let Self::Table(t) = self {
            t.retain(|(a, _)| a != &k);
            if v != Self::Nil {
                t.push((k, v));
            }
        }
    }
    pub fn set(&mut self, k: &str, v: Self) {
        self.set_key(k.into(), v)
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            std::str::from_utf8(s).ok()
        } else {
            None
        }
    }
    pub fn entries(&self) -> &[(Self, Self)] {
        if let Self::Table(t) = self { t } else { &[] }
    }
    pub fn as_i64(&self) -> Option<i64> {
        if let Self::Integer(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}
pub fn encode_name(name: &str) -> String {
    encode(name, false)
}
fn encode(name: &str, store: bool) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || (store && b == b'_') {
            out.push(b as char)
        } else {
            out.push_str(&format!("%{b:02x}"))
        }
    }
    out
}
pub fn path(root: &Path, host: &str, user: Option<&str>, store: &str) -> PathBuf {
    let d = root.join(encode_name(host));
    match user {
        Some(u) => d
            .join(encode(store, true))
            .join(format!("{}.dat", encode_name(u))),
        None => d.join(format!("{}.dat", encode(store, true))),
    }
}
pub fn parse(input: &[u8]) -> Result<LuaValue> {
    ensure!(input.len() <= LIMIT, "storage limit exceeded");
    let lua = crate::lua::bounded_vm().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let env = lua
        .create_table()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let v = lua
        .load(input)
        .set_mode(mlua::chunk::ChunkMode::Text)
        .set_environment(env)
        .eval::<mlua::Value>()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    from_lua(v)
}
pub fn from_lua(v: mlua::Value) -> Result<LuaValue> {
    fn convert(v: mlua::Value, depth: usize, count: &mut usize) -> Result<LuaValue> {
        *count += 1;
        ensure!(depth < 64 && *count <= 200_000, "storage complexity limit");
        Ok(match v {
            mlua::Value::Nil => LuaValue::Nil,
            mlua::Value::Boolean(v) => LuaValue::Bool(v),
            mlua::Value::Integer(v) => LuaValue::Integer(v),
            mlua::Value::Number(v) => {
                ensure!(v.is_finite(), "non-finite storage number");
                LuaValue::Number(v)
            }
            mlua::Value::String(v) => LuaValue::String(v.as_bytes().to_vec()),
            mlua::Value::Table(t) => {
                let mut o = vec![];
                for p in t.pairs::<mlua::Value, mlua::Value>() {
                    let (k, v) = p.map_err(|e| anyhow::anyhow!(e.to_string()))?;
                    ensure!(
                        matches!(
                            k,
                            mlua::Value::Boolean(_)
                                | mlua::Value::String(_)
                                | mlua::Value::Integer(_)
                                | mlua::Value::Number(_)
                        ),
                        "unsupported table key"
                    );
                    o.push((convert(k, depth + 1, count)?, convert(v, depth + 1, count)?));
                }
                LuaValue::Table(o)
            }
            _ => bail!("unsupported storage value"),
        })
    }
    convert(v, 0, &mut 0)
}
pub fn serialize(value: &LuaValue) -> Result<String> {
    fn put(v: &LuaValue, s: &mut String, d: usize) -> Result<()> {
        ensure!(d < 64 && s.len() <= LIMIT, "storage complexity limit");
        match v {
            LuaValue::Nil => s.push_str("nil"),
            LuaValue::Bool(v) => s.push_str(if *v { "true" } else { "false" }),
            LuaValue::Integer(v) => s.push_str(&v.to_string()),
            LuaValue::Number(v) => {
                ensure!(v.is_finite(), "non-finite storage number");
                s.push_str(&format!("{v:?}"))
            }
            LuaValue::String(v) => {
                s.push('"');
                for b in v {
                    match b {
                        b'"' => s.push_str("\\\""),
                        b'\\' => s.push_str("\\\\"),
                        32..=126 => s.push(*b as char),
                        _ => s.push_str(&format!("\\{b:03}")),
                    }
                }
                s.push('"')
            }
            LuaValue::Table(t) => {
                s.push('{');
                for (k, v) in t {
                    ensure!(
                        matches!(
                            k,
                            LuaValue::Bool(_)
                                | LuaValue::Integer(_)
                                | LuaValue::Number(_)
                                | LuaValue::String(_)
                        ),
                        "invalid key"
                    );
                    s.push('[');
                    put(k, s, d + 1)?;
                    s.push_str("]=");
                    put(v, s, d + 1)?;
                    s.push(';')
                }
                s.push('}')
            }
        }
        Ok(())
    }
    let mut s = "return ".to_string();
    put(value, &mut s, 0)?;
    s.push_str(";\n");
    ensure!(s.len() <= LIMIT, "storage limit exceeded");
    Ok(s)
}
pub fn load(root: &Path, host: &str, user: Option<&str>, store: &str) -> Result<Option<LuaValue>> {
    let p = path(root, host, user, store);
    let f = match fs::File::open(&p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut b = vec![];
    f.take((LIMIT + 1) as u64).read_to_end(&mut b)?;
    Ok(Some(parse(&b)?))
}
pub fn atomic_write(p: &Path, data: &[u8]) -> Result<()> {
    let parent = p
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, p)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
pub fn save(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    value: &LuaValue,
) -> Result<()> {
    if matches!(value, LuaValue::Nil) || matches!(value,LuaValue::Table(v) if v.is_empty()) {
        let p = path(root, host, user, store);
        match fs::remove_file(&p) {
            Ok(()) => {
                if let Some(parent) = p.parent() {
                    fs::File::open(parent)?.sync_all()?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        return Ok(());
    }
    let s = serialize(value)?;
    atomic_write(&path(root, host, user, store), s.as_bytes())
}
/// Process-local serialized read/modify/write. Never run two servers on one data directory.
pub fn update<F: FnOnce(&mut LuaValue) -> Result<()>>(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    f: F,
) -> Result<LuaValue> {
    let _g = TRANSACTION
        .lock()
        .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
    let mut v = load(root, host, user, store)?.unwrap_or_default();
    ensure!(matches!(v, LuaValue::Table(_)), "store is not a table");
    f(&mut v)?;
    save(root, host, user, store, &v)?;
    Ok(v)
}
/// util.stanza.preserialize-compatible representation (mixed numeric/string keys).
pub fn stanza_value(n: roxmltree::Node<'_, '_>) -> LuaValue {
    if n.is_text() {
        return n.text().unwrap_or("").into();
    }
    let mut t = LuaValue::table();
    t.set("name", n.tag_name().name().into());
    let mut attr = LuaValue::table();
    attr.set("xmlns", n.tag_name().namespace().unwrap_or("").into());
    for a in n.attributes() {
        let key = match a.namespace() {
            Some("http://www.w3.org/XML/1998/namespace") => format!("xml:{}", a.name()),
            Some(ns) => format!("{ns}\u{1}{}", a.name()),
            None => a.name().into(),
        };
        attr.set(&key, a.value().into());
    }
    t.set("attr", attr);
    for (i, c) in n
        .children()
        .filter(|x| x.is_element() || x.is_text())
        .enumerate()
    {
        t.set_key(LuaValue::Integer(i as i64 + 1), stanza_value(c));
    }
    t
}
pub fn stanza_xml(v: &LuaValue) -> Result<String> {
    use crate::wire::escape;
    if let LuaValue::String(s) = v {
        return Ok(escape(std::str::from_utf8(s)?));
    }
    let name = v
        .get("name")
        .and_then(LuaValue::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing stanza name"))?;
    ensure!(
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || "_-.".contains(c)),
        "invalid stanza name"
    );
    let mut s = format!("<{name}");
    let mut namespace_index = 0;
    if let Some(a) = v.get("attr") {
        for (k, val) in a.entries() {
            let key = k
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid attribute key"))?;
            let val = val
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid attribute value"))?;
            let split = key.split_once('\u{1}').or_else(|| key.split_once('|'));
            if let Some((ns, local)) = split {
                ensure!(
                    !local.is_empty()
                        && local
                            .chars()
                            .all(|c| c.is_alphanumeric() || "_-.".contains(c)),
                    "invalid attribute"
                );
                if ns == "http://www.w3.org/XML/1998/namespace" {
                    s.push_str(&format!(" xml:{local}='{}'", escape(val)))
                } else {
                    namespace_index += 1;
                    s.push_str(&format!(
                        " xmlns:a{namespace_index}='{}' a{namespace_index}:{local}='{}'",
                        escape(ns),
                        escape(val)
                    ))
                }
            } else {
                ensure!(
                    !key.is_empty()
                        && key
                            .chars()
                            .all(|c| c.is_alphanumeric() || "_-.:".contains(c)),
                    "invalid attribute"
                );
                s.push_str(&format!(" {key}='{}'", escape(val)))
            }
        }
    }
    s.push('>');
    let mut i = 1;
    while let Some(child) = v.get_key(&LuaValue::Integer(i)) {
        s.push_str(&stanza_xml(child)?);
        i += 1;
    }
    s.push_str(&format!("</{name}>"));
    Ok(s)
}
/// Prosody datamanager.purge semantics. Caller must stop this user's sessions first.
/// Unknown stores are included, but only exact per-user storage files are removed.
pub fn purge_user(root: &Path, host: &str, user: &str) -> Result<()> {
    let _guard = TRANSACTION
        .lock()
        .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
    ensure!(
        !host.is_empty() && !user.is_empty(),
        "host and user required"
    );
    let dir = root.join(encode_name(host));
    let meta = match fs::symlink_metadata(&dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "refusing symlinked data host"
    );
    let user = encode_name(user);
    let mut files = vec![];
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        ensure!(
            !ty.is_symlink(),
            "refusing symlinked host store during account purge"
        );
        if !ty.is_dir() {
            continue;
        }
        for extension in ["dat", "list", "lidx", "rappend"] {
            let p = entry.path().join(format!("{user}.{extension}"));
            match fs::symlink_metadata(&p) {
                Ok(m) => {
                    ensure!(
                        m.is_file() || m.file_type().is_symlink(),
                        "account store path is not a file"
                    );
                    files.push(p)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    // Revoke login before deleting the remainder; failures are returned, never hidden.
    files.sort_by_key(|p| {
        if p.parent()
            .and_then(|p| p.file_name())
            .is_some_and(|s| s == "accounts")
        {
            0
        } else {
            1
        }
    });
    let mut errors = vec![];
    for p in files {
        match fs::remove_file(&p) {
            Ok(()) => {
                if let Some(parent) = p.parent()
                    && let Err(e) = fs::File::open(parent).and_then(|f| f.sync_all())
                {
                    errors.push(e.to_string())
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(e.to_string()),
        }
    }
    ensure!(
        errors.is_empty(),
        "account purge failed: {}",
        errors.join("; ")
    );
    Ok(())
}
/// Coordinate account creation with key/value updates and user purges.
/// The callback must not call `update`, `purge_user`, or this function recursively.
pub fn with_exclusive_access<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let _guard = TRANSACTION
        .lock()
        .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
    f()
}
