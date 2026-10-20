//! Offline, source-preserving upload migration. The journal is the startup barrier.
use crate::{
    config::Config,
    object_store::{ObjectStore, PART_SIZE, UploadBackendConfig},
    storage,
};
use anyhow::{Context, Result, ensure};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const JOURNAL: &str = "rust_upload_migration.json";
#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    component: String,
    source: Value,
    destination: Value,
    metadata: String,
    committed: bool,
    objects: BTreeMap<String, Progress>,
}
#[derive(Default, Serialize, Deserialize)]
struct Progress {
    checksum: Option<String>,
    verified: bool,
    upload_id: Option<String>,
}
struct Backend(Option<ObjectStore>);
impl Backend {
    fn new(c: UploadBackendConfig) -> Result<Self> {
        Ok(Self(match c {
            UploadBackendConfig::Local => None,
            UploadBackendConfig::S3(c) => Some(ObjectStore::new(c)?),
        }))
    }
    fn identity(&self) -> Value {
        self.0
            .as_ref()
            .map(ObjectStore::identity)
            .unwrap_or_else(|| serde_json::json!({"backend":"local"}))
    }
}
fn save(path: &Path, journal: &Journal) -> Result<()> {
    storage::atomic_write(path, &serde_json::to_vec_pretty(journal)?)
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn local_path(dir: &Path, id: &str) -> PathBuf {
    dir.join("http_file_share")
        .join(format!("{}.bin", storage::encode_name(id)))
}

/// Check all component directories, including components removed from the new config.
pub fn ensure_no_pending(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path().join(JOURNAL);
        if path.exists() {
            let journal: Journal = serde_json::from_slice(&std::fs::read(&path)?)
                .context("invalid upload migration journal; offline recovery required")?;
            ensure!(
                journal.version == 1 && journal.committed,
                "pending upload migration; resume upload-migrate before starting the server"
            );
        }
    }
    Ok(())
}
fn validate_component(config: &Config, component: &str) -> Result<()> {
    ensure!(
        config
            .hosts
            .get(component)
            .and_then(|h| h.component.as_deref())
            == Some("http_file_share"),
        "component must be an HTTP file share in both configurations"
    );
    Ok(())
}
fn stable_settings(old: &Config, new: &Config, component: &str) -> Result<()> {
    // Keep URL construction and JWT verification exactly as configured, including inherited options.
    for key in [
        "http_file_share_secret",
        "http_file_share_base_url",
        "http_host",
        "http_default_host",
        "http_external_url",
        "http_paths",
        "http_ports",
        "https_ports",
    ] {
        ensure!(
            old.option(component, key) == new.option(component, key),
            "migration must preserve {key}; change public routing separately after migration"
        );
    }
    Ok(())
}

/// Plan by default. Execution never deletes source objects or rewrites native metadata.
pub async fn migrate(
    old_path: &Path,
    new_path: &Path,
    component: &str,
    execute: bool,
) -> Result<()> {
    let (old, old_domain) = crate::server::settings_config(old_path)?;
    let (new, new_domain) = crate::server::settings_config(new_path)?;
    ensure!(
        old_domain == new_domain,
        "virtual host must remain unchanged"
    );
    for key in ["http_ports", "https_ports", "data_path"] {
        ensure!(
            old.option(&old_domain, key) == new.option(&new_domain, key),
            "migration must preserve runtime {key}"
        );
    }
    stable_settings(&old, &new, component)?;
    validate_component(&old, component)?;
    validate_component(&new, component)?;
    let root = PathBuf::from(
        old.option(&old_domain, "data_path")
            .and_then(Value::as_str)
            .context("data_path required")?,
    );
    let new_root = PathBuf::from(
        new.option(&new_domain, "data_path")
            .and_then(Value::as_str)
            .context("data_path required")?,
    );
    ensure!(
        root.is_dir() && new_root.is_dir(),
        "existing data directories required"
    );
    ensure!(
        root.canonicalize()? == new_root.canonicalize()?,
        "migration requires the same data directory; native metadata must stay in place"
    );
    let _guard = crate::data_lock::DataDirectoryGuard::acquire(&root)?;
    let source = Backend::new(crate::server::upload_backend(&old, component)?)?;
    let target = Backend::new(crate::server::upload_backend(&new, component)?)?;
    ensure!(
        source.identity() != target.identity(),
        "source and destination backend identities are identical"
    );
    let dir = root.join(storage::encode_name(component));
    let cache = match std::fs::read(dir.join("rust_uploads.json")) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => b"{}".to_vec(),
        Err(e) => return Err(e.into()),
    };
    let records: BTreeMap<String, Value> = serde_json::from_slice(&cache)?;
    ensure!(
        !storage::path(&root, component, None, "uploads")
            .with_extension("rappend")
            .exists(),
        "upload archive has pending append recovery; recover source server before migration"
    );
    let entries = crate::archive::load_store(&root, component, None, "uploads")?;
    let mut seen = std::collections::BTreeSet::new();
    let mut objects = BTreeMap::new();
    let mut fingerprint = Sha256::new();
    // Lua table traversal can reorder reconstructed XML attributes between
    // processes. Bind exact authoritative archive bytes, not reconstructed XML.
    fingerprint.update((cache.len() as u64).to_le_bytes());
    fingerprint.update(&cache);
    let archive_path = storage::path(&root, component, None, "uploads").with_extension("list");
    let archive_bytes = match std::fs::read(archive_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    fingerprint.update((archive_bytes.len() as u64).to_le_bytes());
    fingerprint.update(&archive_bytes);
    for e in entries {
        ensure!(
            seen.insert(e.id.clone()),
            "duplicate authoritative upload id"
        );
        let doc = roxmltree::Document::parse(&e.xml)?;
        let node = doc.root_element();
        let size: u64 = node
            .attribute("size")
            .context("upload size missing")?
            .parse()?;
        let filename = node
            .attribute("filename")
            .context("upload filename missing")?;
        let r = records.get(&e.id);
        if let Some(r) = r {
            ensure!(
                r.get("owner").and_then(Value::as_str) == Some(&e.peer)
                    && r.get("filename").and_then(Value::as_str) == Some(filename)
                    && r.get("size").and_then(Value::as_u64) == Some(size),
                "slot metadata/cache mismatch; recover source server first"
            );
            ensure!(
                r.get("upload_id").is_none_or(Value::is_null)
                    && r.get("multipart_intent").and_then(Value::as_bool) != Some(true)
                    && r.get("completion_attempted").and_then(Value::as_bool) != Some(true),
                "slot has unfinished multipart state; recover source server first"
            );
        }
        // Native Prosody files need no Rust completion sidecar. A present final
        // object of exact declared size is completed; absent reservations stay pending.
        let complete = r.and_then(|r| r.get("complete")).and_then(Value::as_bool) == Some(true);
        let present = if complete {
            true
        } else if let Some(store) = &source.0 {
            match store.stat(&e.id).await? {
                Some(n) => {
                    ensure!(n == size, "source object size mismatch");
                    true
                }
                None => false,
            }
        } else {
            local_path(&dir, &e.id).exists()
        };
        if complete || present {
            ensure!(
                objects
                    .insert(
                        e.id.clone(),
                        (
                            size,
                            node.attribute("content-type")
                                .unwrap_or("application/octet-stream")
                                .to_owned()
                        )
                    )
                    .is_none(),
                "duplicate upload id"
            );
        }
    }
    let metadata = hex::encode(fingerprint.finalize());
    let journal_path = dir.join(JOURNAL);
    let mut resumed = false;
    let fresh = || Journal {
        version: 1,
        component: component.into(),
        source: source.identity(),
        destination: target.identity(),
        metadata: metadata.clone(),
        committed: false,
        objects: objects
            .keys()
            .map(|id| (id.clone(), Progress::default()))
            .collect(),
    };
    let mut journal = if journal_path.exists() {
        let j: Journal = serde_json::from_slice(&std::fs::read(&journal_path)?)?;
        if j.version == 1
            && j.committed
            && (j.source != source.identity()
                || j.destination != target.identity()
                || j.metadata != metadata)
        {
            fresh()
        } else {
            ensure!(
                j.version == 1
                    && j.component == component
                    && j.source == source.identity()
                    && j.destination == target.identity()
                    && j.metadata == metadata
                    && j.objects.keys().eq(objects.keys()),
                "migration journal does not match configurations or metadata"
            );
            resumed = true;
            j
        }
    } else {
        fresh()
    };
    let identity_path = dir.join("rust_upload_backend.json");
    let current: Value = if identity_path.exists() {
        serde_json::from_slice(&std::fs::read(&identity_path)?)?
    } else {
        serde_json::json!({"backend":"local"})
    };
    ensure!(
        current == source.identity() || (resumed && current == target.identity()),
        "recorded backend is not the migration source"
    );
    println!(
        "{} completed objects; source objects and all native metadata will be preserved",
        objects.len()
    );
    if !execute {
        println!(
            "Dry run: no objects, journal or backend identity changed. Use --execute to copy and verify."
        );
        return Ok(());
    }
    if journal.committed {
        ensure!(
            current == target.identity(),
            "committed migration identity mismatch"
        );
        println!("Migration already committed.");
        return Ok(());
    }
    save(&journal_path, &journal)?;
    for (id, (size, content_type)) in &objects {
        // Deterministic journal-owned spools can be removed safely after a crash.
        let temp = dir.join(format!(".migration-{}.tmp", digest(id.as_bytes())));
        if temp.exists() {
            std::fs::remove_file(&temp)?;
        }
        let result = async {
            let checksum = spool(&source, &dir, id, *size, &temp)
                .await?
                .context("source object missing")?;
            if let Some(previous) = &journal.objects[id].checksum {
                ensure!(
                    *previous == checksum,
                    "source checksum changed during migration"
                );
            }
            journal.objects.get_mut(id).unwrap().checksum = Some(checksum.clone());
            save(&journal_path, &journal)?;
            // The durable per-object checksum precedes initiation. Sweep this
            // exact key, including an initiation whose response was lost.
            if let Some(store) = &target.0 {
                store.abort_pending(id).await?;
            }
            if let Some(upload_id) = journal.objects[id].upload_id.as_ref() {
                target
                    .0
                    .as_ref()
                    .context("invalid local multipart journal")?
                    .abort(id, upload_id)
                    .await?;
                journal.objects.get_mut(id).unwrap().upload_id = None;
                save(&journal_path, &journal)?;
            }
            let existing = object_checksum(&target, &dir, id, *size).await;
            let existing = existing?;
            if let Some(existing) = existing {
                ensure!(
                    existing == checksum,
                    "destination object conflicts; refusing overwrite"
                );
            } else {
                ensure!(
                    !journal.objects[id].verified,
                    "previously verified destination object disappeared"
                );
                if let Some(store) = &target.0 {
                    let mut upload = store.begin(id, content_type).await?;
                    journal.objects.get_mut(id).unwrap().upload_id =
                        Some(upload.upload_id().into());
                    save(&journal_path, &journal)?;
                    let mut file = std::fs::File::open(&temp)?;
                    loop {
                        let mut part = vec![0; PART_SIZE];
                        let mut n = 0;
                        while n < part.len() {
                            let read = file.read(&mut part[n..])?;
                            if read == 0 {
                                break;
                            }
                            n += read;
                        }
                        part.truncate(n);
                        if n == 0 {
                            if *size == 0 {
                                upload.part(part).await?;
                            }
                            break;
                        }
                        upload.part(part).await?;
                    }
                    upload.complete().await?;
                    journal.objects.get_mut(id).unwrap().upload_id = None;
                    save(&journal_path, &journal)?;
                } else {
                    let path = local_path(&dir, id);
                    std::fs::create_dir_all(path.parent().unwrap())?;
                    // Hard-link publishes without clobbering an existing object; spool is on the same filesystem.
                    std::fs::hard_link(&temp, &path)?;
                    std::fs::File::open(path.parent().unwrap())?.sync_all()?;
                }
                let verified = object_checksum(&target, &dir, id, *size).await;
                ensure!(
                    verified?.as_deref() == Some(checksum.as_str()),
                    "destination checksum mismatch"
                );
            }
            journal.objects.get_mut(id).unwrap().verified = true;
            save(&journal_path, &journal)?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let _ = std::fs::remove_file(&temp);
        result.with_context(|| {
            format!(
                "migration stopped at object {id}; source preserved, resume with the same command"
            )
        })?;
    }
    ensure!(
        journal.objects.values().all(|p| p.verified),
        "unverified migration objects"
    );
    storage::atomic_write(&identity_path, &serde_json::to_vec(&target.identity())?)?;
    journal.committed = true;
    save(&journal_path, &journal)?;
    println!("Migration committed: all destination objects checksum verified; source preserved.");
    Ok(())
}

/// Stream through a private, bounded spool; never trust ETag as a content checksum.
async fn spool(
    backend: &Backend,
    dir: &Path,
    id: &str,
    size: u64,
    temp: &Path,
) -> Result<Option<String>> {
    spool_to(backend, dir, id, size, Some(temp)).await
}
async fn object_checksum(
    backend: &Backend,
    dir: &Path,
    id: &str,
    size: u64,
) -> Result<Option<String>> {
    spool_to(backend, dir, id, size, None).await
}
async fn spool_to(
    backend: &Backend,
    dir: &Path,
    id: &str,
    size: u64,
    temp: Option<&Path>,
) -> Result<Option<String>> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = temp.map(|temp| options.open(temp)).transpose()?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    if let Some(store) = &backend.0 {
        let response = store.read(id, false, None).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        ensure!(
            response.status() == 200,
            "object download failed or returned partial content"
        );
        let mut body = response.into_body();
        while let Some(frame) =
            tokio::time::timeout(std::time::Duration::from_secs(120), body.frame())
                .await
                .context("migration download timed out")?
        {
            let frame = frame?;
            if let Some(bytes) = frame.data_ref() {
                total = total
                    .checked_add(bytes.len() as u64)
                    .context("size overflow")?;
                ensure!(total <= size, "object exceeds metadata size");
                hash.update(bytes);
                if let Some(file) = &mut file {
                    file.write_all(bytes)?;
                }
            }
        }
    } else {
        let path = local_path(dir, id);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        ensure!(
            metadata.file_type().is_file() && metadata.len() == size,
            "local object is not a regular file of metadata size"
        );
        let mut source = std::fs::File::open(path)?;
        let mut bytes = vec![0; PART_SIZE];
        loop {
            let n = source.read(&mut bytes)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            ensure!(total <= size, "object exceeds metadata size");
            hash.update(&bytes[..n]);
            if let Some(file) = &mut file {
                file.write_all(&bytes[..n])?;
            }
        }
    }
    ensure!(total == size, "object size differs from metadata");
    if let Some(file) = file {
        file.sync_all()?;
    }
    Ok(Some(hex::encode(hash.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn local_spool_checks_size_and_hash_and_preserves_source() {
        let d = tempfile::tempdir().unwrap();
        let path = local_path(d.path(), "a/b");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"payload").unwrap();
        let temp = d.path().join("spool");
        assert_eq!(
            spool(&Backend(None), d.path(), "a/b", 7, &temp)
                .await
                .unwrap(),
            Some(digest(b"payload"))
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        assert!(
            spool(&Backend(None), d.path(), "a/b", 8, &d.path().join("bad"))
                .await
                .is_err()
        );
    }
    #[test]
    fn pending_and_corrupt_journals_block_startup() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("removed-component").join(JOURNAL);
        let mut j = Journal {
            version: 1,
            component: "upload".into(),
            source: Value::Null,
            destination: Value::Null,
            metadata: "a".into(),
            committed: false,
            objects: BTreeMap::new(),
        };
        save(&path, &j).unwrap();
        assert!(ensure_no_pending(d.path()).is_err());
        j.committed = true;
        save(&path, &j).unwrap();
        assert!(ensure_no_pending(d.path()).is_ok());
        std::fs::write(path, b"broken").unwrap();
        assert!(ensure_no_pending(d.path()).is_err());
    }
}
