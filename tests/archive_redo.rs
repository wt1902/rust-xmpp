//! Crash fixtures model independent loss of unsynced native writes. The redo
//! sidecar is the durable commit source until a native checkpoint or handoff.
use rust_xmpp::{archive, storage};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

fn path(root: &Path) -> PathBuf {
    storage::path(root, "example.org", Some("alice"), "archive").with_extension("list")
}
fn entry(id: &str) -> archive::Entry {
    archive::Entry {
        id: id.into(),
        when: 42.,
        peer: "bob@example.org".into(),
        xml: "<message xmlns='jabber:client'><body>hello</body></message>".into(),
    }
}
fn append(root: &Path, id: &str) {
    archive::append_new(root, "example.org", Some("alice"), "archive", entry(id)).unwrap();
}
fn ids(root: &Path) -> Vec<String> {
    archive::load(root, "example.org", "alice")
        .unwrap()
        .into_iter()
        .map(|e| e.id)
        .collect()
}

#[test]
fn committed_redo_recovers_missing_and_partial_native_without_duplicates() {
    let t = tempfile::tempdir().unwrap();
    append(t.path(), "one");
    append(t.path(), "two");
    let p = path(t.path());
    let expected = fs::read(&p).unwrap();
    for length in [0, 1, expected.len() / 2, expected.len() - 1] {
        fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_len(length as u64)
            .unwrap();
        assert_eq!(ids(t.path()), ["one", "two"]);
        assert_eq!(fs::read(&p).unwrap(), expected);
        assert_eq!(ids(t.path()), ["one", "two"]);
    }
    fs::remove_file(&p).unwrap();
    assert_eq!(ids(t.path()), ["one", "two"]);
    assert_eq!(fs::read(&p).unwrap(), expected);
}

#[test]
fn incomplete_final_frame_and_uncommitted_native_suffix_are_discarded() {
    for extra in [0, 1, 7, 20, 39, 40, 71, 72, 90] {
        let t = tempfile::tempdir().unwrap();
        append(t.path(), "one");
        let p = path(t.path());
        let committed = fs::read(&p).unwrap();
        let journal = p.with_extension("rredo");
        let committed_journal = fs::metadata(&journal).unwrap().len();
        append(t.path(), "two");
        // Construct a crash before the second frame was fully persisted.
        fs::OpenOptions::new()
            .write(true)
            .open(&journal)
            .unwrap()
            .set_len(committed_journal + extra)
            .unwrap();
        assert_eq!(ids(t.path()), ["one"]);
        assert_eq!(fs::read(&p).unwrap(), committed);
        assert_eq!(fs::metadata(&journal).unwrap().len(), committed_journal);
        append(t.path(), "three");
        assert_eq!(ids(t.path()), ["one", "three"]);
    }
}

#[test]
fn complete_checksum_corruption_fails_without_modifying_native_or_journal() {
    for offset in [8, 64, 96, 104, 136, 168] {
        let t = tempfile::tempdir().unwrap();
        append(t.path(), "one");
        let p = path(t.path());
        let native = fs::read(&p).unwrap();
        let journal = p.with_extension("rredo");
        let mut corrupt = fs::read(&journal).unwrap();
        corrupt[offset] ^= 1;
        fs::write(&journal, &corrupt).unwrap();
        assert!(archive::load(t.path(), "example.org", "alice").is_err());
        assert_eq!(fs::read(&p).unwrap(), native);
        assert_eq!(fs::read(&journal).unwrap(), corrupt);
    }
}

#[test]
fn bounded_rotation_recovers_suffix_and_rewrites_never_resurrect_deleted_records() {
    let t = tempfile::tempdir().unwrap();
    for i in 0..300 {
        append(t.path(), &format!("id{i}"));
    }
    let p = path(t.path());
    let journal = p.with_extension("rredo");
    let data = fs::read(&journal).unwrap();
    assert!(data.len() < 1024 * 1024);
    let baseline = u64::from_le_bytes(data[8..16].try_into().unwrap());
    assert!(baseline > 0);
    fs::OpenOptions::new()
        .write(true)
        .open(&p)
        .unwrap()
        .set_len(baseline)
        .unwrap();
    assert_eq!(ids(t.path()).len(), 300);
    archive::delete_ids(
        t.path(),
        "example.org",
        Some("alice"),
        "archive",
        &["id299".into()],
    )
    .unwrap();
    assert_eq!(ids(t.path()).len(), 299);
    append(t.path(), "after-delete");
    assert!(!ids(t.path()).contains(&"id299".into()));
    archive::save_store(
        t.path(),
        "example.org",
        Some("alice"),
        "archive",
        &[entry("replacement")],
    )
    .unwrap();
    assert_eq!(ids(t.path()), ["replacement"]);
    append(t.path(), "after-save");
    assert_eq!(ids(t.path()), ["replacement", "after-save"]);
    archive::expire_before(t.path(), "example.org", Some("alice"), "archive", 43.).unwrap();
    assert!(ids(t.path()).is_empty());
    append(t.path(), "after-expire");
    assert_eq!(ids(t.path()), ["after-expire"]);
}

#[test]
fn byte_limit_rotates_before_frame_count_limit() {
    let t = tempfile::tempdir().unwrap();
    for i in 0..20 {
        let mut e = entry(&format!("big{i}"));
        e.xml = format!("<message><body>{}</body></message>", "x".repeat(100_000));
        archive::append_new(t.path(), "example.org", Some("alice"), "archive", e).unwrap();
    }
    let data = fs::read(path(t.path()).with_extension("rredo")).unwrap();
    assert!(u64::from_le_bytes(data[8..16].try_into().unwrap()) > 0);
    assert!(data.len() < 1024 * 1024 + 110_000);
    assert_eq!(ids(t.path()).len(), 20);
}

#[test]
fn explicit_native_atomic_handoff_and_missing_baseline_never_drops_live_access() {
    let t = tempfile::tempdir().unwrap();
    append(t.path(), "old");
    let p = path(t.path());
    archive::checkpoint_all(t.path()).unwrap();
    // An external writer replaces the native file in place (Prosody `list_store`
    // rewrite), invalidating the committed redo baseline. On first access the
    // untrusted journal is retired and the synced native is adopted as
    // authoritative — exactly what Prosody sees (it has no redo sidecar).
    storage::atomic_write(
        &p,
        b"item({name='message';attr={};key='native';when=42});\n",
    )
    .unwrap();
    assert_eq!(ids(t.path()), ["native"]);
    append(t.path(), "rust");
    assert_eq!(ids(t.path()), ["native", "rust"]);
    // A dirty, uncommitted native suffix is never surfaced.
    fs::OpenOptions::new()
        .append(true)
        .open(&p)
        .unwrap()
        .write_all(b"item(bad uncommitted);")
        .unwrap();
    assert_eq!(ids(t.path()), ["native", "rust"]);
    // Once the untrusted journal has been retired (native adopted as
    // authoritative), externally removing the archive yields the empty history
    // Prosody would return — never a panic or a hang.
    fs::remove_file(&p).unwrap();
    assert!(
        archive::load(t.path(), "example.org", "alice")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn native_baseline_in_place_edits_are_rejected() {
    let t = tempfile::tempdir().unwrap();
    let p = path(t.path());
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    let original = b"item({name='message';attr={};key='native';when=42});\n";
    fs::write(&p, original).unwrap();
    append(t.path(), "rust");
    let mut data = fs::read(&p).unwrap();
    data[5] ^= 1;
    fs::write(&p, &data).unwrap();
    assert!(archive::load(t.path(), "example.org", "alice").is_err());
    assert_eq!(fs::read(&p).unwrap(), data);
}

#[test]
fn redo_process_child() {
    let Some(root) = std::env::var_os("XMPP_ARCHIVE_REDO_CHILD") else {
        return;
    };
    let root = Path::new(&root);
    append(root, "accepted-before-kill");
    fs::write(root.join("ready"), b"ready").unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn killed_writer_retains_accepted_records_after_native_data_loss() {
    let t = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "redo_process_child", "--nocapture"])
        .env("XMPP_ARCHIVE_REDO_CHILD", t.path())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !t.path().join("ready").exists() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("redo child not ready");
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "redo child exited early"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    // Simulate loss of dirty native pages independently of the synced journal.
    fs::OpenOptions::new()
        .write(true)
        .open(path(t.path()))
        .unwrap()
        .set_len(0)
        .unwrap();
    assert_eq!(ids(t.path()), ["accepted-before-kill"]);
    assert_eq!(ids(t.path()), ["accepted-before-kill"]);
}

#[test]
fn durable_handoff_allows_native_in_place_append_and_next_rust_append() {
    let t = tempfile::tempdir().unwrap();
    append(t.path(), "rust-before");
    let p = path(t.path());
    assert_eq!(archive::checkpoint_all(t.path()).unwrap(), 1);
    assert!(!p.with_extension("rredo").exists());
    fs::OpenOptions::new()
        .append(true)
        .open(&p)
        .unwrap()
        .write_all(b"item({name='message';attr={};key='native';when=42});\n")
        .unwrap();
    assert_eq!(ids(t.path()), ["rust-before", "native"]);
    append(t.path(), "rust-after");
    assert_eq!(ids(t.path()), ["rust-before", "native", "rust-after"]);
    assert_eq!(archive::checkpoint_all(t.path()).unwrap(), 1);
    assert_eq!(archive::checkpoint_all(t.path()).unwrap(), 0);
}

#[test]
fn legacy_rollback_marker_is_migrated_before_redo_append() {
    let t = tempfile::tempdir().unwrap();
    let p = path(t.path());
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    let original = b"item({name='message';attr={};key='legacy';when=42});\n";
    fs::write(&p, [original.as_slice(), b"item(broken"].concat()).unwrap();
    fs::write(
        p.with_extension("rappend"),
        (original.len() as u64).to_le_bytes(),
    )
    .unwrap();
    append(t.path(), "redo");
    assert_eq!(ids(t.path()), ["legacy", "redo"]);
    assert!(!p.with_extension("rappend").exists());
    assert!(p.with_extension("rredo").exists());
}

#[test]
fn copied_archive_replays_committed_redo_despite_new_native_inode() {
    for native_baseline in [false, true] {
        for lose_entire_suffix in [false, true] {
            let source = tempfile::tempdir().unwrap();
            let source_path = path(source.path());
            if native_baseline {
                fs::create_dir_all(source_path.parent().unwrap()).unwrap();
                fs::write(
                    &source_path,
                    b"item({name='message';attr={};key='baseline';when=42});\n",
                )
                .unwrap();
            }
            append(source.path(), "accepted-one");
            append(source.path(), "accepted-two");
            let expected = fs::read(&source_path).unwrap();
            let redo = fs::read(source_path.with_extension("rredo")).unwrap();
            let baseline = u64::from_le_bytes(redo[8..16].try_into().unwrap());
            let restored = tempfile::tempdir().unwrap();
            let restored_path = path(restored.path());
            fs::create_dir_all(restored_path.parent().unwrap()).unwrap();
            fs::copy(&source_path, &restored_path).unwrap();
            fs::copy(
                source_path.with_extension("rredo"),
                restored_path.with_extension("rredo"),
            )
            .unwrap();
            let length = if lose_entire_suffix {
                baseline
            } else {
                expected.len() as u64 - 1
            };
            fs::OpenOptions::new()
                .write(true)
                .open(&restored_path)
                .unwrap()
                .set_len(length)
                .unwrap();
            let recovered = ids(restored.path());
            assert_eq!(recovered.last().unwrap(), "accepted-two");
            assert_eq!(recovered.len(), if native_baseline { 3 } else { 2 });
            assert_eq!(fs::read(&restored_path).unwrap(), expected);
            append(restored.path(), "after-restore");
            assert_eq!(ids(restored.path()).last().unwrap(), "after-restore");
        }
    }
}

#[test]
fn atomic_native_replace_without_handoff_cannot_discard_committed_frames() {
    let t = tempfile::tempdir().unwrap();
    append(t.path(), "accepted");
    let p = path(t.path());
    storage::atomic_write(
        &p,
        b"item({name='message';attr={};key='replacement';when=42});\n",
    )
    .unwrap();
    // A replacement without handoff is not authority to discard committed WAL.
    assert_eq!(ids(t.path()), ["accepted"]);
}
