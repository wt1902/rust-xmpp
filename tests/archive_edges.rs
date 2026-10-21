use rust_xmpp::{archive, storage};
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const MAX_RECORD: usize = 16 * 1024 * 1024;

fn path(root: &Path) -> PathBuf {
    let p = storage::path(root, "example.org", Some("alice"), "archive").with_extension("list");
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    p
}
fn record(id: &str) -> String {
    format!(
        "item({{name='message';attr={{xmlns='jabber:client'}};key='{id}';when=42;with='bob@example.org';{{name='body';attr={{}};'hello'}}}});\n"
    )
}
fn edges(root: &Path) -> anyhow::Result<Option<(archive::Entry, archive::Entry)>> {
    archive::edges_store(root, "example.org", Some("alice"), "archive")
}

#[test]
fn metadata_skips_large_malformed_middle_without_creating_cache() {
    let t = tempfile::tempdir().unwrap();
    let p = path(t.path());
    let mut file = File::create(&p).unwrap();
    file.write_all(record("first").as_bytes()).unwrap();
    file.write_all(b"item(not valid Lua in the middle\n")
        .unwrap();
    // A sparse >128 MiB history makes accidental full scans fail the record
    // bound; only the endpoints are part of this metadata operation.
    file.seek(SeekFrom::Start(129 * 1024 * 1024)).unwrap();
    file.write_all(b"\n").unwrap();
    file.write_all(record("last").as_bytes()).unwrap();
    drop(file);
    let (first, last) = edges(t.path()).unwrap().unwrap();
    assert_eq!((first.id.as_str(), last.id.as_str()), ("first", "last"));
    assert_eq!(first.when, 42.0);
    assert_eq!(last.peer, "bob@example.org");
    assert!(!p.with_extension("lidx").exists());
    assert!(archive::load(t.path(), "example.org", "alice").is_err());

    // An opaque native index is irrelevant and must remain untouched.
    fs::write(p.with_extension("lidx"), b"stale binary index").unwrap();
    assert_eq!(edges(t.path()).unwrap().unwrap().1.id, "last");
    assert_eq!(
        fs::read(p.with_extension("lidx")).unwrap(),
        b"stale binary index"
    );
}

#[test]
fn multiline_endpoints_match_native_scanner_with_blank_lines() {
    let t = tempfile::tempdir().unwrap();
    let p = path(t.path());
    let first = record("first").replace(";", ";\n");
    let last = format!(
        "item({{\nname='message';attr={{}};key='last';when=43;\n{{name='body';attr={{}};[=[{}]=]}}\n}});\n \t\n",
        "long multiline text\n".repeat(1800)
    );
    fs::write(&p, format!(" \t\n\n{first}\n{}{last}", record("middle"))).unwrap();
    let rows = archive::load(t.path(), "example.org", "alice").unwrap();
    let (a, b) = edges(t.path()).unwrap().unwrap();
    assert_eq!(a.id, rows.first().unwrap().id);
    assert_eq!(b.id, rows.last().unwrap().id);
    assert_eq!(b.xml, rows.last().unwrap().xml);
}

#[test]
fn missing_empty_whitespace_and_single_record() {
    let t = tempfile::tempdir().unwrap();
    assert!(edges(t.path()).unwrap().is_none());
    let p = path(t.path());
    for contents in ["", " \t\r\n\n"] {
        fs::write(&p, contents).unwrap();
        assert!(edges(t.path()).unwrap().is_none());
    }
    // EOF need not have a newline.
    fs::write(&p, record("only").trim_end()).unwrap();
    let (first, last) = edges(t.path()).unwrap().unwrap();
    assert_eq!(first.id, "only");
    assert_eq!(last.id, first.id);
    assert_eq!(last.xml, first.xml);
}

#[test]
fn tail_padding_respects_record_bound() {
    let t = tempfile::tempdir().unwrap();
    let p = path(t.path());
    let mut data = record("first").into_bytes();
    let last = record("last");
    data.extend_from_slice(last.as_bytes());
    data.resize(data.len() + MAX_RECORD - last.len(), b' ');
    fs::write(&p, &data).unwrap();
    assert_eq!(edges(t.path()).unwrap().unwrap().1.id, "last");
    data.push(b' ');
    fs::write(&p, data).unwrap();
    assert!(edges(t.path()).unwrap_err().to_string().contains("16 MiB"));
}

#[test]
fn oversized_prefix_and_malformed_endpoints_fail() {
    let t = tempfile::tempdir().unwrap();
    let p = path(t.path());
    let mut data = vec![b' '; MAX_RECORD + 1];
    data.extend_from_slice(b"\n");
    data.extend_from_slice(record("last").as_bytes());
    fs::write(&p, data).unwrap();
    assert!(edges(t.path()).unwrap_err().to_string().contains("16 MiB"));
    fs::write(&p, format!("item(bad first);\n{}", record("last"))).unwrap();
    assert!(edges(t.path()).is_err());
    fs::write(&p, format!("{}item(bad last);\n", record("first"))).unwrap();
    assert!(edges(t.path()).is_err());
}

#[test]
fn endpoint_read_recovers_partial_append_before_seeking() {
    let t = tempfile::tempdir().unwrap();
    let p = path(t.path());
    let committed = format!("{}{}", record("first"), record("last"));
    fs::write(&p, format!("{committed}item({{broken partial")).unwrap();
    fs::write(
        p.with_extension("rappend"),
        (committed.len() as u64).to_le_bytes(),
    )
    .unwrap();
    let (first, last) = edges(t.path()).unwrap().unwrap();
    assert_eq!((first.id.as_str(), last.id.as_str()), ("first", "last"));
    assert_eq!(fs::read(&p).unwrap(), committed.as_bytes());
    assert!(!p.with_extension("rappend").exists());
}
