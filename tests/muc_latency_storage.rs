use rust_xmpp::{archive, muc::Muc, protocol::ModuleResult, storage};
use std::{fs, path::Path, time::SystemTime};

fn send(muc: &mut Muc, xml: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(xml).unwrap();
    muc.handle("alice@test/a", doc.root_element())
        .unwrap()
        .unwrap()
}

fn room(muc: &mut Muc, name: &str) {
    send(
        muc,
        &format!(
            "<presence to='{name}@rooms.test/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    send(
        muc,
        &format!(
            "<iq type='set' to='{name}@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'/></query></iq>"
        ),
    );
}

fn chat(muc: &mut Muc) -> ModuleResult {
    send(
        muc,
        "<message to='r@rooms.test' type='groupchat'><body>Fresh</body></message>",
    )
}

fn mark(path: &Path) -> SystemTime {
    let marker = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(marker))
        .unwrap();
    fs::metadata(path).unwrap().modified().unwrap()
}

#[test]
fn groupchat_skips_native_rewrites_and_archive_retention_scan() {
    let temp = tempfile::tempdir().unwrap();
    let mut muc = Muc::new(temp.path().into(), "rooms.test".into());
    muc.set_defaults(serde_json::json!({"persistent":true,"archiving":true}));
    muc.set_archive_retention(Some(60.0));
    room(&mut muc, "r");
    room(&mut muc, "other");

    let config = storage::path(temp.path(), "rooms.test", Some("r"), "config");
    let other = storage::path(temp.path(), "rooms.test", Some("other"), "config");
    let index = storage::path(temp.path(), "rooms.test", None, "persistent");
    let journal = storage::path(temp.path(), "rooms.test", None, "rust_muc_checkpoint");
    let config_time = mark(&config);
    let other_time = mark(&other);
    let index_time = mark(&index);
    let journal_time = mark(&journal);

    // An unreadable historic record makes any accidental full archive scan fail.
    // Appending a fresh record needs only the existing file length, never its XML.
    let log = storage::path(temp.path(), "rooms.test", Some("r"), "muc_log").with_extension("list");
    fs::create_dir_all(log.parent().unwrap()).unwrap();
    let historic = b"item(this is intentionally invalid historic archive data);\n";
    fs::write(&log, historic).unwrap();
    let delivered = chat(&mut muc);
    assert_eq!(delivered.deliveries.len(), 1);
    let contents = fs::read(&log).unwrap();
    assert!(contents.starts_with(historic));
    assert!(contents.len() > historic.len());
    assert!(archive::load_store(temp.path(), "rooms.test", Some("r"), "muc_log").is_err());
    for (path, before) in [
        (&config, config_time),
        (&other, other_time),
        (&index, index_time),
    ] {
        assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), before);
    }
    assert_ne!(
        fs::metadata(&journal).unwrap().modified().unwrap(),
        journal_time
    );
    assert!(fs::read_to_string(journal).unwrap().contains("Fresh"));
}

#[test]
fn native_exports_repair_missing_files_and_export_changed_config() {
    let temp = tempfile::tempdir().unwrap();
    let mut muc = Muc::new(temp.path().into(), "rooms.test".into());
    muc.set_defaults(serde_json::json!({"persistent":true}));
    room(&mut muc, "r");
    room(&mut muc, "other");
    let config = storage::path(temp.path(), "rooms.test", Some("r"), "config");
    let other = storage::path(temp.path(), "rooms.test", Some("other"), "config");
    let index = storage::path(temp.path(), "rooms.test", None, "persistent");
    let original = fs::read(&config).unwrap();
    fs::remove_file(&config).unwrap();
    fs::remove_file(&index).unwrap();
    assert_eq!(chat(&mut muc).deliveries.len(), 1);
    assert_eq!(fs::read(&config).unwrap(), original);
    let recovered = storage::load(temp.path(), "rooms.test", None, "persistent")
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.get("r@rooms.test"),
        Some(&storage::LuaValue::Bool(true))
    );
    assert_eq!(
        recovered.get("other@rooms.test"),
        Some(&storage::LuaValue::Bool(true))
    );
    let other_time = mark(&other);
    let index_time = mark(&index);
    let result = send(
        &mut muc,
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='muc#roomconfig_roomname'><value>Updated</value></field></x></query></iq>",
    );
    assert!(result.replies[0].contains("result"));
    assert!(fs::read_to_string(config).unwrap().contains("Updated"));
    assert_eq!(fs::metadata(other).unwrap().modified().unwrap(), other_time);
    assert_eq!(
        fs::metadata(&index).unwrap().modified().unwrap(),
        index_time
    );

    // Export failures are nonfatal after the authoritative room commit, and
    // exports must be retried even if no configuration changed since failure.
    fs::remove_file(&index).unwrap();
    fs::create_dir(&index).unwrap();
    assert_eq!(chat(&mut muc).deliveries.len(), 1);
    fs::remove_dir(&index).unwrap();
    assert_eq!(chat(&mut muc).deliveries.len(), 1);
    let recovered = storage::load(temp.path(), "rooms.test", None, "persistent")
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered.get("r@rooms.test"),
        Some(&storage::LuaValue::Bool(true))
    );
    assert_eq!(
        recovered.get("other@rooms.test"),
        Some(&storage::LuaValue::Bool(true))
    );
}
