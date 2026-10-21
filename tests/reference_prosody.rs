//! Real upstream implementation oracle. Requires a built exact Prosody source and Lua 5.4.
use rust_xmpp::{
    archive, auth,
    storage::{self, LuaValue as V},
};
use std::{path::Path, process::Command};
fn oracle(root: &Path, phase: &str, hash: &str) {
    let src = std::env::var("PROSODY_REFERENCE_SOURCE")
        .expect("set PROSODY_REFERENCE_SOURCE to built source");
    let lua = std::env::var("PROSODY_REFERENCE_LUA").unwrap_or_else(|_| "lua5.4".into());
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/prosody_compat/oracle.lua");
    let output = Command::new(lua)
        .args([
            script.to_str().unwrap(),
            &src,
            root.to_str().unwrap(),
            phase,
            hash,
        ])
        .output()
        .expect("run actual Lua interpreter");
    assert!(
        output.status.success(),
        "native Prosody oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
#[test]
#[ignore = "requires native supplied Prosody source; run scripts/prosody_compat/verify.sh"]
fn real_prosody_storage_and_auth_roundtrip() {
    for hash in ["SHA-1", "SHA-256"] {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        let host = "example.org";
        let mut v = V::default();
        v.set_key(V::Bool(false), "roster".into());
        v.set_key(V::Integer(3), "sparse".into());
        v.set("binary", V::String(vec![0, 1, 10, 255]));
        v.set("text", "Привет & <xml>".into());
        storage::save(root, host, Some("alice"), "oracle", &v).unwrap();
        let mut prefs = V::default();
        prefs.set_key(V::Bool(false), "roster".into());
        storage::save(root, host, Some("alice"), "archive_prefs", &prefs).unwrap();
        auth::create(root, host, "alice", "пароль-Original", hash).unwrap();
        for (i, id) in ["rust-one", "rust-two"].iter().enumerate() {
            archive::append_new(root,host,Some("alice"),"archive",archive::Entry{id:id.to_string(),when:1767225600.+i as f64,peer:"bob@example.org".into(),xml:"<message xmlns='jabber:client' xml:lang='ru' xmlns:o='urn:oracle' o:flag='yes'><body>Rust body</body></message>".into()}).unwrap();
        }
        // Transfer write ownership only after durable native checkpoint.
        archive::checkpoint_all(root).unwrap();
        oracle(root, "roundtrip", hash);
        let v = storage::load(root, host, Some("alice"), "oracle")
            .unwrap()
            .unwrap();
        assert_eq!(v.get("binary"), Some(&V::String(vec![0, 1, 10, 255])));
        assert_eq!(
            v.get("native").unwrap().get("number"),
            Some(&V::Number(1.25))
        );
        let prefs = storage::load(root, host, Some("alice"), "archive_prefs")
            .unwrap()
            .unwrap();
        assert_eq!(prefs.get_key(&V::Bool(false)), Some(&V::Bool(false)));
        assert!(auth::verify(root, host, "alice", "пароль-Native", hash).unwrap());
        assert!(!auth::verify(root, host, "alice", "пароль-Original", hash).unwrap());
        assert!(auth::verify(root, host, "bob", "native-bob", hash).unwrap());
        assert!(auth::verify(root, host, "binary", "binary-password", hash).unwrap());
        let p = storage::path(root, host, Some("alice"), "archive").with_extension("lidx");
        assert!(p.exists(), "original Prosody must create real binary index");
        let rows = archive::load(root, host, "alice").unwrap();
        assert_eq!(
            rows.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
            vec!["rust-one", "native-three", "rust-two"]
        );
        let native = roxmltree::Document::parse(&rows[1].xml).unwrap();
        assert_eq!(
            native.root_element().attribute(("urn:oracle", "flag")),
            Some("native")
        );
        assert!(rows[2].xml.contains("Replaced by native"));
        storage::update(root, host, Some("alice"), "oracle", |v| {
            v.set("rust_final", V::Bool(true));
            Ok(())
        })
        .unwrap();
        auth::set_password(root, host, "bob", "rust-bob-new", hash).unwrap();
        archive::append_new(
            root,
            host,
            Some("alice"),
            "archive",
            archive::Entry {
                id: "rust-final".into(),
                when: 1767225604.,
                peer: "bob@example.org".into(),
                xml: "<message xmlns='jabber:client'><body>Final</body></message>".into(),
            },
        )
        .unwrap();
        assert!(!p.exists());
        archive::checkpoint_all(root).unwrap();
        oracle(root, "verify-final", hash);
    }
}
