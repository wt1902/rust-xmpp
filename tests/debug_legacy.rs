#[test]
fn debug_empty_legacy_bind() {
    let t = tempfile::tempdir().unwrap();
    rust_xmpp::auth::create(t.path(), "localhost", "alice", "secret", "SHA-256").unwrap();
    eprintln!("before legacy");
    let r =
        rust_xmpp::account_modules::legacy_on_bind(t.path(), "localhost", "alice@localhost/main")
            .unwrap();
    eprintln!("after legacy {} {}", r.replies.len(), r.deliveries.len());
    let d = roxmltree::Document::parse("<presence xmlns='jabber:client'/>").unwrap();
    eprintln!("before avatar");
    let _ = rust_xmpp::account_modules::avatar_presence(
        t.path(),
        "localhost",
        "alice@localhost/main",
        d.root_element(),
    )
    .unwrap();
    eprintln!("after avatar");
}
