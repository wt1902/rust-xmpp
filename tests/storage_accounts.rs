use rust_xmpp::{
    account_modules as a,
    storage::{self, LuaValue as V},
};
fn iq(root: &std::path::Path, s: &str) -> rust_xmpp::protocol::ModuleResult {
    let d = roxmltree::Document::parse(s).unwrap();
    a::handle(
        root,
        "example.test",
        "alice@example.test/r",
        d.root_element(),
    )
    .unwrap()
    .unwrap()
}
#[test]
fn private_and_vcard_authorization() {
    let t = tempfile::tempdir().unwrap();
    let r = iq(
        t.path(),
        "<iq type='set' id='1' to='bob@example.test'><query xmlns='jabber:iq:private'><x xmlns='test'>secret</x></query></iq>",
    );
    assert!(r.replies[0].contains("forbidden"));
    assert!(!t.path().join("example%2etest").exists());
    let r = iq(
        t.path(),
        "<iq type='set' id='1'><query xmlns='jabber:iq:private'><x xmlns='test'>secret</x></query></iq>",
    );
    assert!(r.replies[0].contains("result"));
    let r = iq(
        t.path(),
        "<iq type='get' id='2'><query xmlns='jabber:iq:private'><x xmlns='test'/></query></iq>",
    );
    assert!(r.replies[0].contains("secret"));
    let r = iq(
        t.path(),
        "<iq type='set' id='1' to='bob@example.test'><vCard xmlns='vcard-temp'><FN>Alice</FN></vCard></iq>",
    );
    assert!(r.replies[0].contains("forbidden"));
}
#[test]
fn roster_preserves_subscription_and_metadata() {
    let t = tempfile::tempdir().unwrap();
    let v=storage::parse(b"return { [false]={version=9;pending={['foo@example.test']=true}};['bob@example.test']={subscription='both';ask='subscribe';groups={Old=true}}}").unwrap();
    storage::save(t.path(), "example.test", Some("alice"), "roster", &v).unwrap();
    let r = iq(
        t.path(),
        "<iq type='set' id='1'><query xmlns='jabber:iq:roster'><item jid='bob@example.test' subscription='none' name='Bob'><group>New</group></item></query></iq>",
    );
    assert_eq!(r.deliveries.len(), 1);
    let v = storage::load(t.path(), "example.test", Some("alice"), "roster")
        .unwrap()
        .unwrap();
    assert_eq!(
        v.get("bob@example.test")
            .unwrap()
            .get("subscription")
            .and_then(V::as_str),
        Some("both")
    );
    assert_eq!(
        v.get_key(&V::Bool(false)).unwrap().get("version"),
        Some(&V::Integer(10))
    );
    assert!(v.get_key(&V::Bool(false)).unwrap().get("pending").is_some());
    let r = iq(
        t.path(),
        "<iq type='get' id='1'><query xmlns='jabber:iq:roster' ver='10'/></iq>",
    );
    assert!(!r.replies[0].contains("<query"));
}
#[test]
fn blocklist_enforcement_api() {
    let t = tempfile::tempdir().unwrap();
    iq(
        t.path(),
        "<iq type='set' id='1'><block xmlns='urn:xmpp:blocking'><item jid='bob@example.test'/></block></iq>",
    );
    assert!(a::is_blocked(t.path(), "example.test", "alice", "bob@example.test/device").unwrap());
    assert!(!a::is_blocked(t.path(), "example.test", "alice", "carol@example.test").unwrap());
    iq(
        t.path(),
        "<iq type='set' id='2'><unblock xmlns='urn:xmpp:blocking'/></iq>",
    );
    assert!(!a::is_blocked(t.path(), "example.test", "alice", "bob@example.test").unwrap());
}
#[test]
fn subscription_handshake_and_cancel() {
    let t = tempfile::tempdir().unwrap();
    for u in ["alice", "bob"] {
        let mut v = V::table();
        v.set("test", V::Bool(true));
        storage::save(t.path(), "example.test", Some(u), "accounts", &v).unwrap();
    }
    let p =
        roxmltree::Document::parse("<presence type='subscribe' to='bob@example.test'/>").unwrap();
    a::subscription(
        t.path(),
        "example.test",
        "alice@example.test/r",
        p.root_element(),
    )
    .unwrap();
    assert_eq!(
        a::pending_subscriptions(t.path(), "example.test", "bob")
            .unwrap()
            .len(),
        1
    );
    let p = roxmltree::Document::parse("<presence type='subscribed' to='alice@example.test'/>")
        .unwrap();
    a::subscription(
        t.path(),
        "example.test",
        "bob@example.test/r",
        p.root_element(),
    )
    .unwrap();
    assert_eq!(
        a::subscriptions(t.path(), "example.test", "alice").unwrap(),
        vec!["bob@example.test"]
    );
    assert_eq!(
        a::subscribers(t.path(), "example.test", "bob").unwrap(),
        vec!["alice@example.test"]
    );
    assert!(
        a::pending_subscriptions(t.path(), "example.test", "bob")
            .unwrap()
            .is_empty()
    );
    let p =
        roxmltree::Document::parse("<presence type='unsubscribe' to='bob@example.test'/>").unwrap();
    a::subscription(
        t.path(),
        "example.test",
        "alice@example.test/r",
        p.root_element(),
    )
    .unwrap();
    assert!(
        a::subscriptions(t.path(), "example.test", "alice")
            .unwrap()
            .is_empty()
    );
    assert!(
        a::subscribers(t.path(), "example.test", "bob")
            .unwrap()
            .is_empty()
    );
}
#[test]
fn reads_timestamp_blocklist_and_keeps_metadata() {
    let t = tempfile::tempdir().unwrap();
    let v =
        storage::parse(b"return {[false]={created=42};['bob@example.test']=1729000000}").unwrap();
    storage::save(t.path(), "example.test", Some("alice"), "blocklist", &v).unwrap();
    assert!(a::is_blocked(t.path(), "example.test", "alice", "bob@example.test/r").unwrap());
    let r = iq(
        t.path(),
        "<iq type='get' id='1'><blocklist xmlns='urn:xmpp:blocking'/></iq>",
    );
    assert!(r.replies[0].contains("bob@example.test"));
    iq(
        t.path(),
        "<iq type='set' id='2'><unblock xmlns='urn:xmpp:blocking'/></iq>",
    );
    let v = storage::load(t.path(), "example.test", Some("alice"), "blocklist")
        .unwrap()
        .unwrap();
    assert_eq!(
        v.get_key(&V::Bool(false)).unwrap().get("created"),
        Some(&V::Integer(42))
    );
}
fn legacy(root: &std::path::Path, jid: &str, s: &str) -> rust_xmpp::protocol::ModuleResult {
    let user = jid.split('@').next().unwrap();
    if storage::load(root, "example.test", Some(user), "accounts")
        .unwrap()
        .is_none()
    {
        let mut v = V::table();
        v.set("test", V::Bool(true));
        storage::save(root, "example.test", Some(user), "accounts", &v).unwrap();
    }
    let d = roxmltree::Document::parse(s).unwrap();
    a::handle_legacy(root, "example.test", jid, d.root_element())
        .unwrap()
        .unwrap()
}
#[test]
fn vcard_pep_conversion_and_avatar() {
    let t = tempfile::tempdir().unwrap();
    let r = legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='set' id='v'><vCard xmlns='vcard-temp'><FN>Alice</FN><N><FAMILY>Test</FAMILY></N><EMAIL><USERID>a@example.test</USERID><HOME/></EMAIL><PHOTO><TYPE>image/png</TYPE><BINVAL>aGVsbG8=</BINVAL></PHOTO></vCard></iq>",
    );
    assert!(r.replies[0].contains("result"));
    let r = legacy(
        t.path(),
        "bob@example.test/r",
        "<iq type='get' id='v' to='alice@example.test'><vCard xmlns='vcard-temp'/></iq>",
    );
    assert!(r.replies[0].contains("Alice"));
    assert!(r.replies[0].contains("aGVsbG8="));
    let r = legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='get' id='v'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'/></iq>",
    );
    assert!(r.replies[0].contains("surname"));
    let p = roxmltree::Document::parse("<presence xmlns='jabber:client'/>").unwrap();
    let s = a::avatar_presence(
        t.path(),
        "example.test",
        "alice@example.test/r",
        p.root_element(),
    )
    .unwrap();
    assert!(s.contains("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"));
}
#[test]
fn bookmarks_private_pep_bidirectional_and_private() {
    let t = tempfile::tempdir().unwrap();
    let r = legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='set' id='b'><query xmlns='jabber:iq:private'><storage xmlns='storage:bookmarks'><conference jid='room@conference.example.test' name='Room' autojoin='true'><nick>Alice</nick><password>secret</password></conference></storage></query></iq>",
    );
    assert!(r.replies[0].contains("result"));
    let r = legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='get' id='b'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='storage:bookmarks'/></pubsub></iq>",
    );
    assert!(r.replies[0].contains("secret"));
    let d=roxmltree::Document::parse("<iq type='get' id='x' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:bookmarks:1'/></pubsub></iq>").unwrap();
    let r = rust_xmpp::pubsub::handle(
        t.path(),
        "example.test",
        "bob@example.test/r",
        d.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(r.replies[0].contains("forbidden"));
    legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='set' id='b'><query xmlns='jabber:iq:private'><storage xmlns='storage:bookmarks'/></query></iq>",
    );
    let r = legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='get' id='b'><query xmlns='jabber:iq:private'><storage xmlns='storage:bookmarks'/></query></iq>",
    );
    assert!(!r.replies[0].contains("room@"));
}
#[test]
fn inbound_subscription_requires_pending_to_grant_to() {
    let t = tempfile::tempdir().unwrap();
    let mut v = V::table();
    v.set("test", V::Bool(true));
    storage::save(t.path(), "example.test", Some("alice"), "accounts", &v).unwrap();
    let d = roxmltree::Document::parse("<presence type='subscribed' to='alice@example.test'/>")
        .unwrap();
    a::inbound_subscription(
        t.path(),
        "example.test",
        "evil@other.test",
        d.root_element(),
    )
    .unwrap();
    assert!(
        a::subscriptions(t.path(), "example.test", "alice")
            .unwrap()
            .is_empty()
    );
}
#[test]
fn legacy_migration_clears_source_after_success() {
    let t = tempfile::tempdir().unwrap();
    let mut account = V::table();
    account.set("test", V::Bool(true));
    storage::save(
        t.path(),
        "example.test",
        Some("alice"),
        "accounts",
        &account,
    )
    .unwrap();
    let d =
        roxmltree::Document::parse("<vCard xmlns='vcard-temp'><FN>Old Alice</FN></vCard>").unwrap();
    storage::save(
        t.path(),
        "example.test",
        Some("alice"),
        "vcard",
        &storage::stanza_value(d.root_element()),
    )
    .unwrap();
    let d=roxmltree::Document::parse("<storage xmlns='storage:bookmarks'><conference jid='room@conference.example.test'/></storage>").unwrap();
    let mut private = V::table();
    private.set(
        "storage:storage:bookmarks",
        storage::stanza_value(d.root_element()),
    );
    private.set("unrelated", "keep".into());
    storage::save(t.path(), "example.test", Some("alice"), "private", &private).unwrap();
    a::legacy_on_bind(t.path(), "example.test", "alice@example.test/r").unwrap();
    assert!(
        storage::load(t.path(), "example.test", Some("alice"), "vcard")
            .unwrap()
            .is_none()
    );
    let v = storage::load(t.path(), "example.test", Some("alice"), "private")
        .unwrap()
        .unwrap();
    assert!(v.get("storage:storage:bookmarks").is_none());
    assert_eq!(v.get("unrelated").and_then(V::as_str), Some("keep"));
    a::legacy_on_bind(t.path(), "example.test", "alice@example.test/r").unwrap();
    let r = legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='get' id='v'><vCard xmlns='vcard-temp'/></iq>",
    );
    assert!(r.replies[0].contains("Old Alice"));
}
#[test]
fn domain_roster_and_block_jid_normalization() {
    let t = tempfile::tempdir().unwrap();
    let r = iq(
        t.path(),
        "<iq type='set' id='r'><query xmlns='jabber:iq:roster'><item jid='Transport.EXAMPLE.test' name='Transport'/></query></iq>",
    );
    assert!(r.replies[0].contains("result"));
    let d = storage::load(t.path(), "example.test", Some("alice"), "roster")
        .unwrap()
        .unwrap();
    assert!(d.get("transport.example.test").is_some());
    let r = iq(
        t.path(),
        "<iq type='set' id='b'><block xmlns='urn:xmpp:blocking'><item jid='BOB@EXAMPLE.TEST/Phone'/></block></iq>",
    );
    assert!(a::is_blocked(t.path(), "example.test", "alice", "bob@example.test/Phone").unwrap());
    assert!(r.deliveries[0].1.contains("bob@example.test/Phone"));
}
#[test]
fn purge_account_exact_files_preserves_others_and_extras() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    for store in ["accounts", "roster", "pep_aabbcc", "custom_store"] {
        for user in ["alice", "bob"] {
            for ext in ["dat", "list", "lidx", "rappend"] {
                let p = storage::path(root, "example.test", Some(user), store).with_extension(ext);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, b"fixture").unwrap();
            }
        }
    }
    let extra =
        storage::path(root, "example.test", Some("alice"), "custom_store").with_extension("backup");
    std::fs::write(&extra, b"keep").unwrap();
    let hostwide = storage::path(root, "example.test", None, "hostwide");
    std::fs::write(&hostwide, b"keep").unwrap();
    a::remove_account(root, "example.test", "alice").unwrap();
    for store in ["accounts", "roster", "pep_aabbcc", "custom_store"] {
        for ext in ["dat", "list", "lidx", "rappend"] {
            assert!(
                !storage::path(root, "example.test", Some("alice"), store)
                    .with_extension(ext)
                    .exists()
            );
            assert!(
                storage::path(root, "example.test", Some("bob"), store)
                    .with_extension(ext)
                    .exists()
            );
        }
    }
    assert!(extra.exists());
    assert!(hostwide.exists());
    a::remove_account(root, "example.test", "alice").unwrap();
}
#[test]
fn privacy_migration_only_default_deny_jids() {
    let t = tempfile::tempdir().unwrap();
    let mut v = V::table();
    v.set("test", V::Bool(true));
    storage::save(t.path(), "example.test", Some("alice"), "accounts", &v).unwrap();
    let old=storage::parse(b"return {default='main';lists={main={items={{type='jid';action='deny';value='BOB@EXAMPLE.TEST'};{type='jid';action='allow';value='carol@example.test'};{type='group';action='deny';value='Friends'}}};other={items={{type='jid';action='deny';value='other@example.test'}}}}}").unwrap();
    storage::save(t.path(), "example.test", Some("alice"), "privacy", &old).unwrap();
    assert!(
        a::load_blocklist(t.path(), "example.test", "alice", false)
            .unwrap()
            .entries()
            .is_empty()
    );
    assert!(a::is_blocked(t.path(), "example.test", "alice", "bob@example.test/r").unwrap());
    assert!(!a::is_blocked(t.path(), "example.test", "alice", "carol@example.test").unwrap());
    assert!(!a::is_blocked(t.path(), "example.test", "alice", "other@example.test").unwrap());
    let b = a::load_blocklist(t.path(), "example.test", "alice", true).unwrap();
    assert_eq!(
        b.get_key(&V::Bool(false))
            .unwrap()
            .get("migrated")
            .and_then(V::as_str),
        Some("privacy")
    );
    assert!(
        storage::load(t.path(), "example.test", Some("alice"), "privacy")
            .unwrap()
            .is_some()
    );
}
#[cfg(unix)]
#[test]
fn account_purge_refuses_symlink_store_without_touching_other_files() {
    let t = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let mut v = V::table();
    v.set("test", V::Bool(true));
    storage::save(t.path(), "example.test", Some("alice"), "accounts", &v).unwrap();
    std::fs::write(other.path().join("alice.dat"), b"external").unwrap();
    std::os::unix::fs::symlink(other.path(), t.path().join("example%2etest/linked")).unwrap();
    assert!(a::remove_account(t.path(), "example.test", "alice").is_err());
    assert!(
        storage::load(t.path(), "example.test", Some("alice"), "accounts")
            .unwrap()
            .is_some()
    );
    assert!(other.path().join("alice.dat").exists());
}
#[test]
fn legacy_bookmarks_respect_host_limit_and_read_over_256() {
    let t = tempfile::tempdir().unwrap();
    a::set_legacy_pep_limit(t.path(), "example.test", 500).unwrap();
    legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='set' id='b'><query xmlns='jabber:iq:private'><storage xmlns='storage:bookmarks'><conference jid='seed@conference.example.test'/></storage></query></iq>",
    );
    let meta = storage::load(t.path(), "example.test", Some("alice"), "pep")
        .unwrap()
        .unwrap();
    assert_eq!(
        meta.get("urn:xmpp:bookmarks:1")
            .unwrap()
            .get("config")
            .unwrap()
            .get("max_items"),
        Some(&V::Integer(500))
    );
    let store = "pep_urn:xmpp:bookmarks:1";
    let entries = (0..300)
        .map(|i| rust_xmpp::archive::Entry {
            id: format!("room{i}@conference.example.test"),
            when: 1700000000.0 + i as f64,
            peer: "alice@example.test".into(),
            xml: "<conference xmlns='urn:xmpp:bookmarks:1'/>".into(),
        })
        .collect::<Vec<_>>();
    rust_xmpp::archive::save_store(t.path(), "example.test", Some("alice"), store, &entries)
        .unwrap();
    let s = a::legacy_bookmarks(t.path(), "example.test", "alice@example.test/r").unwrap();
    assert_eq!(s.matches("<conference ").count(), 300);
}
#[test]
fn malformed_roster_iq_never_mutates() {
    let t = tempfile::tempdir().unwrap();
    for xml in [
        "<iq type='set' id='x'><query xmlns='jabber:iq:roster'><item xmlns='evil' jid='bob@example.test'/></query></iq>",
        "<iq type='set' id='x'><query xmlns='jabber:iq:roster'><item jid='bob@example.test'/></query><extra/></iq>",
        "<iq type='set'><query xmlns='jabber:iq:roster'><item jid='bob@example.test'/></query></iq>",
    ] {
        assert!(iq(t.path(), xml).replies[0].contains("bad-request"));
    }
    assert!(
        storage::load(t.path(), "example.test", Some("alice"), "roster")
            .unwrap()
            .is_none()
    );
    let r = iq(
        t.path(),
        "<iq type='set' id='x'><query xmlns='jabber:iq:roster'><item jid='missing@example.test' subscription='remove'/></query></iq>",
    );
    assert!(r.replies[0].contains("item-not-found"));
    assert!(r.deliveries.is_empty());
}
#[test]
fn broken_roster_is_not_overwritten() {
    let t = tempfile::tempdir().unwrap();
    let p = storage::path(t.path(), "example.test", Some("alice"), "roster");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let data=b"return {[false]={broken='read-failed';version=7};['bob@example.test']={subscription='both';groups={}}}";
    std::fs::write(&p, data).unwrap();
    let r = iq(
        t.path(),
        "<iq type='set' id='x'><query xmlns='jabber:iq:roster'><item jid='carol@example.test'/></query></iq>",
    );
    assert!(r.replies[0].contains("internal-server-error"));
    assert_eq!(std::fs::read(&p).unwrap(), data);
    std::fs::write(&p, b"this is corrupt").unwrap();
    let r = iq(
        t.path(),
        "<iq type='get' id='x'><query xmlns='jabber:iq:roster'/></iq>",
    );
    assert!(r.replies[0].contains("internal-server-error"));
    assert_eq!(std::fs::read(&p).unwrap(), b"this is corrupt");
}
#[test]
fn roster_empty_name_and_foreign_group_ignored() {
    let t = tempfile::tempdir().unwrap();
    let r = iq(
        t.path(),
        "<iq type='get' id='x'><query xmlns='jabber:iq:roster'/></iq>",
    );
    assert!(r.replies[0].contains("ver='1'"));
    iq(
        t.path(),
        "<iq type='set' id='x'><query xmlns='jabber:iq:roster'><item jid='bob@example.test' name=''><group/><group xmlns='evil'>Hidden</group><group>Friends</group></item></query></iq>",
    );
    let v = storage::load(t.path(), "example.test", Some("alice"), "roster")
        .unwrap()
        .unwrap();
    let item = v.get("bob@example.test").unwrap();
    assert!(item.get("name").is_none());
    let groups = item.get("groups").unwrap();
    assert_eq!(groups.entries().len(), 1);
    assert!(groups.get("Friends").is_some());
}
#[test]
fn creation_and_purge_are_serialized() {
    use rust_xmpp::auth;
    use std::sync::{Arc, Barrier};
    for _ in 0..5 {
        let t = tempfile::tempdir().unwrap();
        auth::create(t.path(), "example.test", "alice", "old", "SHA-256").unwrap();
        let mut v = V::table();
        v.set("old", "private-data".into());
        storage::save(t.path(), "example.test", Some("alice"), "private", &v).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let b = barrier.clone();
            let p = t.path();
            let new = scope.spawn(move || {
                b.wait();
                auth::create(p, "example.test", "alice", "new", "SHA-256")
            });
            barrier.wait();
            a::remove_account(t.path(), "example.test", "alice").unwrap();
            let created = new.join().unwrap();
            assert!(
                storage::load(t.path(), "example.test", Some("alice"), "private")
                    .unwrap()
                    .is_none()
            );
            if created.is_ok() {
                assert!(auth::verify(t.path(), "example.test", "alice", "new", "SHA-256").unwrap());
            }
        });
    }
}
#[test]
fn password_change_after_purge_never_recreates_account() {
    use rust_xmpp::auth;
    let t = tempfile::tempdir().unwrap();
    auth::create(t.path(), "example.test", "alice", "old", "SHA-256").unwrap();
    a::remove_account(t.path(), "example.test", "alice").unwrap();
    assert!(auth::set_password(t.path(), "example.test", "alice", "new", "SHA-256").is_err());
    assert!(
        storage::load(t.path(), "example.test", Some("alice"), "accounts")
            .unwrap()
            .is_none()
    );
}
#[test]
fn malformed_legacy_vcard_and_private_bookmarks_rejected() {
    let t = tempfile::tempdir().unwrap();
    let r = legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='set' id='x'><wrong xmlns='vcard-temp'><FN>Bad</FN></wrong></iq>",
    );
    assert!(r.replies[0].contains("bad-request"));
    assert!(
        storage::load(t.path(), "example.test", Some("alice"), "pep")
            .unwrap()
            .is_none()
    );
    let r = legacy(
        t.path(),
        "alice@example.test/r",
        "<iq type='set' id='x'><query xmlns='jabber:iq:private'><storage xmlns='storage:bookmarks'/><other xmlns='other'/></query></iq>",
    );
    assert!(r.replies[0].contains("bad-request"));
    let r = iq(
        t.path(),
        "<iq type='set' id='b'><block xmlns='urn:xmpp:blocking'><item xmlns='evil' jid='bob@example.test'/></block></iq>",
    );
    assert!(r.replies[0].contains("bad-request"));
    assert!(!a::is_blocked(t.path(), "example.test", "alice", "bob@example.test").unwrap());
}
