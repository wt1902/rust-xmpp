use rust_xmpp::muc_recovery::{self as recovery, OccupantSnapshot, PendingOccupants};

fn occupant() -> OccupantSnapshot {
    OccupantSnapshot { jid: "alice@test/phone".into(), nick: "Alice".into(), role: "participant".into(), presence_payload: "<show>away</show><status>hi &amp; bye</status><x xmlns='http://jabber.org/protocol/muc'><password>secret</password></x>".into() }
}

#[test]
fn native_checkpoint_roundtrip_filters_sensitive_extensions() {
    let dir = tempfile::tempdir().unwrap();
    recovery::save_room_checkpoint(
        dir.path(),
        "rooms.test",
        "r@rooms.test",
        &[occupant()],
        Some(&"a".repeat(64)),
        100,
    )
    .unwrap();
    let occupants = recovery::load_room(dir.path(), "rooms.test", "r@rooms.test").unwrap();
    assert_eq!(occupants.len(), 1);
    assert_eq!(occupants[0].jid, "alice@test/phone");
    let wrapped = format!("<presence>{}</presence>", occupants[0].presence_payload);
    let parsed = roxmltree::Document::parse(&wrapped).unwrap();
    let fields = parsed
        .root_element()
        .children()
        .filter(|node| node.is_element())
        .map(|node| (node.tag_name().name(), node.text().unwrap_or("")))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields.get("show"), Some(&"away"));
    assert_eq!(fields.get("status"), Some(&"hi & bye"));
    assert!(
        parsed
            .descendants()
            .filter(|node| node.is_element())
            .all(|node| matches!(node.tag_name().name(), "presence" | "show" | "status"))
    );
    assert_eq!(
        recovery::load_checkpoint_time(dir.path(), "rooms.test", "r@rooms.test").unwrap(),
        Some(100)
    );
    let raw = std::fs::read_to_string(rust_xmpp::storage::path(
        dir.path(),
        "rooms.test",
        Some("r"),
        "state",
    ))
    .unwrap();
    assert!(!raw.contains("secret"));
    assert!(!raw.contains("password"));
}

#[test]
fn recovery_claim_requires_exact_authenticated_resource_and_expires() {
    let mut pending = PendingOccupants::default();
    pending
        .insert_checkpoint("r@rooms.test".into(), vec![occupant()], 100, 200)
        .unwrap();
    assert!(pending.candidates("alice@test/other", 200).is_empty());
    assert!(
        pending
            .claim("r@rooms.test", "mallory@test/phone", "Alice", 200)
            .is_none()
    );
    assert_eq!(pending.candidates("alice@test/phone", 200).len(), 1);
    assert_eq!(pending.expire(400), 1);
    assert!(
        pending
            .claim("r@rooms.test", "alice@test/phone", "Alice", 400)
            .is_none()
    );
    pending
        .insert_checkpoint("r@rooms.test".into(), vec![occupant()], 100, 401)
        .unwrap();
    assert!(pending.is_empty());
}

#[test]
fn claim_is_one_time_and_does_not_change_untrusted_role() {
    let mut pending = PendingOccupants::default();
    pending
        .insert("r@rooms.test".into(), vec![occupant()], 100)
        .unwrap();
    assert!(
        pending
            .claim("r@rooms.test", "alice@test/phone", "Wrong", 101)
            .is_none()
    );
    assert!(
        pending
            .claim("r@rooms.test", "alice@test/phone", "Alice", 101)
            .is_some()
    );
    assert!(
        pending
            .claim("r@rooms.test", "alice@test/phone", "Alice", 101)
            .is_none()
    );
}

#[test]
fn native_last_message_roundtrip_preserves_namespaces_and_rejects_other_rooms() {
    let dir = tempfile::tempdir().unwrap();
    let packet = "<message xmlns='jabber:client' type='groupchat' from='r@rooms.test/Alice'><body>hello</body><delay xmlns='urn:xmpp:delay' stamp='2026-01-01T00:00:00Z'/></message>";
    recovery::set_last_message(
        dir.path(),
        "rooms.test",
        "r@rooms.test",
        Some((packet, 100)),
    )
    .unwrap();
    let (saved, at) = recovery::load_last_message(dir.path(), "rooms.test", "r@rooms.test")
        .unwrap()
        .unwrap();
    assert_eq!(at, 100);
    let doc = roxmltree::Document::parse(&saved).unwrap();
    assert_eq!(
        doc.root_element().tag_name().namespace(),
        Some("jabber:client")
    );
    assert!(
        doc.descendants()
            .any(|n| n.is_element() && n.tag_name().namespace() == Some("urn:xmpp:delay"))
    );
    assert!(
        recovery::set_last_message(
            dir.path(),
            "rooms.test",
            "other@rooms.test",
            Some((packet, 100))
        )
        .is_err()
    );
    recovery::set_last_message(dir.path(), "rooms.test", "r@rooms.test", None).unwrap();
    assert!(
        recovery::load_last_message(dir.path(), "rooms.test", "r@rooms.test")
            .unwrap()
            .is_none()
    );
}

#[test]
fn pending_snapshot_keeps_original_checkpoint_time() {
    let mut pending = PendingOccupants::default();
    pending
        .insert_checkpoint("r@rooms.test".into(), vec![occupant()], 100, 200)
        .unwrap();
    let (saved_at, occupants) = pending.room_snapshot("r@rooms.test", 300).unwrap();
    assert_eq!(saved_at, 100);
    let mut restarted = PendingOccupants::default();
    restarted
        .insert_checkpoint("r@rooms.test".into(), occupants, saved_at, 350)
        .unwrap();
    assert!(restarted.room_snapshot("r@rooms.test", 400).is_none());
}

#[test]
fn oversized_status_never_prevents_membership_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    for length in [4096, 256 * 1024] {
        let mut original = occupant();
        original.presence_payload = format!("<status>{}</status>", "x".repeat(length));
        recovery::save_room_checkpoint(
            dir.path(),
            "rooms.test",
            "r@rooms.test",
            &[original.clone()],
            None,
            100,
        )
        .unwrap();
        let restored = recovery::load_room(dir.path(), "rooms.test", "r@rooms.test").unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].jid, original.jid);
        assert_eq!(restored[0].nick, original.nick);
        assert_eq!(restored[0].role, original.role);
        assert!(restored[0].presence_payload.is_empty());
    }
}

#[test]
fn configuration_fingerprint_is_independent_of_lua_table_iteration_order() {
    use rust_xmpp::storage::{self, LuaValue as V};
    let a = storage::parse(
        b"return {a=1,_data={password='hidden',nested={x=true,y='value'}},owner='owner'}",
    )
    .unwrap();
    let b = storage::parse(
        b"return {owner='owner',_data={nested={y='value',x=true},password='hidden'},a=1}",
    )
    .unwrap();
    let expected = rust_xmpp::muc_recovery::configuration_fingerprint(&a).unwrap();
    assert_eq!(
        expected,
        rust_xmpp::muc_recovery::configuration_fingerprint(&b).unwrap()
    );
    for _ in 0..32 {
        let value = storage::parse(storage::serialize(&a).unwrap().as_bytes()).unwrap();
        assert_eq!(
            expected,
            rust_xmpp::muc_recovery::configuration_fingerprint(&value).unwrap()
        );
    }
    let mut changed = b;
    changed.set("owner", V::from("outcast"));
    assert_ne!(
        expected,
        rust_xmpp::muc_recovery::configuration_fingerprint(&changed).unwrap()
    );
}
