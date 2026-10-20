use rust_xmpp::{muc::Muc, protocol::ModuleResult};
use serde_json::json;
fn send(m: &mut Muc, who: &str, packet: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(packet).unwrap();
    m.handle(who, doc.root_element()).unwrap().unwrap()
}
fn join(m: &mut Muc, who: &str, nick: &str) -> ModuleResult {
    send(
        m,
        who,
        &format!(
            "<presence to='r@rooms.test/{nick}'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    )
}
#[test]
fn probes_and_invalid_presence_cannot_join_or_rename() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = Muc::new(dir.path().into(), "rooms.test".into());
    m.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    assert!(
        send(
            &mut m,
            "alice@test/r",
            "<presence to='r@rooms.test/Alice'/>"
        )
        .replies[0]
            .contains("item-not-found")
    );
    join(&mut m, "alice@test/r", "Alice");
    assert!(
        send(
            &mut m,
            "bob@test/r",
            "<presence type='probe' to='r@rooms.test/Alice'/>"
        )
        .replies[0]
            .contains("not-acceptable")
    );
    assert!(
        send(
            &mut m,
            "bob@test/r",
            "<presence type='subscribe' to='r@rooms.test/Bob'/>"
        )
        .replies[0]
            .contains("bad-request")
    );
    let probe = send(
        &mut m,
        "alice@test/r",
        "<presence type='probe' to='r@rooms.test/Alice'/>",
    );
    assert!(probe.replies[0].contains("role='moderator'"));
    assert!(probe.deliveries.is_empty());
    assert!(
        send(
            &mut m,
            "alice@test/r",
            "<presence type='probe' to='r@rooms.test/Absent'/>"
        )
        .replies
        .is_empty()
    );
}
#[test]
fn error_messages_kick_only_on_delivery_failure_and_presence_errors_kick() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = Muc::new(dir.path().into(), "rooms.test".into());
    m.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    join(&mut m, "alice@test/r", "Alice");
    join(&mut m, "bob@test/r", "Bob");
    let denied = send(
        &mut m,
        "bob@test/r",
        "<message type='error' to='r@rooms.test'><error><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
    );
    assert!(denied.replies.is_empty() && denied.deliveries.is_empty());
    let forwarded = send(
        &mut m,
        "bob@test/r",
        "<message type='error' to='r@rooms.test/Alice'><error><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
    );
    assert_eq!(forwarded.deliveries.len(), 1);
    assert!(forwarded.deliveries[0].1.contains("type='error'"));
    let kicked = send(
        &mut m,
        "bob@test/r",
        "<message type='error' to='r@rooms.test/Alice'><error><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
    );
    assert!(
        kicked
            .deliveries
            .iter()
            .any(|(_, p)| p.contains("code='333'") && p.contains("Kicked: service unavailable"))
    );
    join(&mut m, "bob@test/r", "Bob");
    let kicked = send(
        &mut m,
        "bob@test/r",
        "<presence type='error' to='r@rooms.test/Bob'><error><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>",
    );
    assert!(
        kicked
            .deliveries
            .iter()
            .any(|(_, p)| p.contains("code='333'"))
    );
}
#[test]
fn room_creation_policies_apply_only_to_new_rooms() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = Muc::new(dir.path().into(), "rooms.test".into());
    m.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    m.set_local_domain("test".into());
    m.set_component_options(json!({"muc_room_locking":false,"restrict_room_creation":true,"admins":["admin@test"],"muc_max_rooms":1}), false);
    assert!(join(&mut m, "alice@test/r", "Alice").replies[0].contains("not-allowed"));
    assert!(
        join(&mut m, "admin@test/r", "Admin")
            .replies
            .iter()
            .any(|p| p.contains("code='201'"))
    );
    assert!(
        join(&mut m, "alice@remote/r", "Alice")
            .replies
            .iter()
            .any(|p| p.contains("code='110'"))
    );
    let full = send(
        &mut m,
        "admin@test/r",
        "<presence to='s@rooms.test/Admin'><x xmlns='http://jabber.org/protocol/muc'/></presence>",
    );
    assert!(full.replies[0].contains("resource-constraint"));
    m.set_component_options(json!({"restrict_room_creation":"local"}), false);
    assert!(send(&mut m, "alice@remote/r", "<presence to='s@rooms.test/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>").replies[0].contains("not-allowed"));
    m.set_component_options(json!({}), false);
    assert!(send(&mut m, "alice@remote/r", "<presence to='s@rooms.test/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>").replies.iter().any(|p|p.contains("code='201'")));
}
#[test]
fn ordinary_presence_extensions_survive_but_client_identity_is_filtered() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = Muc::new(dir.path().into(), "rooms.test".into());
    m.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    join(&mut m, "alice@test/r", "Alice");
    let result = send(
        &mut m,
        "bob@test/r",
        "<presence to='r@rooms.test/Bob'><x xmlns='http://jabber.org/protocol/muc'/><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='client' ver='v'/><idle xmlns='urn:xmpp:idle:1' since='2026-01-01T00:00:00Z'/><occupant-id xmlns='urn:xmpp:occupant-id:0' id='forged'/></presence>",
    );
    let p = &result.deliveries[0].1;
    assert!(p.contains("http://jabber.org/protocol/caps") && p.contains("urn:xmpp:idle:1"));
    assert!(!p.contains("forged"));
}

#[test]
fn subject_with_body_remains_an_ordinary_groupchat_message() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = Muc::new(dir.path().into(), "rooms.test".into());
    m.set_component_options(json!({"muc_room_locking":false}), false);
    join(&mut m, "alice@test/r", "Alice");
    join(&mut m, "bob@test/r", "Bob");
    let ordinary = send(
        &mut m,
        "bob@test/r",
        "<message type='groupchat' to='r@rooms.test'><subject>Heading</subject><body>Message text</body></message>",
    );
    assert!(ordinary.replies.is_empty());
    assert_eq!(ordinary.deliveries.len(), 2);
    let subject = send(
        &mut m,
        "bob@test/r",
        "<message type='groupchat' to='r@rooms.test'><subject>Room title</subject></message>",
    );
    assert!(subject.replies[0].contains("forbidden"));
}
