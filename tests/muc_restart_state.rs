use rust_xmpp::{muc::Muc, protocol::ModuleResult, storage};
use serde_json::json;
const HOST: &str = "rooms.example.org";
const ROOM: &str = "live@rooms.example.org";
const ALICE: &str = "alice@example.org/laptop";
fn send(m: &mut Muc, jid: &str, packet: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(packet).unwrap();
    m.handle(jid, doc.root_element()).unwrap().unwrap()
}
fn initial(root: &std::path::Path) -> Muc {
    let mut m = Muc::new(root.into(), HOST.into());
    m.set_component_options(json!({"muc_room_locking":false}), false);
    m.set_defaults(json!({"persistent": true, "password":"private-pass"}));
    send(
        &mut m,
        ALICE,
        &format!(
            "<presence to='{ROOM}/Alice'><x xmlns='http://jabber.org/protocol/muc'><password>private-pass</password></x><status>saved status</status></presence>"
        ),
    );
    m
}
#[test]
fn repeated_restart_keeps_dormant_claim_and_deadline_without_ghost_routing() {
    let root = tempfile::tempdir().unwrap();
    let mut m = initial(root.path());
    m.checkpoint_live().unwrap();
    let before = rust_xmpp::muc_recovery::load_checkpoint_time(root.path(), HOST, ROOM).unwrap();
    drop(m);
    let mut m = Muc::new(root.path().into(), HOST.into());
    m.prepare_recovery().unwrap();
    assert!(
        m.restore_for_session("alice@example.org/phone")
            .unwrap()
            .replies
            .is_empty()
    );
    assert!(
        m.restore_for_session("eve@example.org/laptop")
            .unwrap()
            .replies
            .is_empty()
    );
    m.checkpoint_live().unwrap();
    assert_eq!(
        rust_xmpp::muc_recovery::load_checkpoint_time(root.path(), HOST, ROOM).unwrap(),
        before
    );
    drop(m);
    let mut m = Muc::new(root.path().into(), HOST.into());
    m.prepare_recovery().unwrap();
    let restored = m.restore_for_session(ALICE).unwrap();
    assert!(
        restored
            .replies
            .iter()
            .any(|p| p.contains("saved status") && p.contains("110"))
    );
    assert!(restored.replies.iter().all(|p| !p.contains("private-pass")));
    assert!(m.restore_for_session(ALICE).unwrap().replies.is_empty());
    // The authenticated restoration itself committed fresh live membership,
    // so a second crash recovers that current room state again.
    drop(m);
    let mut m = Muc::new(root.path().into(), HOST.into());
    m.prepare_recovery().unwrap();
    assert!(
        m.restore_for_session(ALICE)
            .unwrap()
            .replies
            .iter()
            .any(|p| p.contains("110"))
    );
}
#[test]
fn changed_configuration_invalidates_auto_recovery_without_disclosing_password() {
    let root = tempfile::tempdir().unwrap();
    let mut m = initial(root.path());
    m.checkpoint_live().unwrap();
    drop(m);
    storage::update(root.path(), HOST, Some("live"), "config", |v| {
        let mut data = v.get("_data").cloned().unwrap();
        data.set("password", "new-private-password".into());
        v.set("_data", data);
        Ok(())
    })
    .unwrap();
    let mut m = Muc::new(root.path().into(), HOST.into());
    m.prepare_recovery().unwrap();
    let result = m.restore_for_session(ALICE).unwrap();
    assert!(result.replies.is_empty() && result.deliveries.is_empty());
    let denied = send(
        &mut m,
        ALICE,
        &format!(
            "<presence to='{ROOM}/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    assert!(denied.replies.iter().any(|p| p.contains("not-authorized")));
    assert!(
        denied
            .replies
            .iter()
            .all(|p| !p.contains("new-private-password"))
    );
}

#[test]
fn unrelated_disconnect_does_not_delete_dormant_temporary_room() {
    let root = tempfile::tempdir().unwrap();
    let mut m = Muc::new(root.path().into(), HOST.into());
    send(
        &mut m,
        ALICE,
        &format!(
            "<presence to='{ROOM}/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    m.checkpoint_live().unwrap();
    drop(m);
    let mut m = Muc::new(root.path().into(), HOST.into());
    m.prepare_recovery().unwrap();
    m.disconnect("unrelated@example.org/mobile");
    let restored = m.restore_for_session(ALICE).unwrap();
    assert!(restored.replies.iter().any(|p| p.contains("110")));
}
