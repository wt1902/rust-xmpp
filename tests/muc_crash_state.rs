//! Dropping Muc without checkpoint_live models an abrupt process loss: only
//! checkpoints committed before returning the accepted stanza can survive.
use rust_xmpp::{muc::Muc, protocol::ModuleResult, storage};
use serde_json::json;
const HOST: &str = "rooms.example.org";
const ROOM: &str = "crash@rooms.example.org";
const A: &str = "alice@example.org/desktop";
const B: &str = "bob@example.org/phone";
fn send(m: &mut Muc, jid: &str, packet: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(packet).unwrap();
    m.handle(jid, doc.root_element()).unwrap().unwrap()
}
fn muc(root: &std::path::Path) -> Muc {
    let mut m = Muc::new(root.into(), HOST.into());
    m.set_component_options(json!({"muc_room_locking":false,"max_history_messages":3,"muc_room_default_history_length":3}), false);
    m
}
fn join(m: &mut Muc, jid: &str, nick: &str) -> ModuleResult {
    send(
        m,
        jid,
        &format!(
            "<presence to='{ROOM}/{nick}'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    )
}
fn has_self(out: &ModuleResult) -> bool {
    out.replies.iter().any(|p| p.contains("code='110'"))
}
#[test]
fn temporary_membership_and_full_bounded_history_survive_ungraceful_loss() {
    let root = tempfile::tempdir().unwrap();
    let mut first = muc(root.path());
    assert!(has_self(&join(&mut first, A, "Alice")));
    assert!(has_self(&join(&mut first, B, "Bob")));
    for text in ["old-zero", "recent-one", "recent-two", "recent-three"] {
        let out = send(
            &mut first,
            A,
            &format!("<message to='{ROOM}' type='groupchat'><body>{text}</body></message>"),
        );
        assert!(!out.deliveries.is_empty());
    }
    drop(first);
    let mut next = muc(root.path());
    next.prepare_recovery().unwrap();
    assert!(
        next.restore_for_session("alice@example.org/other")
            .unwrap()
            .replies
            .is_empty()
    );
    let a = next.restore_for_session(A).unwrap();
    assert!(has_self(&a));
    // A dormant Bob is never an available routing target before authenticating.
    let out = send(
        &mut next,
        A,
        &format!("<message to='{ROOM}' type='groupchat'><body>after-restart</body></message>"),
    );
    assert!(out.deliveries.iter().all(|(jid, _)| jid != B));
    let b = next.restore_for_session(B).unwrap();
    let history = b.replies.join("");
    assert!(has_self(&b));
    assert!(
        !history.contains("old-zero") && !history.contains("recent-one"),
        "{history}"
    );
    assert!(
        history.contains("recent-two")
            && history.contains("recent-three")
            && history.contains("after-restart")
    );
    assert!(history.contains("urn:xmpp:delay"));
    drop(next);
    let mut third = muc(root.path());
    third.prepare_recovery().unwrap();
    assert!(has_self(&third.restore_for_session(A).unwrap()));
    assert!(has_self(&third.restore_for_session(B).unwrap()));
}
#[test]
fn acknowledged_kick_and_room_destruction_cannot_resurrect_membership() {
    let root = tempfile::tempdir().unwrap();
    let mut first = muc(root.path());
    join(&mut first, A, "Alice");
    join(&mut first, B, "Bob");
    let kicked = send(
        &mut first,
        A,
        &format!(
            "<iq to='{ROOM}' type='set' id='kick'><query xmlns='http://jabber.org/protocol/muc#admin'><item nick='Bob' role='none'/></query></iq>"
        ),
    );
    assert!(kicked.replies.iter().any(|p| p.contains("type='result'")));
    drop(first);
    let mut next = muc(root.path());
    next.prepare_recovery().unwrap();
    assert!(next.restore_for_session(B).unwrap().replies.is_empty());
    assert!(has_self(&next.restore_for_session(A).unwrap()));
    let destroyed = send(
        &mut next,
        A,
        &format!(
            "<iq to='{ROOM}' type='set' id='destroy'><query xmlns='http://jabber.org/protocol/muc#owner'><destroy/></query></iq>"
        ),
    );
    assert!(
        destroyed
            .replies
            .iter()
            .any(|p| p.contains("type='result'"))
    );
    drop(next);
    let mut third = muc(root.path());
    third.prepare_recovery().unwrap();
    assert!(third.restore_for_session(A).unwrap().replies.is_empty());
    assert!(third.restore_for_session(B).unwrap().replies.is_empty());
}
#[test]
fn dormant_deadline_stays_fixed_when_another_occupant_recovers_and_sends() {
    let root = tempfile::tempdir().unwrap();
    let mut first = muc(root.path());
    join(&mut first, A, "Alice");
    join(&mut first, B, "Bob");
    drop(first);
    let initial = storage::load(root.path(), HOST, None, "rust_muc_checkpoint")
        .unwrap()
        .unwrap();
    let initial_at = initial
        .get("rooms")
        .unwrap()
        .get(ROOM)
        .unwrap()
        .get("saved_at")
        .unwrap()
        .as_i64()
        .unwrap();
    let mut next = muc(root.path());
    next.prepare_recovery().unwrap();
    next.restore_for_session(A).unwrap();
    send(
        &mut next,
        A,
        &format!("<message to='{ROOM}' type='groupchat'><body>traffic</body></message>"),
    );
    drop(next);
    storage::update(root.path(), HOST, None, "rust_muc_checkpoint", |v| {
        let mut rooms = v.get("rooms").unwrap().clone();
        let mut room = rooms.get(ROOM).unwrap().clone();
        assert_eq!(room.get("saved_at").unwrap().as_i64().unwrap(), initial_at);
        room.set("saved_at", storage::LuaValue::Integer(initial_at - 301));
        rooms.set(ROOM, room);
        v.set("rooms", rooms);
        Ok(())
    })
    .unwrap();
    let mut third = muc(root.path());
    third.prepare_recovery().unwrap();
    assert!(third.restore_for_session(B).unwrap().replies.is_empty());
}
#[test]
fn durable_disconnect_removes_last_temporary_room_without_shutdown_export() {
    let root = tempfile::tempdir().unwrap();
    let mut first = muc(root.path());
    join(&mut first, A, "Alice");
    first.disconnect_durable(A).unwrap();
    drop(first);
    let mut next = muc(root.path());
    next.prepare_recovery().unwrap();
    assert!(next.restore_for_session(A).unwrap().replies.is_empty());
}
#[test]
fn journal_failure_returns_no_routing_and_rolls_back_role_mutation() {
    let root = tempfile::tempdir().unwrap();
    let mut first = muc(root.path());
    join(&mut first, A, "Alice");
    join(&mut first, B, "Bob");
    let path = storage::path(root.path(), HOST, None, "rust_muc_checkpoint");
    let checkpoint = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let packet = format!(
        "<iq to='{ROOM}' type='set' id='kick'><query xmlns='http://jabber.org/protocol/muc#admin'><item nick='Bob' role='none'/></query></iq>"
    );
    let doc = roxmltree::Document::parse(&packet).unwrap();
    assert!(first.handle(A, doc.root_element()).is_err());
    std::fs::remove_dir(&path).unwrap();
    storage::atomic_write(&path, &checkpoint).unwrap();
    let out = send(
        &mut first,
        B,
        &format!("<message to='{ROOM}' type='groupchat'><body>still-participant</body></message>"),
    );
    assert!(
        out.deliveries
            .iter()
            .any(|(jid, p)| jid == A && p.contains("still-participant"))
    );
}

#[test]
fn safe_presence_checkpoint_sanitization_is_idempotent() {
    use rust_xmpp::muc_recovery::sanitize_presence_payload;
    let payload = "<show xmlns='jabber:client'>away</show><status xmlns='jabber:client'>Ready &amp; waiting</status><x xmlns='http://jabber.org/protocol/muc'><password>secret</password></x>";
    let safe = sanitize_presence_payload(payload);
    assert_eq!(
        safe,
        "<show>away</show><status>Ready &amp; waiting</status>"
    );
    assert_eq!(sanitize_presence_payload(&safe), safe);
}
#[test]
fn foreign_stanzas_do_not_initialize_or_rewrite_muc_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let mut m = muc(root.path());
    let packet = "<message to='bob@example.org/phone' type='chat'><body>direct</body></message>";
    let doc = roxmltree::Document::parse(packet).unwrap();
    assert!(m.handle(A, doc.root_element()).unwrap().is_none());
    let path = storage::path(root.path(), HOST, None, "rust_muc_checkpoint");
    assert!(!path.exists());
    join(&mut m, A, "Alice");
    let checkpoint = std::fs::read(&path).unwrap();
    // A sentinel distinguishes a write from an identical journal serialization.
    let sentinel = [checkpoint.as_slice(), b"-- untouched\n"].concat();
    storage::atomic_write(&path, &sentinel).unwrap();
    assert!(m.handle(A, doc.root_element()).unwrap().is_none());
    assert_eq!(std::fs::read(&path).unwrap(), sentinel);
}
