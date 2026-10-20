use rust_xmpp::{muc::Muc, protocol::ModuleResult, storage};

fn send(muc: &mut Muc, jid: &str, xml: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(xml).unwrap();
    muc.handle(jid, doc.root_element()).unwrap().unwrap()
}

#[test]
fn native_domain_bans_block_remote_users_but_allow_explicit_members() {
    let temp = tempfile::tempdir().unwrap();
    // Prosody freezes room affiliations into the top-level room table.
    let raw = storage::parse(b"return {_jid='room@rooms.test'; _data={persistent=true}; ['owner@test']='owner'; ['remote.test']='outcast'; ['member@remote.test']='member'}").unwrap();
    storage::save(temp.path(), "rooms.test", Some("room"), "config", &raw).unwrap();
    let mut muc = Muc::new(temp.path().into(), "rooms.test".into());
    muc.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    let denied = send(
        &mut muc,
        "outsider@remote.test/client",
        "<presence to='room@rooms.test/Outsider'><x xmlns='http://jabber.org/protocol/muc'/></presence>",
    );
    assert!(
        denied.replies[0].contains("forbidden"),
        "{:?}",
        denied.replies
    );
    let admitted = send(
        &mut muc,
        "member@remote.test/client",
        "<presence to='room@rooms.test/Member'><x xmlns='http://jabber.org/protocol/muc'/></presence>",
    );
    assert!(!admitted.replies.iter().any(|p| p.contains("type='error'")));
    assert!(
        admitted
            .replies
            .iter()
            .any(|p| p.contains("affiliation='member'"))
    );
}

#[test]
fn applying_domain_ban_removes_remote_occupants_and_blocks_rejoin() {
    let temp = tempfile::tempdir().unwrap();
    let mut muc = Muc::new(temp.path().into(), "rooms.test".into());
    muc.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    send(
        &mut muc,
        "owner@test/r",
        "<presence to='room@rooms.test/Owner'><x xmlns='http://jabber.org/protocol/muc'/></presence>",
    );
    send(
        &mut muc,
        "remote@remote.test/r",
        "<presence to='room@rooms.test/Remote'><x xmlns='http://jabber.org/protocol/muc'/></presence>",
    );
    send(
        &mut muc,
        "other@allowed.test/r",
        "<presence to='room@rooms.test/Other'><x xmlns='http://jabber.org/protocol/muc'/></presence>",
    );
    let banned = send(
        &mut muc,
        "owner@test/r",
        "<iq type='set' to='room@rooms.test'><query xmlns='http://jabber.org/protocol/muc#admin'><item jid='remote.test' affiliation='outcast'/></query></iq>",
    );
    assert!(banned.replies[0].contains("type='result'"));
    assert!(
        banned
            .deliveries
            .iter()
            .any(|(jid, packet)| jid == "remote@remote.test/r" && packet.contains("code='301'"))
    );
    let message = "<message type='groupchat' to='room@rooms.test'><body>hello</body></message>";
    assert!(send(&mut muc, "remote@remote.test/r", message).replies[0].contains("not-acceptable"));
    assert_eq!(
        send(&mut muc, "other@allowed.test/r", message)
            .deliveries
            .len(),
        2
    );
    assert!(
        send(
            &mut muc,
            "remote@remote.test/new",
            "<presence to='room@rooms.test/Remote'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        )
        .replies[0]
            .contains("forbidden")
    );
}
