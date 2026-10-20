use rust_xmpp::{
    muc::Muc,
    protocol::ModuleResult,
    storage::{self, LuaValue as V},
};

fn send(muc: &mut Muc, jid: &str, packet: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(packet).unwrap();
    muc.handle(jid, doc.root_element()).unwrap().unwrap()
}

fn join(muc: &mut Muc, jid: &str, nick: &str) -> ModuleResult {
    send(muc, jid, &format!("<presence to='r@rooms.test/{nick}'/>"))
}

fn role(muc: &mut Muc, actor: &str, nick: &str, role: &str) -> ModuleResult {
    send(
        muc,
        actor,
        &format!(
            "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#admin'><item nick='{nick}' role='{role}'/></query></iq>"
        ),
    )
}

#[test]
fn moderators_cannot_kick_or_demote_other_moderators() {
    let temp = tempfile::tempdir().unwrap();
    let mut muc = Muc::new(temp.path().into(), "rooms.test".into());
    join(&mut muc, "owner@test/r", "Owner");
    join(&mut muc, "bob@test/r", "Bob");
    join(&mut muc, "carol@test/r", "Carol");
    for nick in ["Bob", "Carol"] {
        assert!(
            role(&mut muc, "owner@test/r", nick, "moderator").replies[0].contains("type='result'")
        );
    }
    for denied_role in ["none", "visitor", "participant"] {
        let result = role(&mut muc, "bob@test/r", "Carol", denied_role);
        assert!(result.replies[0].contains("not-allowed"));
        assert!(result.deliveries.is_empty());
    }
    // An owner can still revoke an unaffiliated moderator's role.
    let result = role(&mut muc, "owner@test/r", "Carol", "participant");
    assert!(result.replies[0].contains("type='result'"));
    assert!(
        result
            .deliveries
            .iter()
            .any(|(jid, packet)| jid == "carol@test/r" && packet.contains("role='participant'"))
    );
    assert!(role(&mut muc, "carol@test/r", "Bob", "none").replies[0].contains("forbidden"));
}

#[test]
fn binary_occupant_id_salt_survives_saves_and_restarts() {
    let temp = tempfile::tempdir().unwrap();
    let salt = V::String(vec![0xff, 0, 0x80, b's']);
    let mut raw = storage::parse(
        b"return {_jid='r@rooms.test'; _data={persistent=true}; ['owner@test']='owner'}",
    )
    .unwrap();
    let mut data = raw.get("_data").unwrap().clone();
    data.set("occupant_id_salt", salt.clone());
    raw.set("_data", data);
    storage::save(temp.path(), "rooms.test", Some("r"), "config", &raw).unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let mut muc = Muc::new(temp.path().into(), "rooms.test".into());
        let result = join(&mut muc, "owner@test/r", "Owner");
        let packet = result
            .replies
            .iter()
            .find(|p| p.starts_with("<presence"))
            .unwrap();
        let doc = roxmltree::Document::parse(packet).unwrap();
        let id = doc
            .descendants()
            .find(|n| n.has_tag_name(("urn:xmpp:occupant-id:0", "occupant-id")))
            .unwrap()
            .attribute("id")
            .unwrap()
            .to_owned();
        ids.push(id);
        let saved = storage::load(temp.path(), "rooms.test", Some("r"), "config")
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.get("_data").unwrap().get("occupant_id_salt"),
            Some(&salt)
        );
    }
    assert_eq!(ids[0], ids[1]);
}

#[test]
fn nested_affiliations_do_not_fall_back_to_obsolete_flat_entries() {
    let temp = tempfile::tempdir().unwrap();
    let raw = storage::parse(b"return {_jid='r@rooms.test'; _data={persistent=true; members_only=true}; _affiliations={['owner@test']='owner'; ['member@test']='member'}; ['member@test']='owner'}").unwrap();
    storage::save(temp.path(), "rooms.test", Some("r"), "config", &raw).unwrap();
    let mut muc = Muc::new(temp.path().into(), "rooms.test".into());
    join(&mut muc, "owner@test/r", "Owner");
    let result = send(
        &mut muc,
        "owner@test/r",
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#admin'><item jid='member@test' affiliation='none'/></query></iq>",
    );
    assert!(result.replies[0].contains("type='result'"));
    assert!(join(&mut muc, "member@test/r", "Member").replies[0].contains("registration-required"));
    drop(muc);
    let mut muc = Muc::new(temp.path().into(), "rooms.test".into());
    assert!(join(&mut muc, "member@test/r", "Member").replies[0].contains("registration-required"));
}
