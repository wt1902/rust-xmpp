use rust_xmpp::{muc::Muc, protocol::ModuleResult};
use serde_json::json;
const ROOM: &str = "room@rooms.example.org";
const COMMANDS: &str = "http://jabber.org/protocol/commands";
const AFF: &str = "http://prosody.im/protocol/muc#set-affiliation";
const DESTROY: &str = "http://prosody.im/protocol/muc#destroy";
fn send(m: &mut Muc, jid: &str, xml: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(xml).unwrap();
    m.handle(jid, doc.root_element()).unwrap().unwrap()
}
fn room(m: &mut Muc) {
    send(
        m,
        "owner@example.org/r",
        &format!(
            "<presence to='{ROOM}/Owner'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    send(
        m,
        "owner@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='muc#roomconfig_persistentroom'><value>1</value></field></x></query></iq>"
        ),
    );
}
fn register(m: &mut Muc, jid: &str, nick: &str) -> ModuleResult {
    send(
        m,
        jid,
        &format!(
            "<iq to='{ROOM}' type='set'><query xmlns='jabber:iq:register'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#register</value></field><field var='muc#register_roomnick'><value>{nick}</value></field></x></query></iq>"
        ),
    )
}
#[test]
fn optional_registration_grants_membership_and_enforces_reserved_nickname() {
    let root = tempfile::tempdir().unwrap();
    let mut m = Muc::new(root.path().into(), "rooms.example.org".into());
    m.set_component_options(json!({"allow_unaffiliated_register":true,"enforce_registered_nickname":true,"muc_registration_include_form":true}),false);
    room(&mut m);
    assert!(register(&mut m, "bob@example.org/r", "Reserved").replies[0].contains("type='result'"));
    let result = send(
        &mut m,
        "bob@example.org/r",
        &format!("<iq to='{ROOM}' type='get'><query xmlns='jabber:iq:register'/></iq>"),
    );
    assert!(result.replies[0].contains("type='result'><field"));
    assert!(result.replies[0].contains("<value>Reserved</value>"));
    let joined = send(
        &mut m,
        "bob@example.org/r",
        &format!(
            "<presence to='{ROOM}/Other'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    assert!(
        joined
            .replies
            .iter()
            .any(|p| p.contains("/Reserved'") && p.contains("affiliation='member'"))
    );
    let rename = send(
        &mut m,
        "bob@example.org/r",
        &format!("<presence to='{ROOM}/Other'/>"),
    );
    assert!(rename.replies[0].contains("not-acceptable"));
    let reregister = register(&mut m, "bob@example.org/r", "New");
    assert!(
        reregister
            .deliveries
            .iter()
            .any(|(_, p)| p.contains("code='307'"))
    );
    let message = send(
        &mut m,
        "bob@example.org/r",
        &format!("<message to='{ROOM}' type='groupchat'><body>departed</body></message>"),
    );
    assert!(message.replies[0].contains("not-acceptable"));
}
#[test]
fn default_registration_denies_unaffiliated_users() {
    let root = tempfile::tempdir().unwrap();
    let mut m = Muc::new(root.path().into(), "rooms.example.org".into());
    room(&mut m);
    assert!(
        register(&mut m, "bob@example.org/r", "Bob").replies[0].contains("registration-required")
    );
}
fn start(m: &mut Muc, jid: &str, node: &str) -> String {
    let result = send(
        m,
        jid,
        &format!(
            "<iq to='rooms.example.org' type='set'><command xmlns='{COMMANDS}' node='{node}'/></iq>"
        ),
    );
    let doc = roxmltree::Document::parse(&result.replies[0]).unwrap();
    doc.descendants()
        .find(|n| n.has_tag_name((COMMANDS, "command")))
        .unwrap()
        .attribute("sessionid")
        .unwrap()
        .to_owned()
}
fn submit(m: &mut Muc, jid: &str, node: &str, id: &str, fields: &str) -> ModuleResult {
    send(
        m,
        jid,
        &format!(
            "<iq to='rooms.example.org' type='set'><command xmlns='{COMMANDS}' node='{node}' sessionid='{id}' action='complete'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{node}</value></field>{fields}</x></command></iq>"
        ),
    )
}
#[test]
fn administration_commands_recheck_authority_bind_sessions_and_update_live_rooms() {
    let root = tempfile::tempdir().unwrap();
    let mut m = Muc::new(root.path().into(), "rooms.example.org".into());
    m.set_component_options(json!({"admins":["admin@example.org","other@example.org"],"muc_tombstone_expiry":"0 seconds"}),false);
    room(&mut m);
    let outsider = send(
        &mut m,
        "stranger@example.org/r",
        &format!(
            "<iq to='rooms.example.org' type='get'><query xmlns='http://jabber.org/protocol/disco#items' node='{COMMANDS}'/></iq>"
        ),
    );
    assert!(!outsider.replies[0].contains("node='http://prosody.im/protocol/muc#destroy'"));
    let denied = send(
        &mut m,
        "stranger@example.org/r",
        &format!(
            "<iq to='rooms.example.org' type='set'><command xmlns='{COMMANDS}' node='{AFF}'/></iq>"
        ),
    );
    assert!(denied.replies[0].contains("forbidden"));
    let id = start(&mut m, "admin@example.org/r", AFF);
    let fields = format!(
        "<field var='room'><value>{ROOM}</value></field><field var='jid'><value>owner@example.org</value></field><field var='affiliation'><value>outcast</value></field>"
    );
    assert!(
        submit(&mut m, "other@example.org/r", AFF, &id, &fields).replies[0].contains("bad-request")
    );
    let updated = submit(&mut m, "admin@example.org/r", AFF, &id, &fields);
    assert!(updated.replies[0].contains("status='completed'"));
    assert!(
        updated
            .deliveries
            .iter()
            .any(|(_, p)| p.contains("code='301'"))
    );
    assert!(
        submit(&mut m, "admin@example.org/r", AFF, &id, &fields).replies[0].contains("bad-request")
    );
    // A privileged component command may remove the final owner, just like
    // native room:set_affiliation(true,...); destroying such a room still works.
    let id = start(&mut m, "admin@example.org/r", DESTROY);
    assert!(
        submit(
            &mut m,
            "admin@example.org/r",
            DESTROY,
            &id,
            &format!("<field var='rooms'><value>{ROOM}</value></field>")
        )
        .replies[0]
            .contains("status='completed'")
    );
    let rejoin = send(
        &mut m,
        "new@example.org/r",
        &format!(
            "<presence to='{ROOM}/New'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    assert!(rejoin.replies.iter().any(|p| p.contains("code='201'")));
}
#[test]
fn configured_tombstone_expiry_allows_immediate_recreation() {
    let root = tempfile::tempdir().unwrap();
    let mut m = Muc::new(root.path().into(), "rooms.example.org".into());
    m.set_component_options(json!({"muc_tombstone_expiry":"0 seconds"}), false);
    room(&mut m);
    send(
        &mut m,
        "owner@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><destroy/></query></iq>"
        ),
    );
    let joined = send(
        &mut m,
        "new@example.org/r",
        &format!(
            "<presence to='{ROOM}/New'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    assert!(joined.replies.iter().any(|p| p.contains("code='201'")));
}
