use rust_xmpp::{muc::Muc, protocol::ModuleResult};
fn send(m: &mut Muc, j: &str, x: &str) -> ModuleResult {
    let d = roxmltree::Document::parse(x).unwrap();
    m.handle(j, d.root_element()).unwrap().unwrap()
}
fn join(m: &mut Muc, j: &str, n: &str) -> ModuleResult {
    send(
        m,
        j,
        &format!(
            "<presence to='r@rooms.test/{n}'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    )
}
fn unlock(m: &mut Muc) {
    let r = send(
        m,
        "alice@test/a",
        "<iq type='set' id='c' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'/></query></iq>",
    );
    assert!(r.replies[0].contains("type='result'"));
}
#[test]
fn join_lock_chat_leave() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    let a = join(&mut m, "alice@test/a", "Alice");
    assert!(a.replies[0].contains("201"));
    assert!(join(&mut m, "bob@test/b", "Bob").replies[0].contains("item-not-found"));
    unlock(&mut m);
    let b = join(&mut m, "bob@test/b", "Bob");
    assert!(b.replies.iter().any(|x| x.contains("Alice")));
    assert!(!b.replies[0].contains("alice@test"));
    let c = send(
        &mut m,
        "bob@test/b",
        "<message to='r@rooms.test' type='groupchat' id='x'><body>Hello</body></message>",
    );
    assert_eq!(c.deliveries.len(), 2);
    assert!(c.deliveries[0].1.contains("Hello"));
    assert_eq!(m.disconnect("bob@test/b").deliveries.len(), 1);
}
#[test]
fn authorization_and_conflict() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    assert!(join(&mut m, "bob@test/b", "Alice").replies[0].contains("conflict"));
    join(&mut m, "bob@test/b", "Bob");
    let r = send(
        &mut m,
        "bob@test/b",
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#admin'><item jid='bob@test' affiliation='owner'/></query></iq>",
    );
    assert!(r.replies[0].contains("forbidden"));
    let r = send(
        &mut m,
        "alice@test/a",
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#admin'><item jid='alice@test' affiliation='none'/></query></iq>",
    );
    assert!(r.replies[0].contains("conflict"));
    let r = send(
        &mut m,
        "alice@test/a",
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#admin'><item jid='bob@test' affiliation='outcast'/></query></iq>",
    );
    assert_eq!(r.deliveries.len(), 2);
    assert!(join(&mut m, "bob@test/b", "Bob").replies[0].contains("forbidden"));
}
#[test]
fn persistence_roundtrip() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    join(&mut m, "alice@test/a", "Alice");
    let r = send(
        &mut m,
        "alice@test/a",
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='muc#roomconfig_persistentroom'><value>1</value></field><field var='muc#roomconfig_roomname'><value>Комната</value></field></x></query></iq>",
    );
    assert!(r.replies[0].contains("result"));
    drop(m);
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    let r = send(
        &mut m,
        "alice@test/a",
        "<iq type='get' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'/></iq>",
    );
    assert!(r.replies[0].contains("Комната"));
    join(&mut m, "alice@test/a", "Alice");
}
#[test]
fn archive_history_and_permissions() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    m.set_defaults(serde_json::json!({"archiving":true,"persistent":true}));
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    send(
        &mut m,
        "alice@test/a",
        "<message to='r@rooms.test' type='groupchat'><body>Archived</body></message>",
    );
    let query = "<iq type='set' to='r@rooms.test' id='mam'><query xmlns='urn:xmpp:mam:2'/></iq>";
    // Native public/open room archives are readable by unaffiliated users.
    assert!(send(&mut m, "outsider@test/a", query).replies[0].contains("Archived"));
    let r = send(&mut m, "alice@test/a", query);
    assert!(r.replies[0].contains("Archived"));
    assert!(r.replies.last().unwrap().contains("<fin"));
    let joined = join(&mut m, "bob@test/b", "Bob");
    assert!(
        joined
            .replies
            .iter()
            .any(|x| x.contains("Archived") && x.contains("urn:xmpp:delay"))
    );
    send(
        &mut m,
        "alice@test/a",
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='muc#roomconfig_membersonly'><value>1</value></field></x></query></iq>",
    );
    assert!(send(&mut m, "outsider@test/a", query).replies[0].contains("forbidden"));
}
#[test]
fn nick_invite_destroy_and_local_creation() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    m.set_local_domain("test".into());
    assert!(join(&mut m, "external@else/a", "External").replies[0].contains("forbidden"));
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    let renamed = join(&mut m, "alice@test/a", "NewName");
    assert!(renamed.replies[0].contains("303"));
    assert!(renamed.replies[0].contains("nick='NewName'"));
    let inv = send(
        &mut m,
        "alice@test/a",
        "<message to='r@rooms.test'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@test'><reason>Join us</reason></invite></x></message>",
    );
    assert_eq!(inv.deliveries[0].0, "bob@test");
    assert!(inv.deliveries[0].1.contains("Join us"));
    let destroy = "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'><destroy/></query></iq>";
    assert!(send(&mut m, "bob@test/a", destroy).replies[0].contains("forbidden"));
    assert_eq!(send(&mut m, "alice@test/a", destroy).deliveries.len(), 1);
    assert!(join(&mut m, "bob@test/a", "Bob").replies[0].contains("201"));
}
#[test]
fn preserves_unknown_binary_mixed_room_fields() {
    use rust_xmpp::storage::{self, LuaValue as V};
    let t = tempfile::tempdir().unwrap();
    let mut raw = V::table();
    raw.set("_jid", "r@rooms.test".into());
    raw.set("alice@test", "owner".into());
    let mut data = V::table();
    data.set("persistent", V::Bool(true));
    data.set("salt", V::String(vec![0xff, 0x00, 0x80]));
    let mut mixed = V::table();
    mixed.set("extension", "original".into());
    mixed.set_key(V::Integer(1), "first".into());
    data.set("mixed", mixed.clone());
    raw.set("_data", data);
    storage::save(t.path(), "rooms.test", Some("r"), "config", &raw).unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    join(&mut m, "alice@test/a", "Alice");
    send(
        &mut m,
        "alice@test/a",
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='muc#roomconfig_roomname'><value>New</value></field></x></query></iq>",
    );
    let saved = storage::load(t.path(), "rooms.test", Some("r"), "config")
        .unwrap()
        .unwrap();
    let d = saved.get("_data").unwrap();
    assert_eq!(d.get("salt"), Some(&V::String(vec![0xff, 0x00, 0x80])));
    assert_eq!(d.get("mixed"), Some(&mixed));
    assert_eq!(d.get("name").unwrap().as_str(), Some("New"));
}
#[test]
fn multiple_resources_share_nick_and_private_delivery() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    join(&mut m, "bob@test/a", "Bob");
    let second = join(&mut m, "bob@test/b", "Bob");
    assert!(!second.replies.iter().any(|s| s.contains("type='error'")));
    let pm = send(
        &mut m,
        "alice@test/a",
        "<message to='r@rooms.test/Bob' type='chat'><body>Private</body></message>",
    );
    assert_eq!(pm.deliveries.len(), 2);
    assert_eq!(m.disconnect("bob@test/a").deliveries.len(), 0);
    assert_eq!(m.disconnect("bob@test/b").deliveries.len(), 1);
}
#[test]
fn iq_response_requires_expected_sender() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    join(&mut m, "bob@test/b", "Bob");
    let request = send(
        &mut m,
        "alice@test/a",
        "<iq to='r@rooms.test/Bob' type='get' id='original'><ping xmlns='urn:xmpp:ping'/></iq>",
    );
    let packet = roxmltree::Document::parse(&request.deliveries[0].1).unwrap();
    let id = packet.root_element().attribute("id").unwrap();
    let answer = format!("<iq type='result' to='r@rooms.test/Alice' id='{id}'/>");
    assert!(
        send(&mut m, "mallory@test/c", &answer)
            .deliveries
            .is_empty()
    );
    let response = send(&mut m, "bob@test/b", &answer);
    assert_eq!(response.deliveries[0].0, "alice@test/a");
    assert!(response.deliveries[0].1.contains("id='original'"));
}
#[test]
fn persistent_destroy_creates_prosody_tombstone() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    m.set_defaults(serde_json::json!({"persistent":true}));
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    send(
        &mut m,
        "alice@test/a",
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'><destroy><reason>Closed</reason></destroy></query></iq>",
    );
    drop(m);
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    assert!(join(&mut m, "bob@test/a", "Bob").replies[0].contains("gone"));
    let saved = rust_xmpp::storage::load(t.path(), "rooms.test", Some("r"), "config")
        .unwrap()
        .unwrap();
    assert_eq!(
        saved.get("_data").unwrap().get("destroyed"),
        Some(&rust_xmpp::storage::LuaValue::Bool(true))
    );
}
#[test]
fn reserved_nickname_blocks_other_users() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    m.set_defaults(serde_json::json!({"persistent":true}));
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    let reg = "<iq type='set' to='r@rooms.test'><query xmlns='jabber:iq:register'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#register</value></field><field var='muc#register_roomnick'><value>Reserved</value></field></x></query></iq>";
    assert!(send(&mut m, "alice@test/a", reg).replies[0].contains("type='result'"));
    assert!(join(&mut m, "bob@test/a", "Reserved").replies[0].contains("conflict"));
    drop(m);
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    assert!(join(&mut m, "bob@test/a", "Reserved").replies[0].contains("conflict"));
    assert!(!join(&mut m, "alice@test/a", "Reserved").replies[0].contains("type='error'"));
}
#[test]
fn occupant_id_is_stable_and_spoofed_ids_removed() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    let first = send(
        &mut m,
        "alice@test/a",
        "<message to='r@rooms.test' type='groupchat'><body>Hi</body><occupant-id xmlns='urn:xmpp:occupant-id:0' id='fake'/></message>",
    );
    let d = roxmltree::Document::parse(&first.deliveries[0].1).unwrap();
    let ids = d
        .descendants()
        .filter(|n| n.has_tag_name(("urn:xmpp:occupant-id:0", "occupant-id")))
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 1);
    let id = ids[0].attribute("id").unwrap().to_owned();
    assert_ne!(id, "fake");
    let next = join(&mut m, "alice@test/b", "Alice");
    assert!(next.replies.iter().any(|p| p.contains(&id)));
}
#[test]
fn switching_to_members_only_removes_unaffiliated_users() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    join(&mut m, "bob@test/a", "Bob");
    let r = send(
        &mut m,
        "alice@test/a",
        "<iq type='set' to='r@rooms.test'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='muc#roomconfig_membersonly'><value>1</value></field></x></query></iq>",
    );
    assert!(
        r.deliveries
            .iter()
            .any(|(j, p)| j == "bob@test/a" && p.contains("322"))
    );
    assert!(
        send(
            &mut m,
            "bob@test/a",
            "<message type='groupchat' to='r@rooms.test'><body>Still here?</body></message>"
        )
        .replies[0]
            .contains("not-acceptable")
    );
}
#[test]
fn room_vcard_owner_only_and_avatar_presence() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    let set = "<iq type='set' to='r@rooms.test'><vCard xmlns='vcard-temp'><FN>Test Room</FN><PHOTO><TYPE>image/png</TYPE><BINVAL>aGVsbG8=</BINVAL></PHOTO></vCard></iq>";
    assert!(send(&mut m, "bob@test/a", set).replies[0].contains("forbidden"));
    let result = send(&mut m, "alice@test/a", set);
    assert!(result.replies[0].contains("result"));
    assert!(
        result
            .deliveries
            .iter()
            .any(|(_, p)| p.contains("vcard-temp:x:update"))
    );
    let get = send(
        &mut m,
        "bob@test/a",
        "<iq type='get' to='r@rooms.test'><vCard xmlns='vcard-temp'/></iq>",
    );
    assert!(get.replies[0].contains("Test Room"));
    let joined = join(&mut m, "bob@test/a", "Bob");
    assert!(
        joined
            .replies
            .iter()
            .any(|p| p.contains("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"))
    );
}
#[test]
fn visitor_voice_request_cannot_spoof_identity_or_grant_itself_voice() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    m.set_defaults(serde_json::json!({"moderated":true}));
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    join(&mut m, "bob@test/a", "Bob");
    let message = "<message to='r@rooms.test' type='groupchat'><body>Hello</body></message>";
    assert!(send(&mut m, "bob@test/a", message).replies[0].contains("forbidden"));
    let request = "<message to='r@rooms.test' type='normal'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#jid'><value>mallory@test/a</value></field><field var='muc#request_allow'><value>1</value></field><field var='muc#role'><value>moderator</value></field></x></message>";
    let forwarded = send(&mut m, "bob@test/a", request);
    assert_eq!(forwarded.deliveries.len(), 1);
    assert_eq!(forwarded.deliveries[0].0, "alice@test/a");
    assert!(forwarded.deliveries[0].1.contains("bob@test/a"));
    assert!(!forwarded.deliveries[0].1.contains("mallory"));
    assert!(send(&mut m, "bob@test/a", message).replies[0].contains("forbidden"));
    let grant = request.replace("mallory@test/a", "bob@test/a");
    let result = send(&mut m, "alice@test/a", &grant);
    assert_eq!(result.deliveries.len(), 2);
    assert!(result.deliveries[0].1.contains("role='participant'"));
    assert_eq!(send(&mut m, "bob@test/a", message).deliveries.len(), 2);
}
#[test]
fn maintenance_expires_idle_archives_and_tombstones() {
    use rust_xmpp::archive::{self, Entry};
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    m.set_defaults(serde_json::json!({"persistent":true,"archiving":true}));
    m.set_archive_retention(Some(60.0));
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    for (id, when) in [("old", now - 100.0), ("new", now - 10.0)] {
        archive::append_new(
            t.path(),
            "rooms.test",
            Some("r"),
            "muc_log",
            Entry {
                id: id.into(),
                when,
                peer: "alice@test/a".into(),
                xml:
                    "<message xmlns='jabber:client' type='groupchat'><body>Stored</body></message>"
                        .into(),
            },
        )
        .unwrap();
    }
    drop(m);
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    m.set_archive_retention(Some(60.0));
    m.maintenance(now).unwrap();
    let entries = archive::load_store(t.path(), "rooms.test", Some("r"), "muc_log").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, "new");
    send(
        &mut m,
        "alice@test/a",
        "<iq to='r@rooms.test' type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><destroy/></query></iq>",
    );
    m.maintenance(now + 32.0 * 86400.0).unwrap();
    assert!(join(&mut m, "bob@test/a", "Bob").replies[0].contains("201"));
}
#[test]
fn restored_temporary_room_is_deleted_after_last_disconnect() {
    use rust_xmpp::storage::{self, LuaValue as V};
    let t = tempfile::tempdir().unwrap();
    let raw = storage::parse(
        b"return {_jid='r@rooms.test';_data={persistent=false};['alice@test']='owner'}",
    )
    .unwrap();
    storage::save(t.path(), "rooms.test", Some("r"), "config", &raw).unwrap();
    storage::save(t.path(), "rooms.test", Some("r"), "state", &V::table()).unwrap();
    let mut index = V::table();
    index.set("r@rooms.test", V::Bool(true));
    storage::save(t.path(), "rooms.test", None, "persistent", &index).unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    join(&mut m, "alice@test/a", "Alice");
    m.disconnect("alice@test/a");
    assert!(
        storage::load(t.path(), "rooms.test", Some("r"), "config")
            .unwrap()
            .is_none()
    );
    assert!(
        storage::load(t.path(), "rooms.test", Some("r"), "state")
            .unwrap()
            .is_none()
    );
    assert!(join(&mut m, "bob@test/a", "Bob").replies[0].contains("201"));
}
#[test]
fn configured_lock_timeout_expires_without_owner_submission() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    m.set_component_options(serde_json::json!({"muc_room_lock_timeout":0}), false);
    join(&mut m, "alice@test/a", "Alice");
    assert!(!join(&mut m, "bob@test/a", "Bob").replies[0].contains("item-not-found"));
}
#[test]
fn native_muc_archive_type_and_anonymity_are_preserved() {
    use rust_xmpp::archive::{self, Entry};
    let t = tempfile::tempdir().unwrap();
    let mut m = Muc::new(t.path().into(), "rooms.test".into());
    m.set_defaults(serde_json::json!({"persistent":true,"archiving":true,"whois":"moderators"}));
    join(&mut m, "alice@test/a", "Alice");
    unlock(&mut m);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    archive::append_new(t.path(),"rooms.test",Some("r"),"muc_log",Entry{id:"native".into(),when:now,peer:"message<groupchat".into(),xml:"<message xmlns='jabber:client' type='groupchat' from='r@rooms.test/OldNick' to='secret@example/r'><body>Native old message</body><x xmlns='http://jabber.org/protocol/muc#user'><item jid='secret@example'/></x></message>".into()}).unwrap();
    let joined = join(&mut m, "bob@test/b", "Bob");
    let historic = joined
        .replies
        .iter()
        .find(|s| s.contains("Native old message"))
        .unwrap();
    assert!(!historic.contains("secret@example"));
    let query = "<iq to='r@rooms.test' type='set'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>secret@example/r</value></field></x></query></iq>";
    let result = send(&mut m, "bob@test/b", query);
    assert!(
        result
            .replies
            .iter()
            .any(|s| s.contains("Native old message"))
    );
    assert!(!result.replies.iter().any(|s| s.contains("secret@example")));
    send(
        &mut m,
        "alice@test/a",
        "<message to='r@rooms.test' type='groupchat'><body>New</body></message>",
    );
    assert!(
        archive::load_store(t.path(), "rooms.test", Some("r"), "muc_log")
            .unwrap()
            .iter()
            .all(|e| e.peer == "message<groupchat")
    );
}
