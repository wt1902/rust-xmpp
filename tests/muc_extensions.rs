use rust_xmpp::{muc::Muc, protocol::ModuleResult};
use serde_json::json;
const ROOM: &str = "room@rooms.example.org";
fn send(m: &mut Muc, jid: &str, packet: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(packet).unwrap();
    m.handle(jid, doc.root_element()).unwrap().unwrap()
}
fn setup(defaults: serde_json::Value) -> (tempfile::TempDir, Muc) {
    let root = tempfile::tempdir().unwrap();
    let mut m = Muc::new(root.path().into(), "rooms.example.org".into());
    m.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    m.set_defaults(defaults);
    send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<presence to='{ROOM}/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    (root, m)
}
#[test]
fn restricted_private_messages_allow_self_and_optional_moderators() {
    let (_root, mut m) = setup(json!({"allow_pm":"none"}));
    send(
        &mut m,
        "bob@example.org/r",
        &format!(
            "<presence to='{ROOM}/Bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    let denied = send(
        &mut m,
        "bob@example.org/r",
        &format!("<message to='{ROOM}/Alice' type='chat'><body>blocked</body></message>"),
    );
    assert!(denied.replies[0].contains("policy-violation"));
    assert!(denied.deliveries.is_empty());
    let own = send(
        &mut m,
        "bob@example.org/r",
        &format!("<message to='{ROOM}/Bob' type='chat'><body>self</body></message>"),
    );
    assert_eq!(own.deliveries.len(), 1);
    let config = send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='{{xmpp:prosody.im}}muc#allow_modpm'><value>1</value></field></x></query></iq>"
        ),
    );
    assert!(config.replies[0].contains("type='result'"));
    let allowed = send(
        &mut m,
        "bob@example.org/r",
        &format!("<message to='{ROOM}/Alice' type='chat'><body>allowed</body></message>"),
    );
    assert_eq!(allowed.deliveries.len(), 1);
}
#[test]
fn broadcast_roles_hide_visitors_and_configuration_announces_transition() {
    let (_root, mut m) = setup(json!({"moderated":true,"presence_broadcast":{"moderator":true}}));
    let join = send(
        &mut m,
        "bob@example.org/r",
        &format!(
            "<presence to='{ROOM}/Bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    assert!(join.deliveries.is_empty());
    assert!(
        join.replies
            .iter()
            .any(|p| p.contains("/Bob") && p.contains("110"))
    );
    let update = send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='muc#roomconfig_presencebroadcast'><value>moderator</value><value>visitor</value></field></x></query></iq>"
        ),
    );
    assert!(
        update
            .deliveries
            .iter()
            .any(|(to, p)| to == "alice@example.org/r"
                && p.contains("/Bob")
                && !p.contains("unavailable"))
    );
}
#[test]
fn language_config_sections_discovery_and_native_affiliation_hats() {
    let (root, mut m) = setup(json!({"persistent":true}));
    let config = send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='muc#roomconfig_lang'><value>de</value></field></x></query></iq>"
        ),
    );
    assert!(config.replies[0].contains("type='result'"));
    let path = rust_xmpp::storage::path(root.path(), "rooms.example.org", Some("room"), "config");
    let mut frozen = rust_xmpp::storage::parse(&std::fs::read(&path).unwrap()).unwrap();
    let hats=rust_xmpp::storage::parse(br#"return {['alice@example.org']={hats={['urn:staff']={active=true,title='Staff'},['urn:off']={active=false,title='Hidden'}}}}"#).unwrap();
    frozen.set("_affiliation_data", hats);
    std::fs::write(path, rust_xmpp::storage::serialize(&frozen).unwrap()).unwrap();
    let mut m = Muc::new(root.path().into(), "rooms.example.org".into());
    m.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    let join = send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<presence to='{ROOM}/Alice'><x xmlns='http://jabber.org/protocol/muc'/><hats xmlns='urn:xmpp:hats:0'><hat uri='fake'/></hats></presence>"
        ),
    );
    let presence = join.replies.iter().find(|p| p.contains("110")).unwrap();
    assert!(presence.contains("urn:staff"));
    assert!(!presence.contains("urn:off"));
    assert!(!presence.contains("fake"));
    let disco = send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='get'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
        ),
    );
    assert!(disco.replies[0].contains("urn:xmpp:hats:0"));
    assert!(disco.replies[0].contains("<value>de</value>"));
    let form = send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='get'><query xmlns='http://jabber.org/protocol/muc#owner'/></iq>"
        ),
    );
    assert!(form.replies[0].contains("Room information"));
    assert!(form.replies[0].contains("muc#roomconfig_lang"));
}
#[test]
fn messages_cannot_spoof_room_identity_hats_or_occupant_identifiers() {
    let (_root, mut m) = setup(json!({}));
    send(
        &mut m,
        "bob@example.org/r",
        &format!(
            "<presence to='{ROOM}/Bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    for (kind, to) in [
        ("groupchat", ROOM.to_string()),
        ("chat", format!("{ROOM}/Bob")),
    ] {
        let result = send(
            &mut m,
            "alice@example.org/r",
            &format!(
                "<message type='{kind}' to='{to}'><body>safe</body><x xmlns='http://jabber.org/protocol/muc#user'><item jid='forged@example.org'/></x><hats xmlns='urn:xmpp:hats:0'><hat uri='forged-hat'/></hats><occupant-id xmlns='urn:xmpp:occupant-id:0' id='forged-id'/></message>"
            ),
        );
        assert!(!result.deliveries.is_empty());
        for (_, p) in result.deliveries {
            assert!(!p.contains("forged"));
            assert!(p.contains("occupant-id"));
        }
    }
}
#[test]
fn disabled_optional_vcard_and_occupant_ids_are_not_advertised_or_emitted() {
    let root = tempfile::tempdir().unwrap();
    let mut m = Muc::new(root.path().into(), "rooms.example.org".into());
    m.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    m.set_component_options(
        json!({"muc_room_locking":false,"muc_vcard":false,"muc_occupant_id":false}),
        false,
    );
    let join = send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<presence to='{ROOM}/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    assert!(join.replies.iter().all(|p| !p.contains("occupant-id")));
    let disco = send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='get'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
        ),
    );
    assert!(!disco.replies[0].contains("occupant-id"));
    assert!(!disco.replies[0].contains("vcard-temp"));
    let vcard = send(
        &mut m,
        "alice@example.org/r",
        &format!("<iq to='{ROOM}' type='get'><vCard xmlns='vcard-temp'/></iq>"),
    );
    assert!(vcard.replies[0].contains("feature-not-implemented"));
}
#[test]
fn mam_all_rooms_presence_logging_public_queries_and_optional_totals() {
    let root = tempfile::tempdir().unwrap();
    let mut m = Muc::new(root.path().into(), "rooms.example.org".into());
    m.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    m.set_component_options(json!({"muc_room_locking":false,"muc_log_all_rooms":true,"muc_log_by_default":false,"muc_log_presences":true,"muc_log_include_total":false}),true);
    send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<presence to='{ROOM}/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    send(
        &mut m,
        "alice@example.org/r",
        &format!("<message to='{ROOM}' type='groupchat'><body>retained</body></message>"),
    );
    let query = send(
        &mut m,
        "outsider@example.org/r",
        &format!("<iq to='{ROOM}' type='set'><query xmlns='urn:xmpp:mam:2'/></iq>"),
    );
    let text = query.replies.join("");
    assert!(text.contains("retained"));
    let mut saw_presence = false;
    rust_xmpp::archive::scan_store(
        root.path(),
        "rooms.example.org",
        Some("room"),
        "muc_log",
        |entry| {
            saw_presence |= entry.xml.contains("<presence");
            Ok(())
        },
    )
    .unwrap();
    assert!(saw_presence);
    assert!(!text.contains("<count>"));
    assert!(!text.contains(" index="));
    send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><destroy/></query></iq>"
        ),
    );
    let mut count = 0;
    rust_xmpp::archive::scan_store(
        root.path(),
        "rooms.example.org",
        Some("room"),
        "muc_log",
        |_| {
            count += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(count, 0);
}
#[test]
fn offline_reserved_affiliates_follow_anonymity_and_roominfo_counts_nicknames() {
    let (root, _m) = setup(
        json!({"persistent":true,"whois":"moderators","presence_broadcast":{"none":true,"visitor":true,"participant":true,"moderator":true},"description":"Room description"}),
    );
    let path = rust_xmpp::storage::path(root.path(), "rooms.example.org", Some("room"), "config");
    let mut frozen = rust_xmpp::storage::parse(&std::fs::read(&path).unwrap()).unwrap();
    frozen.set("offline@example.org", "member".into());
    frozen.set("unnamed@example.org", "member".into());
    frozen.set(
        "_affiliation_data",
        rust_xmpp::storage::parse(
            b"return {['offline@example.org']={reserved_nickname='Offline'}}",
        )
        .unwrap(),
    );
    std::fs::write(path, rust_xmpp::storage::serialize(&frozen).unwrap()).unwrap();
    let mut m = Muc::new(root.path().into(), "rooms.example.org".into());
    m.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    let guest = send(
        &mut m,
        "bob@example.org/r",
        &format!(
            "<presence to='{ROOM}/Bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    let offline = guest
        .replies
        .iter()
        .find(|p| p.contains("/Offline"))
        .unwrap();
    assert!(offline.contains("unavailable"));
    assert!(!offline.contains("offline@example.org"));
    assert!(
        guest
            .replies
            .iter()
            .all(|p| !p.contains("unnamed@example.org"))
    );
    let owner = send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<presence to='{ROOM}/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    assert!(
        owner
            .replies
            .iter()
            .any(|p| p.contains("unnamed@example.org"))
    );
    send(
        &mut m,
        "bob@example.org/second",
        &format!(
            "<presence to='{ROOM}/Bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    let disco = send(
        &mut m,
        "bob@example.org/r",
        &format!(
            "<iq to='{ROOM}' type='get'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
        ),
    );
    assert!(disco.replies[0].contains("muc_semianonymous"));
    assert!(disco.replies[0].contains("<field var='muc#roominfo_occupants'><value>2</value>"));
    assert!(disco.replies[0].contains("Room description"));
}
#[test]
fn recovery_claim_is_durable_and_unrelated_disconnect_keeps_temporary_claims() {
    let (root, mut first) = setup(json!({"persistent":false}));
    first.checkpoint_live().unwrap();
    drop(first);
    let mut recovered = Muc::new(root.path().into(), "rooms.example.org".into());
    recovered.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    recovered.prepare_recovery().unwrap();
    recovered.disconnect("unrelated@example.org/r");
    let restored = recovered
        .restore_for_session("alice@example.org/r")
        .unwrap();
    assert!(
        restored
            .replies
            .iter()
            .any(|p| p.contains("110") && p.contains("role='moderator'"))
    );
    drop(recovered);
    // Authenticated restoration committed a new live membership checkpoint.
    let mut again = Muc::new(root.path().into(), "rooms.example.org".into());
    again.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    again.prepare_recovery().unwrap();
    let restored_again = again.restore_for_session("alice@example.org/r").unwrap();
    assert!(
        restored_again
            .replies
            .iter()
            .any(|p| p.contains("/Alice") && p.contains("110") && p.contains("role='moderator'"))
    );
}
#[test]
fn large_optional_history_does_not_prevent_checkpointing_membership() {
    let (_root, mut m) = setup(json!({}));
    send(
        &mut m,
        "alice@example.org/r",
        &format!(
            "<message to='{ROOM}' type='groupchat'><body>{}</body></message>",
            "x".repeat(20 * 1024)
        ),
    );
    m.checkpoint_live().unwrap();
}
#[test]
fn explicit_new_nickname_consumes_old_proof_and_pending_nicks_are_reserved() {
    let (root, mut first) = setup(json!({"persistent":false}));
    send(
        &mut first,
        "bob@example.org/r",
        &format!(
            "<presence to='{ROOM}/Bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    first.checkpoint_live().unwrap();
    drop(first);
    let mut recovered = Muc::new(root.path().into(), "rooms.example.org".into());
    recovered.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    recovered.prepare_recovery().unwrap();
    let stolen = send(
        &mut recovered,
        "mallory@example.org/r",
        &format!(
            "<presence to='{ROOM}/Bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    assert!(stolen.replies.iter().any(|p| p.contains("conflict")));
    let explicit = send(
        &mut recovered,
        "alice@example.org/r",
        &format!(
            "<presence to='{ROOM}/Changed'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ),
    );
    assert!(explicit.replies.iter().any(|p| p.contains("110")));
    // Temporary room config and Bob's claim survive Alice's ordinary join.
    drop(recovered);
    let mut again = Muc::new(root.path().into(), "rooms.example.org".into());
    again.set_component_options(serde_json::json!({"muc_room_locking":false}), false);
    again.prepare_recovery().unwrap();
    let alice = again.restore_for_session("alice@example.org/r").unwrap();
    assert!(
        alice
            .replies
            .iter()
            .any(|p| p.contains("/Changed") && p.contains("110"))
    );
    assert!(alice.replies.iter().all(|p| !p.contains("/Alice")));
    assert!(
        again
            .restore_for_session("bob@example.org/r")
            .unwrap()
            .replies
            .iter()
            .any(|p| p.contains("/Bob") && p.contains("110"))
    );
}
