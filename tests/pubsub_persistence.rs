use rust_xmpp::{
    pubsub,
    storage::{self, LuaValue as V},
};
use std::path::Path;
fn account(root: &Path, user: &str) {
    let mut data = V::table();
    data.set("password", "test-only".into());
    storage::save(root, "example.test", Some(user), "accounts", &data).unwrap();
}
fn request(root: &Path, actor: &str, body: &str) -> String {
    let doc = roxmltree::Document::parse(body).unwrap();
    pubsub::handle(root, "example.test", actor, doc.root_element())
        .unwrap()
        .unwrap()
        .replies
        .join("")
}
fn iq(typ: &str, to: &str, content: &str) -> String {
    format!(
        "<iq type='{typ}' id='x' to='{to}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>{content}</pubsub></iq>"
    )
}
#[test]
fn pep_persists_namespaces_and_enforces_owner() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    account(d.path(), "bob");
    let publish = iq(
        "set",
        "alice@example.test",
        "<publish node='urn:xmpp:omemo:2:devices'><item id='current'><devices xmlns='urn:xmpp:omemo:2' xmlns:ex='urn:extension'><device id='123' ex:label='phone'/></devices></item></publish>",
    );
    assert!(request(d.path(), "bob@example.test/r", &publish).contains("forbidden"));
    assert!(request(d.path(), "alice@example.test/r", &publish).contains("type='result'"));
    let get = iq(
        "get",
        "alice@example.test",
        "<items node='urn:xmpp:omemo:2:devices'/>",
    );
    assert!(request(d.path(), "bob@example.test/r", &get).contains("forbidden"));
    let response = request(d.path(), "alice@example.test/r", &get);
    let doc = roxmltree::Document::parse(&response).unwrap();
    let device = doc
        .descendants()
        .find(|n| n.has_tag_name(("urn:xmpp:omemo:2", "device")))
        .unwrap();
    assert_eq!(device.attribute(("urn:extension", "label")), Some("phone"));
    let nodes = storage::load(d.path(), "example.test", Some("alice"), "pep")
        .unwrap()
        .unwrap();
    assert!(nodes.get("urn:xmpp:omemo:2:devices").is_some());
}
#[test]
fn open_model_and_notifications() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    account(d.path(), "bob");
    let create = iq(
        "set",
        "alice@example.test",
        "<create node='test'/><configure><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#access_model'><value>open</value></field></x></configure>",
    );
    assert!(request(d.path(), "alice@example.test/r", &create).contains("type='result'"));
    let sub = iq(
        "set",
        "alice@example.test",
        "<subscribe node='test' jid='bob@example.test/r'/>",
    );
    assert!(request(d.path(), "bob@example.test/r", &sub).contains("subscribed"));
    let p = iq(
        "set",
        "alice@example.test",
        "<publish node='test'><item id='a'><data xmlns='urn:test'>abc</data></item></publish>",
    );
    let doc = roxmltree::Document::parse(&p).unwrap();
    let result = pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(result.deliveries.len(), 1);
    assert!(
        result
            .deliveries
            .iter()
            .any(|d| d.0 == "bob@example.test/r")
    );
    assert!(
        request(
            d.path(),
            "bob@example.test/r",
            &iq("get", "alice@example.test", "<items node='test'/>")
        )
        .contains("abc")
    );
}
#[test]
fn roster_presence_access_and_foreign_subscription_denied() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    let p = iq(
        "set",
        "alice@example.test",
        "<publish node='test'><item id='a'><x xmlns='urn:test'/></item></publish>",
    );
    request(d.path(), "alice@example.test/r", &p);
    let mut roster = V::table();
    let mut contact = V::table();
    contact.set("subscription", "from".into());
    roster.set("bob@example.test", contact);
    storage::save(d.path(), "example.test", Some("alice"), "roster", &roster).unwrap();
    assert!(
        request(
            d.path(),
            "bob@example.test/r",
            &iq("get", "alice@example.test", "<items node='test'/>")
        )
        .contains("type='result'")
    );
    assert!(
        request(
            d.path(),
            "bob@example.test/r",
            &iq(
                "set",
                "alice@example.test",
                "<subscribe node='test' jid='eve@example.test'/>"
            )
        )
        .contains("forbidden")
    );
}
#[test]
fn configure_requires_owner() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    request(
        d.path(),
        "alice@example.test/r",
        &iq("set", "alice@example.test", "<create node='test'/>"),
    );
    let x = "<iq type='set' to='alice@example.test' id='x'><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><delete node='test'/></pubsub></iq>";
    assert!(request(d.path(), "bob@example.test/r", x).contains("forbidden"));
    assert!(request(d.path(), "alice@example.test/r", x).contains("type='result'"));
    assert!(
        request(
            d.path(),
            "alice@example.test/r",
            &iq("get", "alice@example.test", "<items node='test'/>")
        )
        .contains("item-not-found")
    );
}
#[test]
fn reads_prosody_legacy_fixture() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    let p = storage::path(d.path(), "example.test", Some("alice"), "pep");
    storage::atomic_write(&p,b"return { ['urn:old']={name='urn:old';config={access_model='open';max_items=1};subscribers={};affiliations={['alice@example.test']='owner'}}};").unwrap();
    let archive = storage::path(d.path(), "example.test", Some("alice"), "pep_urn:old")
        .with_extension("list");
    storage::atomic_write(&archive,b"item({name='payload';attr={xmlns='urn:old';stamp='2020-01-01T00:00:00Z'};[1]='persisted';key='current';when=1577836800;with='alice@example.test'});\n").unwrap();
    let out = request(
        d.path(),
        "bob@example.test/r",
        &iq("get", "alice@example.test", "<items node='urn:old'/>"),
    );
    assert!(out.contains("persisted"), "{out}");
    let doc = roxmltree::Document::parse(&out).unwrap();
    assert!(
        doc.descendants()
            .any(|n| n.has_tag_name(("urn:old", "payload")))
    );
}
#[test]
fn configurable_limits_component_creation_and_publisher() {
    let d = tempfile::tempdir().unwrap();
    let options = pubsub::Options {
        max_items: 10000,
        restrict_node_creation: false,
        autocreate_on_publish: false,
    };
    let run = |actor: &str, xml: &str| {
        let doc = roxmltree::Document::parse(xml).unwrap();
        pubsub::handle_component_with_options(
            d.path(),
            "pubsub.example.test",
            actor,
            &[],
            doc.root_element(),
            &options,
        )
        .unwrap()
        .unwrap()
        .replies
        .join("")
    };
    assert!(run("alice@example.test/r",&iq("set","pubsub.example.test","<create node='n'/><configure><x xmlns='jabber:x:data' type='submit'><field var='pubsub#max_items'><value>10000</value></field></x></configure>")).contains("type='result'"));
    let set = "<iq type='set' to='pubsub.example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><affiliations node='n'><affiliation jid='bob@example.test' affiliation='publisher'/></affiliations></pubsub></iq>";
    assert!(run("alice@example.test/r", set).contains("type='result'"));
    let publish = iq(
        "set",
        "pubsub.example.test",
        "<publish node='n'><item id='a'><x xmlns='urn:test'/></item></publish>",
    );
    assert!(run("bob@example.test/r", &publish).contains("type='result'"));
    assert!(run("eve@example.test/r", &publish).contains("forbidden"));
}
#[test]
fn capability_discovery_replays_and_filters_notifications() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    account(d.path(), "bob");
    let mut a = V::table();
    let mut c = V::table();
    c.set("subscription", "from".into());
    a.set("bob@example.test", c);
    storage::save(d.path(), "example.test", Some("alice"), "roster", &a).unwrap();
    let mut b = V::table();
    let mut c = V::table();
    c.set("subscription", "to".into());
    b.set("alice@example.test", c);
    storage::save(d.path(), "example.test", Some("bob"), "roster", &b).unwrap();
    let publish = iq(
        "set",
        "alice@example.test",
        "<publish node='urn:test'><item id='one'><x xmlns='urn:test'>hello</x></item></publish>",
    );
    request(d.path(), "alice@example.test/r", &publish);
    let presence=roxmltree::Document::parse("<presence><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='urn:client' ver='abc'/></presence>").unwrap();
    let query = pubsub::on_presence(
        d.path(),
        "example.test",
        "bob@example.test/r",
        presence.root_element(),
    )
    .unwrap();
    assert_eq!(query.deliveries.len(), 1);
    let querydoc = roxmltree::Document::parse(&query.deliveries[0].1).unwrap();
    let id = querydoc.root_element().attribute("id").unwrap();
    let response = format!(
        "<iq type='result' id='{id}'><query xmlns='http://jabber.org/protocol/disco#info'><feature var='urn:test+notify'/></query></iq>"
    );
    let doc = roxmltree::Document::parse(&response).unwrap();
    assert!(
        pubsub::on_disco_result(
            d.path(),
            "example.test",
            "eve@example.test/r",
            doc.root_element()
        )
        .unwrap()
        .is_none()
    );
    let replay = pubsub::on_disco_result(
        d.path(),
        "example.test",
        "bob@example.test/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(replay.deliveries.len(), 1);
    assert!(replay.deliveries[0].1.contains("hello"));
    let doc = roxmltree::Document::parse(&publish).unwrap();
    let events = pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(
        events
            .deliveries
            .iter()
            .any(|d| d.0 == "bob@example.test/r")
    );
    storage::save(
        d.path(),
        "example.test",
        Some("alice"),
        "roster",
        &V::table(),
    )
    .unwrap();
    let events = pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(
        !events
            .deliveries
            .iter()
            .any(|d| d.0 == "bob@example.test/r")
    );
}
#[test]
fn subscription_options_disable_events_and_require_subscriber() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    request(
        d.path(),
        "alice@example.test/r",
        &iq(
            "set",
            "alice@example.test",
            "<create node='n'/><configure><x xmlns='jabber:x:data' type='submit'><field var='pubsub#access_model'><value>open</value></field></x></configure>",
        ),
    );
    let sub = iq(
        "set",
        "alice@example.test",
        "<subscribe node='n' jid='bob@example.test/r'/><options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#subscribe_options</value></field><field var='pubsub#deliver'><value>0</value></field></x></options>",
    );
    assert!(request(d.path(), "bob@example.test/r", &sub).contains("subscribed"));
    let get = iq(
        "get",
        "alice@example.test",
        "<options node='n' jid='bob@example.test/r'/>",
    );
    assert!(request(d.path(), "bob@example.test/r", &get).contains("<value>0</value>"));
    assert!(request(d.path(), "eve@example.test/r", &get).contains("forbidden"));
    let pubxml = iq(
        "set",
        "alice@example.test",
        "<publish node='n'><item id='x'><x xmlns='urn:test'/></item></publish>",
    );
    let doc = roxmltree::Document::parse(&pubxml).unwrap();
    let result = pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(
        !result
            .deliveries
            .iter()
            .any(|d| d.0 == "bob@example.test/r")
    );
}
#[test]
fn nonpersistent_items_stay_in_memory_and_can_be_made_persistent() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    let create = iq(
        "set",
        "alice@example.test",
        "<create node='n'/><configure><x xmlns='jabber:x:data' type='submit'><field var='pubsub#persist_items'><value>0</value></field></x></configure>",
    );
    assert!(request(d.path(), "alice@example.test/r", &create).contains("type='result'"));
    let p = iq(
        "set",
        "alice@example.test",
        "<publish node='n'><item id='a'><x xmlns='urn:test'>memory-only</x></item></publish>",
    );
    assert!(request(d.path(), "alice@example.test/r", &p).contains("type='result'"));
    let get = iq("get", "alice@example.test", "<items node='n'/>");
    assert!(request(d.path(), "alice@example.test/r", &get).contains("memory-only"));
    assert!(
        rust_xmpp::archive::load_store(d.path(), "example.test", Some("alice"), "pep_n")
            .unwrap()
            .is_empty()
    );
    let config = "<iq type='set' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure node='n'><x xmlns='jabber:x:data' type='submit'><field var='pubsub#persist_items'><value>1</value></field></x></configure></pubsub></iq>";
    assert!(request(d.path(), "alice@example.test/r", config).contains("type='result'"));
    assert_eq!(
        rust_xmpp::archive::load_store(d.path(), "example.test", Some("alice"), "pep_n")
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn modern_bookmarks_notify_legacy_capability() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    let presence=roxmltree::Document::parse("<presence><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='client' ver='v'/></presence>").unwrap();
    let q = pubsub::on_presence(
        d.path(),
        "example.test",
        "alice@example.test/old",
        presence.root_element(),
    )
    .unwrap();
    let qdoc = roxmltree::Document::parse(&q.deliveries[0].1).unwrap();
    let id = qdoc.root_element().attribute("id").unwrap();
    let answer = format!(
        "<iq type='result' id='{id}'><query xmlns='http://jabber.org/protocol/disco#info'><feature var='storage:bookmarks+notify'/></query></iq>"
    );
    let doc = roxmltree::Document::parse(&answer).unwrap();
    pubsub::on_disco_result(
        d.path(),
        "example.test",
        "alice@example.test/old",
        doc.root_element(),
    )
    .unwrap();
    let publish = iq(
        "set",
        "alice@example.test",
        "<publish node='urn:xmpp:bookmarks:1'><item id='room@conference.example.test'><conference xmlns='urn:xmpp:bookmarks:1' name='Room' autojoin='true'><nick>Alice</nick></conference></item></publish>",
    );
    let doc = roxmltree::Document::parse(&publish).unwrap();
    let events = pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/new",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    let legacy = events
        .deliveries
        .iter()
        .find(|d| d.0 == "alice@example.test/old")
        .unwrap();
    assert!(legacy.1.contains("storage:bookmarks"));
    assert!(legacy.1.contains("jid='room@conference.example.test'"));
    assert!(legacy.1.contains("<nick>Alice</nick>"));
}
#[test]
fn remote_caps_replay_and_open_node_privacy_revoke() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    let create = iq(
        "set",
        "alice@example.test",
        "<create node='urn:test'/><configure><x xmlns='jabber:x:data' type='submit'><field var='pubsub#access_model'><value>open</value></field></x></configure>",
    );
    request(d.path(), "alice@example.test/r", &create);
    let p = iq(
        "set",
        "alice@example.test",
        "<publish node='urn:test'><item id='x'><x xmlns='urn:test'>remote payload</x></item></publish>",
    );
    request(d.path(), "alice@example.test/r", &p);
    let presence=roxmltree::Document::parse("<presence from='bob@remote.test/r' to='alice@example.test'><c xmlns='http://jabber.org/protocol/caps' node='client' ver='v' hash='sha-1'/></presence>").unwrap();
    assert!(
        pubsub::on_remote_presence(
            d.path(),
            "example.test",
            "bob@remote.test/r",
            presence.root_element()
        )
        .unwrap()
        .deliveries
        .is_empty()
    );
    let mut roster = V::table();
    let mut c = V::table();
    c.set("subscription", "from".into());
    roster.set("bob@remote.test", c);
    storage::save(d.path(), "example.test", Some("alice"), "roster", &roster).unwrap();
    let q = pubsub::on_remote_presence(
        d.path(),
        "example.test",
        "bob@remote.test/r",
        presence.root_element(),
    )
    .unwrap();
    assert_eq!(q.deliveries.len(), 1);
    let doc = roxmltree::Document::parse(&q.deliveries[0].1).unwrap();
    let id = doc.root_element().attribute("id").unwrap();
    let answer = format!(
        "<iq type='result' id='{id}'><query xmlns='http://jabber.org/protocol/disco#info'><feature var='urn:test+notify'/></query></iq>"
    );
    let doc = roxmltree::Document::parse(&answer).unwrap();
    assert!(
        pubsub::on_disco_result(
            d.path(),
            "example.test",
            "mallory@remote.test/r",
            doc.root_element()
        )
        .unwrap()
        .is_none()
    );
    let result = pubsub::on_disco_result(
        d.path(),
        "example.test",
        "bob@remote.test/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(result.deliveries.len(), 1);
    assert!(result.deliveries[0].1.contains("remote payload"));
    let doc = roxmltree::Document::parse(&p).unwrap();
    let result = pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(result.deliveries.iter().any(|e| e.0 == "bob@remote.test/r"));
    storage::save(
        d.path(),
        "example.test",
        Some("alice"),
        "roster",
        &V::table(),
    )
    .unwrap();
    let result = pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(!result.deliveries.iter().any(|e| e.0 == "bob@remote.test/r"));
}
#[test]
fn component_default_retention_matches_prosody_twenty_items() {
    let d = tempfile::tempdir().unwrap();
    let options = pubsub::Options {
        restrict_node_creation: false,
        ..Default::default()
    };
    let run = |xml: String| {
        let doc = roxmltree::Document::parse(&xml).unwrap();
        pubsub::handle_component_with_options(
            d.path(),
            "pubsub.example.test",
            "alice@example.test/r",
            &[],
            doc.root_element(),
            &options,
        )
        .unwrap()
        .unwrap()
    };
    run(iq("set", "pubsub.example.test", "<create node='n'/>"));
    for i in 0..22 {
        run(iq(
            "set",
            "pubsub.example.test",
            &format!("<publish node='n'><item id='{i}'><x xmlns='urn:test'/></item></publish>"),
        ));
    }
    let entries =
        rust_xmpp::archive::load_store(d.path(), "pubsub.example.test", None, "pubsub_n").unwrap();
    assert_eq!(entries.len(), 20);
    assert_eq!(entries[0].id, "2");
}
#[test]
fn remote_unavailable_is_scoped_to_addressed_owner_and_cancels_pending() {
    let d = tempfile::tempdir().unwrap();
    for owner in ["alice", "carol"] {
        account(d.path(), owner);
        let mut roster = V::table();
        let mut c = V::table();
        c.set("subscription", "from".into());
        roster.set("bob@remote.test", c);
        storage::save(d.path(), "example.test", Some(owner), "roster", &roster).unwrap();
    }
    let mut ids = vec![];
    for owner in ["alice", "carol"] {
        let p = format!(
            "<presence from='bob@remote.test/r' to='{owner}@example.test'><c xmlns='http://jabber.org/protocol/caps' ver='v'/></presence>"
        );
        let doc = roxmltree::Document::parse(&p).unwrap();
        let q = pubsub::on_remote_presence(
            d.path(),
            "example.test",
            "bob@remote.test/r",
            doc.root_element(),
        )
        .unwrap();
        let qdoc = roxmltree::Document::parse(&q.deliveries[0].1).unwrap();
        ids.push(qdoc.root_element().attribute("id").unwrap().to_owned());
    }
    let unavailable = roxmltree::Document::parse(
        "<presence from='bob@remote.test' to='alice@example.test' type='unavailable'/>",
    )
    .unwrap();
    pubsub::on_remote_presence(
        d.path(),
        "example.test",
        "bob@remote.test",
        unavailable.root_element(),
    )
    .unwrap();
    for (i, id) in ids.iter().enumerate() {
        let answer = format!(
            "<iq type='result' id='{id}'><query xmlns='http://jabber.org/protocol/disco#info'><feature var='urn:test+notify'/></query></iq>"
        );
        let doc = roxmltree::Document::parse(&answer).unwrap();
        let result = pubsub::on_disco_result(
            d.path(),
            "example.test",
            "bob@remote.test/r",
            doc.root_element(),
        )
        .unwrap();
        assert_eq!(result.is_some(), i == 1);
    }
    for owner in ["alice", "carol"] {
        let p = iq(
            "set",
            &format!("{owner}@example.test"),
            "<publish node='urn:test'><item id='x'><x xmlns='urn:test'/></item></publish>",
        );
        let doc = roxmltree::Document::parse(&p).unwrap();
        let r = pubsub::handle(
            d.path(),
            "example.test",
            &format!("{owner}@example.test/r"),
            doc.root_element(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            r.deliveries.iter().any(|e| e.0 == "bob@remote.test/r"),
            owner == "carol"
        );
    }
}

#[test]
fn payload_policy_applies_to_subscription_and_caps_replays() {
    for (node, advertised, payload) in [
        (
            "urn:test:private",
            "urn:test:private",
            "<secret xmlns='urn:test'>payload-secret</secret>",
        ),
        (
            "urn:xmpp:bookmarks:1",
            "storage:bookmarks",
            "<conference xmlns='urn:xmpp:bookmarks:1' name='payload-secret'/>",
        ),
    ] {
        let d = tempfile::tempdir().unwrap();
        account(d.path(), "alice");
        let create = iq(
            "set",
            "alice@example.test",
            &format!(
                "<create node='{node}'/><configure><x xmlns='jabber:x:data' type='submit'><field var='pubsub#include_payload'><value>0</value></field></x></configure>"
            ),
        );
        assert!(request(d.path(), "alice@example.test/r", &create).contains("type='result'"));
        let publish = iq(
            "set",
            "alice@example.test",
            &format!(
                "<publish node='{node}'><item id='room@conference.example.test'>{payload}</item></publish>"
            ),
        );
        assert!(request(d.path(), "alice@example.test/r", &publish).contains("type='result'"));
        let subscribe = iq(
            "set",
            "alice@example.test",
            &format!("<subscribe node='{node}' jid='alice@example.test/subscriber'/>"),
        );
        let doc = roxmltree::Document::parse(&subscribe).unwrap();
        let result = pubsub::handle(
            d.path(),
            "example.test",
            "alice@example.test/r",
            doc.root_element(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.deliveries.len(), 1);
        assert!(
            result.deliveries[0]
                .1
                .contains("<item id='room@conference.example.test'/>"),
            "{:?}",
            result.deliveries
        );
        assert!(!result.deliveries[0].1.contains("payload-secret"));

        let presence = roxmltree::Document::parse(
            "<presence><c xmlns='http://jabber.org/protocol/caps' ver='v'/></presence>",
        )
        .unwrap();
        let query = pubsub::on_presence(
            d.path(),
            "example.test",
            "alice@example.test/caps",
            presence.root_element(),
        )
        .unwrap();
        let query_doc = roxmltree::Document::parse(&query.deliveries[0].1).unwrap();
        let id = query_doc.root_element().attribute("id").unwrap();
        let answer = format!(
            "<iq type='result' id='{id}'><query xmlns='http://jabber.org/protocol/disco#info'><feature var='{advertised}+notify'/></query></iq>"
        );
        let doc = roxmltree::Document::parse(&answer).unwrap();
        let result = pubsub::on_disco_result(
            d.path(),
            "example.test",
            "alice@example.test/caps",
            doc.root_element(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.deliveries.len(), 1);
        assert!(
            !result.deliveries[0].1.contains("payload-secret"),
            "{:?}",
            result.deliveries
        );
        let doc = roxmltree::Document::parse(&publish).unwrap();
        let result = pubsub::handle(
            d.path(),
            "example.test",
            "alice@example.test/r",
            doc.root_element(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.deliveries.len(), 2);
        assert!(
            result
                .deliveries
                .iter()
                .all(|(_, xml)| !xml.contains("payload-secret"))
        );
        // Omitting notification payload does not discard the stored item.
        let get = iq(
            "get",
            "alice@example.test",
            &format!("<items node='{node}'/>"),
        );
        assert!(request(d.path(), "alice@example.test/r", &get).contains("payload-secret"));
    }
}

#[test]
fn publish_options_conflict_is_recoverable_and_preserves_item() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    let node = "urn:xmpp:omemo:2:devices";
    let publish = |value: &str, access: &str| {
        iq(
            "set",
            "alice@example.test",
            &format!(
                "<publish node='{node}'><item id='current'><devices xmlns='urn:xmpp:omemo:2'>{value}</devices></item></publish><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='pubsub#access_model'><value>{access}</value></field></x></publish-options>"
            ),
        )
    };
    assert!(
        request(
            d.path(),
            "alice@example.test/r",
            &publish("original", "presence")
        )
        .contains("type='result'")
    );
    let reply = request(
        d.path(),
        "alice@example.test/r",
        &publish("replacement", "open"),
    );
    let doc = roxmltree::Document::parse(&reply).unwrap();
    assert!(
        doc.descendants()
            .any(|n| n.has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", "conflict")))
    );
    assert!(doc.descendants().any(|n| n.has_tag_name((
        "http://jabber.org/protocol/pubsub#errors",
        "precondition-not-met"
    ))));
    let get = iq(
        "get",
        "alice@example.test",
        &format!("<items node='{node}'/>"),
    );
    let reply = request(d.path(), "alice@example.test/r", &get);
    assert!(reply.contains("original"));
    assert!(!reply.contains("replacement"));
}

#[test]
fn full_jid_block_applies_to_reads_subscription_replays_and_events() {
    let d = tempfile::tempdir().unwrap();
    account(d.path(), "alice");
    account(d.path(), "bob");
    let create = iq(
        "set",
        "alice@example.test",
        "<create node='n'/><configure><x xmlns='jabber:x:data' type='submit'><field var='pubsub#access_model'><value>open</value></field></x></configure>",
    );
    assert!(request(d.path(), "alice@example.test/r", &create).contains("type='result'"));
    let subscribe = iq(
        "set",
        "alice@example.test",
        "<subscribe node='n' jid='bob@example.test/blocked'/>",
    );
    assert!(request(d.path(), "bob@example.test/blocked", &subscribe).contains("subscribed"));
    let publish = iq(
        "set",
        "alice@example.test",
        "<publish node='n'><item id='one'><x xmlns='urn:test'>secret</x></item></publish>",
    );
    request(d.path(), "alice@example.test/r", &publish);
    let mut blocked = V::table();
    blocked.set("bob@example.test/blocked", V::Bool(true));
    storage::save(
        d.path(),
        "example.test",
        Some("alice"),
        "blocklist",
        &blocked,
    )
    .unwrap();
    let get = iq("get", "alice@example.test", "<items node='n'/>");
    assert!(request(d.path(), "bob@example.test/blocked", &get).contains("forbidden"));
    assert!(request(d.path(), "bob@example.test/allowed", &get).contains("secret"));
    // A different resource must not cause a replay to the blocked resource.
    assert!(request(d.path(), "bob@example.test/allowed", &subscribe).contains("forbidden"));
    let doc = roxmltree::Document::parse(&publish).unwrap();
    let result = pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(result.deliveries.is_empty(), "{:?}", result.deliveries);
}

#[test]
fn native_string_max_items_satisfies_numeric_publish_precondition() {
    for maximum in ["1", "max"] {
        let d = tempfile::tempdir().unwrap();
        account(d.path(), "alice");
        let mut config = V::table();
        config.set("max_items", maximum.into());
        let mut node = V::table();
        node.set("name", "urn:test:devices".into());
        node.set("config", config);
        let mut metadata = V::table();
        metadata.set("urn:test:devices", node);
        storage::save(d.path(), "example.test", Some("alice"), "pep", &metadata).unwrap();
        let publish = iq(
            "set",
            "alice@example.test",
            &format!(
                "<publish node='urn:test:devices'><item id='current'><devices xmlns='urn:test:devices'/></item></publish><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='pubsub#max_items'><value>{maximum}</value></field></x></publish-options>"
            ),
        );
        let result = request(d.path(), "alice@example.test/r", &publish);
        assert!(result.contains("type='result'"), "{result}");
    }
}

#[test]
fn native_notification_fields_and_retract_policy_are_independent() {
    for component in [false, true] {
        let d = tempfile::tempdir().unwrap();
        account(d.path(), "alice");
        let target = if component {
            "pubsub.example.test"
        } else {
            "alice@example.test"
        };
        let options = pubsub::Options {
            restrict_node_creation: false,
            ..Default::default()
        };
        let run = |actor: &str, xml: &str| {
            let doc = roxmltree::Document::parse(xml).unwrap();
            if component {
                pubsub::handle_component_with_options(
                    d.path(),
                    target,
                    actor,
                    &[],
                    doc.root_element(),
                    &options,
                )
            } else {
                pubsub::handle(d.path(), "example.test", actor, doc.root_element())
            }
            .unwrap()
            .unwrap()
        };
        let create = iq(
            "set",
            target,
            "<create node='n'/><configure><x xmlns='jabber:x:data' type='submit'><field var='pubsub#access_model'><value>open</value></field><field var='pubsub#deliver_notifications'><value>0</value></field><field var='pubsub#deliver_payloads'><value>0</value></field><field var='pubsub#notify_retract'><value>1</value></field></x></configure>",
        );
        assert!(run("alice@example.test/r", &create).replies[0].contains("type='result'"));
        run(
            "bob@example.test/r",
            &iq(
                "set",
                target,
                "<subscribe node='n' jid='bob@example.test/r'/>",
            ),
        );
        let publish = iq(
            "set",
            target,
            "<publish node='n'><item id='one'><x xmlns='urn:test'>secret</x></item></publish>",
        );
        let retract = iq(
            "set",
            target,
            "<retract node='n' notify='true'><item id='one'/></retract>",
        );
        assert!(run("alice@example.test/r", &publish).deliveries.is_empty());
        let result = run("alice@example.test/r", &retract);
        assert_eq!(result.deliveries.len(), 1, "{:?}", result);
        assert!(
            result.deliveries[0]
                .1
                .contains("<items node='n'><retract id='one'/></items>")
        );

        let configure = format!(
            "<iq type='set' to='{target}'><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure node='n'><x xmlns='jabber:x:data' type='submit'><field var='pubsub#deliver_notifications'><value>1</value></field><field var='pubsub#notify_retract'><value>0</value></field></x></configure></pubsub></iq>"
        );
        run("alice@example.test/r", &configure);
        let result = run("alice@example.test/r", &publish);
        assert_eq!(result.deliveries.len(), 1);
        assert!(!result.deliveries[0].1.contains("secret"));
        assert!(run("alice@example.test/r", &retract).deliveries.is_empty());
        let get = format!(
            "<iq type='get' to='{target}'><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure node='n'/></pubsub></iq>"
        );
        let result = run("alice@example.test/r", &get);
        assert!(result.replies[0].contains("pubsub#deliver_notifications"));
        assert!(result.replies[0].contains("pubsub#deliver_payloads"));
        assert!(!result.replies[0].contains("pubsub#notify_items"));
        assert!(!result.replies[0].contains("pubsub#include_payload"));
    }
}
