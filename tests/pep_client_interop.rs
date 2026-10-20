//! Wire-level PEP requests used by Conversations/monocles. This exercises the
//! server handlers; it does not claim Android device interoperability validation.
use rust_xmpp::{
    auth,
    protocol::ModuleResult,
    pubsub,
    storage::{self, LuaValue as V},
};
use std::path::Path;

fn request(root: &Path, actor: &str, stanza: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(stanza).unwrap();
    pubsub::handle(root, "example.test", actor, doc.root_element())
        .unwrap()
        .unwrap()
}
fn account(root: &Path) {
    auth::create(root, "example.test", "alice", "secret", "SHA-256").unwrap();
}
fn publish(root: &Path, node: &str, id: &str, payload: &str, fields: &str) -> ModuleResult {
    request(
        root,
        "alice@example.test/phone",
        &format!(
            "<iq type='set' id='publish'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='{node}'><item id='{id}'>{payload}</item></publish><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>{fields}</x></publish-options></pubsub></iq>"
        ),
    )
}
fn assert_payload(stanza: &str, payload: &str) {
    fn same(actual: roxmltree::Node<'_, '_>, expected: roxmltree::Node<'_, '_>) {
        assert_eq!(actual.tag_name(), expected.tag_name());
        let attrs = |n: roxmltree::Node<'_, '_>| {
            n.attributes()
                .map(|a| {
                    (
                        a.namespace().unwrap_or("").to_owned(),
                        a.name().to_owned(),
                        a.value().to_owned(),
                    )
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(attrs(actual), attrs(expected));
        let actual: Vec<_> = actual
            .children()
            .filter(|n| n.is_element() || n.is_text())
            .collect();
        let expected: Vec<_> = expected
            .children()
            .filter(|n| n.is_element() || n.is_text())
            .collect();
        assert_eq!(actual.len(), expected.len());
        for (a, e) in actual.into_iter().zip(expected) {
            if e.is_element() {
                same(a, e);
            } else {
                assert_eq!(a.text(), e.text());
            }
        }
    }
    let actual = roxmltree::Document::parse(stanza).unwrap();
    let expected = roxmltree::Document::parse(payload).unwrap();
    let e = expected.root_element();
    let a = actual
        .descendants()
        .find(|n| n.is_element() && n.tag_name() == e.tag_name())
        .unwrap();
    same(a, e);
}
const OPEN: &str = "<field var='pubsub#access_model'><value>open</value></field>";

#[test]
fn missing_own_omemo_bundle_returns_recoverable_item_not_found() {
    let d = tempfile::tempdir().unwrap();
    account(d.path());
    // Monocles latches pepBroken for other errors in this initial lookup.
    for node in [
        "urn:xmpp:omemo:2:bundles",
        "eu.siacs.conversations.axolotl.bundles:42",
    ] {
        let result = request(
            d.path(),
            "alice@example.test/phone",
            &format!(
                "<iq type='get' id='bundle' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='{node}'><item id='42'/></items></pubsub></iq>"
            ),
        );
        let doc = roxmltree::Document::parse(&result.replies[0]).unwrap();
        assert_eq!(doc.root_element().attribute("type"), Some("error"));
        assert!(
            doc.descendants()
                .any(|n| n.has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", "item-not-found")))
        );
    }
}

#[test]
fn avatar_and_omemo_publish_options_support_readback_and_caps_notifications() {
    let d = tempfile::tempdir().unwrap();
    account(d.path());
    let presence = roxmltree::Document::parse("<presence><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='urn:test:client' ver='caps'/></presence>").unwrap();
    let caps = pubsub::on_presence(
        d.path(),
        "example.test",
        "alice@example.test/laptop",
        presence.root_element(),
    )
    .unwrap();
    let caps_doc = roxmltree::Document::parse(&caps.deliveries[0].1).unwrap();
    let id = caps_doc.root_element().attribute("id").unwrap();
    let answer = format!(
        "<iq type='result' id='{id}'><query xmlns='http://jabber.org/protocol/disco#info'><feature var='urn:xmpp:avatar:metadata+notify'/><feature var='eu.siacs.conversations.axolotl.devicelist+notify'/></query></iq>"
    );
    let answer = roxmltree::Document::parse(&answer).unwrap();
    pubsub::on_disco_result(
        d.path(),
        "example.test",
        "alice@example.test/laptop",
        answer.root_element(),
    )
    .unwrap()
    .unwrap();
    for (node, id, payload, notify) in [
        (
            "urn:xmpp:avatar:data",
            "avatar-hash",
            "<data xmlns='urn:xmpp:avatar:data'>aW1hZ2U=</data>",
            false,
        ),
        (
            "urn:xmpp:avatar:metadata",
            "avatar-hash",
            "<metadata xmlns='urn:xmpp:avatar:metadata'><info id='avatar-hash' bytes='5' type='image/png'/></metadata>",
            true,
        ),
        (
            "eu.siacs.conversations.axolotl.devicelist",
            "current",
            "<list xmlns='eu.siacs.conversations.axolotl'><device id='42'/></list>",
            true,
        ),
        (
            "urn:xmpp:omemo:2:bundles",
            "42",
            "<bundle xmlns='urn:xmpp:omemo:2'><ik>test-key</ik></bundle>",
            false,
        ),
    ] {
        let result = publish(d.path(), node, id, payload, OPEN);
        assert!(
            result.replies[0].contains("type='result'"),
            "{:?}",
            result.replies
        );
        assert_eq!(result.deliveries.len(), usize::from(notify));
        if notify {
            assert_eq!(result.deliveries[0].0, "alice@example.test/laptop");
            assert_payload(&result.deliveries[0].1, payload);
        }
        let read = request(
            d.path(),
            "bob@remote.test/phone",
            &format!(
                "<iq type='get' id='read' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='{node}'><item id='{id}'/></items></pubsub></iq>"
            ),
        );
        assert_payload(&read.replies[0], payload);
    }
}

#[test]
fn publish_options_match_implicit_notification_defaults_on_old_nodes() {
    let d = tempfile::tempdir().unwrap();
    account(d.path());
    let mut nodes = V::table();
    let mut node = V::table();
    node.set("name", "urn:test:existing".into());
    // Native and earlier Rust stores can omit default-valued config fields.
    node.set("config", V::table());
    nodes.set("urn:test:existing", node);
    storage::save(d.path(), "example.test", Some("alice"), "pep", &nodes).unwrap();
    let fields = [
        "deliver_notifications",
        "deliver_payloads",
        "notify_delete",
        "notify_retract",
    ]
    .into_iter()
    .map(|key| format!("<field var='pubsub#{key}'><value>true</value></field>"))
    .collect::<String>();
    let result = publish(
        d.path(),
        "urn:test:existing",
        "current",
        "<data xmlns='urn:test'>new</data>",
        &fields,
    );
    assert!(
        result.replies[0].contains("type='result'"),
        "{:?}",
        result.replies
    );
    let result = publish(
        d.path(),
        "urn:test:existing",
        "current",
        "<data xmlns='urn:test'>bad</data>",
        "<field var='pubsub#deliver_payloads'><value>false</value></field>",
    );
    assert!(result.replies[0].contains("precondition-not-met"));
    let read = request(
        d.path(),
        "alice@example.test/phone",
        "<iq type='get' id='read'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:test:existing'/></pubsub></iq>",
    );
    assert!(read.replies[0].contains(">new</data>"));
    assert!(!read.replies[0].contains(">bad</data>"));
}

fn owner_config(root: &Path, actor: &str, node: &str, fields: &str) -> ModuleResult {
    request(
        root,
        actor,
        &format!(
            "<iq type='set' id='configure'><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure node='{node}'><x xmlns='jabber:x:data' type='submit'>{fields}</x></configure></pubsub></iq>"
        ),
    )
}

#[test]
fn migrated_native_configuration_can_roundtrip_access_model_edit() {
    let d = tempfile::tempdir().unwrap();
    account(d.path());
    let path = storage::path(d.path(), "example.test", Some("alice"), "pep");
    storage::atomic_write(&path, b"return { ['urn:test:migrated']={name='urn:test:migrated';config={access_model='presence';notification_type='headline';itemreply='none';payload_type='urn:test:data';type='urn:stale:alias';publish_model='publishers';max_items=1};subscribers={};affiliations={['alice@example.test']='owner'}}};").unwrap();
    let get = request(
        d.path(),
        "alice@example.test/phone",
        "<iq type='get' id='get-config'><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure node='urn:test:migrated'/></pubsub></iq>",
    );
    assert!(!get.replies[0].contains("pubsub#payload_type"));
    assert!(get.replies[0].contains("pubsub#type"));
    let doc = roxmltree::Document::parse(&get.replies[0]).unwrap();
    assert_eq!(
        doc.descendants()
            .filter(|n| n.attribute("var") == Some("pubsub#type"))
            .count(),
        1
    );
    let form = doc
        .descendants()
        .find(|n| n.has_tag_name(("jabber:x:data", "x")))
        .unwrap();
    let form = rust_xmpp::protocol::xml(form)
        .replace("type='form'", "type='submit'")
        .replace(">presence<", ">open<");
    let set = request(
        d.path(),
        "alice@example.test/phone",
        &format!(
            "<iq type='set' id='set-config'><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure node='urn:test:migrated'>{form}</configure></pubsub></iq>"
        ),
    );
    assert!(
        set.replies[0].contains("type='result'"),
        "{:?}",
        set.replies
    );
    let metadata = storage::load(d.path(), "example.test", Some("alice"), "pep")
        .unwrap()
        .unwrap();
    let config = metadata
        .get("urn:test:migrated")
        .unwrap()
        .get("config")
        .unwrap();
    assert_eq!(config.get("access_model").and_then(V::as_str), Some("open"));
    assert!(config.get("type").is_none());
    assert_eq!(
        config.get("payload_type").and_then(V::as_str),
        Some("urn:test:data")
    );
    assert_eq!(
        config.get("notification_type").and_then(V::as_str),
        Some("headline")
    );
    assert_eq!(config.get("itemreply").and_then(V::as_str), Some("none"));
    for (key, value) in [
        ("notification_type", "chat"),
        ("itemreply", "everyone"),
        ("publish_model", "anyone"),
    ] {
        let bad = owner_config(
            d.path(),
            "alice@example.test/phone",
            "urn:test:migrated",
            &format!("<field var='pubsub#{key}'><value>{value}</value></field>"),
        );
        assert!(
            bad.replies[0].contains("not-acceptable"),
            "{:?}",
            bad.replies
        );
    }
}

#[test]
fn native_itemreply_controls_publisher_visibility_in_reads_and_replays() {
    let d = tempfile::tempdir().unwrap();
    account(d.path());
    for reply in ["none", "owner", "publisher"] {
        let fields = format!("{OPEN}<field var='pubsub#itemreply'><value>{reply}</value></field>");
        let node = format!("urn:test:{reply}");
        assert!(
            publish(
                d.path(),
                &node,
                "current",
                "<data xmlns='urn:test'>value</data>",
                &fields
            )
            .replies[0]
                .contains("type='result'")
        );
        let read = request(
            d.path(),
            "bob@remote.test/phone",
            &format!(
                "<iq type='get' id='read' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='{node}'/></pubsub></iq>"
            ),
        );
        let replay = request(
            d.path(),
            "bob@remote.test/phone",
            &format!(
                "<iq type='set' id='sub' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='{node}' jid='bob@remote.test/phone'/></pubsub></iq>"
            ),
        );
        assert_eq!(replay.deliveries.len(), 1);
        let event = publish(
            d.path(),
            &node,
            "current",
            "<data xmlns='urn:test'>update</data>",
            &fields,
        );
        assert_eq!(event.deliveries.len(), 1);
        for stanza in [
            &read.replies[0],
            &replay.deliveries[0].1,
            &event.deliveries[0].1,
        ] {
            let doc = roxmltree::Document::parse(stanza).unwrap();
            let item = doc
                .descendants()
                .find(|n| n.is_element() && n.tag_name().name() == "item")
                .unwrap();
            assert_eq!(
                item.attribute("publisher"),
                (reply == "publisher").then_some("alice@example.test")
            );
        }
    }
}

#[test]
fn native_component_notification_type_applies_to_events_and_subscription_replay() {
    let d = tempfile::tempdir().unwrap();
    let call = |actor: &str, xml: &str| {
        let doc = roxmltree::Document::parse(xml).unwrap();
        pubsub::handle_component(
            d.path(),
            "pubsub.example.test",
            actor,
            &["alice@example.test".into()],
            doc.root_element(),
        )
        .unwrap()
        .unwrap()
    };
    for kind in ["normal", "headline"] {
        let result = call(
            "alice@example.test/phone",
            &format!(
                "<iq type='set' id='create'><pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='{kind}'/><configure><x xmlns='jabber:x:data' type='submit'><field var='pubsub#notification_type'><value>{kind}</value></field><field var='pubsub#send_last_published_item'><value>on_sub</value></field></x></configure></pubsub></iq>"
            ),
        );
        assert!(result.replies[0].contains("type='result'"));
        let publish = format!(
            "<iq type='set' id='publish'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='{kind}'><item id='one'><data xmlns='urn:test'/></item></publish></pubsub></iq>"
        );
        call("alice@example.test/phone", &publish);
        let replay = call(
            "bob@remote.test/phone",
            &format!(
                "<iq type='set' id='sub'><pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='{kind}' jid='bob@remote.test/phone'/></pubsub></iq>"
            ),
        );
        let event = call("alice@example.test/phone", &publish);
        for result in [replay, event] {
            assert_eq!(result.deliveries.len(), 1);
            let doc = roxmltree::Document::parse(&result.deliveries[0].1).unwrap();
            assert_eq!(doc.root_element().attribute("type"), Some(kind));
        }
    }
}

#[test]
fn native_open_and_subscriber_publish_models_preserve_outcast_and_blocking_checks() {
    let d = tempfile::tempdir().unwrap();
    account(d.path());
    auth::create(d.path(), "example.test", "bob", "secret", "SHA-256").unwrap();
    for model in ["open", "subscribers"] {
        let node = format!("urn:test:{model}");
        let fields =
            format!("{OPEN}<field var='pubsub#publish_model'><value>{model}</value></field>");
        assert!(
            publish(
                d.path(),
                &node,
                "current",
                "<data xmlns='urn:test'/>",
                &fields
            )
            .replies[0]
                .contains("type='result'")
        );
        let write = format!(
            "<iq type='set' id='write' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='{node}'><item id='bob'><data xmlns='urn:test'/></item></publish></pubsub></iq>"
        );
        let initial = request(d.path(), "bob@example.test/phone", &write);
        assert_eq!(
            initial.replies[0].contains("type='result'"),
            model == "open"
        );
        let sub = format!(
            "<iq type='set' id='sub' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='{node}' jid='bob@example.test/phone'/></pubsub></iq>"
        );
        request(d.path(), "bob@example.test/phone", &sub);
        assert!(
            request(d.path(), "bob@example.test/phone", &write).replies[0]
                .contains("type='result'")
        );
        let mut metadata = storage::load(d.path(), "example.test", Some("alice"), "pep")
            .unwrap()
            .unwrap();
        let mut entry = metadata.get(&node).unwrap().clone();
        let mut affiliations = entry.get("affiliations").unwrap().clone();
        affiliations.set("bob@example.test", "outcast".into());
        entry.set("affiliations", affiliations);
        metadata.set(&node, entry);
        storage::save(d.path(), "example.test", Some("alice"), "pep", &metadata).unwrap();
        assert!(
            request(d.path(), "bob@example.test/phone", &write).replies[0].contains("forbidden")
        );
        let mut metadata = storage::load(d.path(), "example.test", Some("alice"), "pep")
            .unwrap()
            .unwrap();
        let mut entry = metadata.get(&node).unwrap().clone();
        entry.set("affiliations", V::table());
        metadata.set(&node, entry);
        storage::save(d.path(), "example.test", Some("alice"), "pep", &metadata).unwrap();
        let mut blocked = V::table();
        blocked.set("bob@example.test", V::Bool(true));
        storage::save(
            d.path(),
            "example.test",
            Some("alice"),
            "blocklist",
            &blocked,
        )
        .unwrap();
        assert!(
            request(d.path(), "bob@example.test/phone", &write).replies[0].contains("forbidden")
        );
        storage::save(
            d.path(),
            "example.test",
            Some("alice"),
            "blocklist",
            &V::table(),
        )
        .unwrap();
    }
}
