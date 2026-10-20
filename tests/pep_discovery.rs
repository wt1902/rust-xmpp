use rust_xmpp::pubsub;
use std::path::Path;

fn account(root: &Path) {
    rust_xmpp::auth::create(root, "example.test", "alice", "secret", "SHA-256").unwrap();
}

fn query(root: &Path, actor: &str, to: &str, namespace: &str, node: Option<&str>) -> String {
    let node = node.map(|n| format!(" node='{n}'")).unwrap_or_default();
    let xml =
        format!("<iq type='get' id='disco' to='{to}'><query xmlns='{namespace}'{node}/></iq>");
    let doc = roxmltree::Document::parse(&xml).unwrap();
    pubsub::handle(root, "example.test", actor, doc.root_element())
        .unwrap()
        .unwrap()
        .replies
        .join("")
}

#[test]
fn account_disco_advertises_pep_without_requiring_a_node() {
    let d = tempfile::tempdir().unwrap();
    account(d.path());
    for actor in ["alice@example.test/phone", "bob@remote.test/phone"] {
        let reply = query(
            d.path(),
            actor,
            "alice@example.test",
            "http://jabber.org/protocol/disco#info",
            None,
        );
        let doc = roxmltree::Document::parse(&reply).unwrap();
        assert!(doc.descendants().any(|n| n.tag_name().name() == "identity"
            && n.attribute("category") == Some("pubsub")
            && n.attribute("type") == Some("pep")));
        assert!(
            !doc.descendants()
                .any(|n| n.attribute("category") == Some("server"))
        );
        for feature in [
            "auto-create",
            "auto-subscribe",
            "filtered-notifications",
            "create-and-configure",
            "publish-options",
            "persistent-items",
        ] {
            let feature = format!("http://jabber.org/protocol/pubsub#{feature}");
            assert!(
                doc.descendants().any(|n| n.tag_name().name() == "feature"
                    && n.attribute("var") == Some(feature.as_str())),
                "missing {feature}"
            );
        }
        for feature in [
            "http://jabber.org/protocol/disco#info",
            "http://jabber.org/protocol/disco#items",
        ] {
            assert!(
                doc.descendants()
                    .any(|n| n.attribute("var") == Some(feature))
            );
        }
    }
    assert!(
        query(
            d.path(),
            "alice@example.test/phone",
            "missing@example.test",
            "http://jabber.org/protocol/disco#info",
            None
        )
        .contains("item-not-found")
    );
}

#[test]
fn account_discovery_does_not_intercept_server_or_resource_caps() {
    let d = tempfile::tempdir().unwrap();
    account(d.path());
    for target in [
        None,
        Some("example.test"),
        Some("alice@example.test/phone"),
        Some("alice@remote.test"),
    ] {
        let to = target.map(|t| format!(" to='{t}'")).unwrap_or_default();
        let xml = format!(
            "<iq type='get' id='disco'{to}><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        assert!(
            pubsub::handle(
                d.path(),
                "example.test",
                "alice@example.test/phone",
                doc.root_element()
            )
            .unwrap()
            .is_none()
        );
    }
}

#[test]
fn node_discovery_keeps_node_identity_errors_and_access_checks() {
    let d = tempfile::tempdir().unwrap();
    account(d.path());
    let create = "<iq type='set' id='create' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='private'/></pubsub></iq>";
    let create_doc = roxmltree::Document::parse(create).unwrap();
    let created = pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/phone",
        create_doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(!created.replies[0].contains("type='error'"));
    let xml = "<iq type='set' id='publish' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='private'><item id='one'><data xmlns='urn:test'/></item></publish></pubsub></iq>";
    let doc = roxmltree::Document::parse(xml).unwrap();
    pubsub::handle(
        d.path(),
        "example.test",
        "alice@example.test/phone",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    for namespace in [
        "http://jabber.org/protocol/disco#info",
        "http://jabber.org/protocol/disco#items",
    ] {
        let denied = query(
            d.path(),
            "bob@remote.test/phone",
            "alice@example.test",
            namespace,
            Some("private"),
        );
        assert!(denied.contains("forbidden"));
        assert!(!denied.contains("name='one'"));
        assert!(
            query(
                d.path(),
                "alice@example.test/phone",
                "alice@example.test",
                namespace,
                Some("missing")
            )
            .contains("item-not-found")
        );
        let listed = query(
            d.path(),
            "bob@remote.test/phone",
            "alice@example.test",
            namespace,
            None,
        );
        assert!(!listed.contains("node='private'"));
    }
    let info = query(
        d.path(),
        "alice@example.test/phone",
        "alice@example.test",
        "http://jabber.org/protocol/disco#info",
        Some("private"),
    );
    assert!(info.contains("node='private'"));
    assert!(info.contains("type='leaf'"));
    assert!(!info.contains("type='pep'"));
}

#[test]
fn standalone_component_does_not_claim_pep_automatic_subscriptions() {
    let d = tempfile::tempdir().unwrap();
    let doc = roxmltree::Document::parse("<iq type='get' id='disco' to='pubsub.example.test'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>").unwrap();
    let reply = pubsub::handle_component(
        d.path(),
        "pubsub.example.test",
        "alice@example.test/phone",
        &[],
        doc.root_element(),
    )
    .unwrap()
    .unwrap()
    .replies
    .join("");
    assert!(reply.contains("type='service'"));
    assert!(!reply.contains("type='pep'"));
    for feature in ["auto-create", "auto-subscribe", "filtered-notifications"] {
        assert!(!reply.contains(&format!("pubsub#{feature}")));
    }
}
