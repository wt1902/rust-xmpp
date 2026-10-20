use rust_xmpp::{
    config::{Config, Host},
    extras,
};
use serde_json::json;
use std::time::Instant;

fn config() -> Config {
    let mut config = Config::default();
    config.hosts.insert("example.test".into(), Host::default());
    config
        .global
        .insert("modules_enabled".into(), json!(["seclabels"]));
    config
}

fn request(config: &Config, namespace: &str, extra: &str) -> String {
    request_at(config, "example.test", namespace, extra)
}

fn request_at(config: &Config, domain: &str, namespace: &str, extra: &str) -> String {
    let xml = format!(
        "<iq type='get' id='catalog-1' to='{domain}'><catalog xmlns='{namespace}'{extra}/></iq>"
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    extras::handle(config, domain, document.root_element(), Instant::now())
        .unwrap()
        .unwrap()
        .replies
        .remove(0)
}

#[test]
fn security_catalogs_serve_both_versions_and_preserve_requested_target() {
    let mut config = config();
    config
        .global
        .insert("security_catalog_name".into(), json!("Team & partners"));
    config.global.insert("security_labels".into(), json!({
        "Classified": {"SECRET": {
            "label": "<esssecuritylabel xmlns='urn:example:policy'><classification>SECRET</classification></esssecuritylabel>",
            "display": "Secret & restricted", "color": "black", "bgcolor": "aqua", "default": true
        }}
    }));
    for namespace in [
        "urn:xmpp:sec-label:catalog:2",
        "urn:xmpp:sec-label:catalog:0",
    ] {
        let response = request(&config, namespace, " to='friend@example.test' ");
        let document = roxmltree::Document::parse(&response).unwrap();
        let iq = document.root_element();
        assert_eq!(iq.attribute("type"), Some("result"));
        assert_eq!(iq.attribute("id"), Some("catalog-1"));
        let catalog = iq.first_element_child().unwrap();
        assert_eq!(catalog.tag_name().namespace(), Some(namespace));
        assert_eq!(catalog.attribute("to"), Some("friend@example.test"));
        assert_eq!(catalog.attribute("name"), Some("Team & partners"));
        let item = catalog.first_element_child().unwrap();
        assert_eq!(item.attribute("selector"), Some("Classified|SECRET"));
        assert_eq!(item.attribute("default"), Some("true"));
        let label = if namespace.ends_with(":2") {
            assert_eq!(item.tag_name().name(), "item");
            item.first_element_child().unwrap()
        } else {
            item
        };
        assert_eq!(label.tag_name().name(), "securitylabel");
        assert_eq!(label.tag_name().namespace(), Some("urn:xmpp:sec-label:0"));
        let display = label.first_element_child().unwrap();
        assert_eq!(display.text(), Some("Secret & restricted"));
        assert_eq!(display.attribute("fgcolor"), Some("black"));
        assert_eq!(display.attribute("bgcolor"), Some("aqua"));
        assert!(
            label
                .descendants()
                .any(|node| node.has_tag_name(("urn:example:policy", "esssecuritylabel")))
        );
    }
}

#[test]
fn security_catalog_default_is_a_real_label_and_module_can_be_disabled() {
    let mut config = config();
    let response = request(&config, "urn:xmpp:sec-label:catalog:2", "");
    let document = roxmltree::Document::parse(&response).unwrap();
    let item = document
        .descendants()
        .find(|n| n.has_tag_name(("urn:xmpp:sec-label:catalog:2", "item")))
        .unwrap();
    assert_eq!(item.attribute("selector"), Some("Unclassified"));
    assert_eq!(item.attribute("default"), Some("true"));
    assert!(
        item.descendants()
            .any(|n| n.has_tag_name(("urn:xmpp:sec-label:0", "label"))
                && n.text() == Some("Unclassified"))
    );
    config.global.insert("modules_enabled".into(), json!([]));
    let document = roxmltree::Document::parse(
        "<iq type='get'><catalog xmlns='urn:xmpp:sec-label:catalog:2'/></iq>",
    )
    .unwrap();
    assert!(
        extras::handle(
            &config,
            "example.test",
            document.root_element(),
            Instant::now()
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn unsupported_security_policy_configuration_returns_explicit_error() {
    let mut config = config();
    config
        .global
        .insert("security_labels".into(), json!({"policies": ["SECRET"]}));
    let response = request(&config, "urn:xmpp:sec-label:catalog:2", "");
    let document = roxmltree::Document::parse(&response).unwrap();
    assert_eq!(document.root_element().attribute("type"), Some("error"));
    assert!(
        document
            .descendants()
            .any(|n| n.has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", "not-acceptable")))
    );
}

#[test]
fn actual_example_policy_configuration_exposes_classifications_as_catalog_labels() {
    let config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    for namespace in [
        "urn:xmpp:sec-label:catalog:2",
        "urn:xmpp:sec-label:catalog:0",
    ] {
        let response = request_at(&config, "wthome.ru", namespace, " to='wt@wthome.ru'");
        let document = roxmltree::Document::parse(&response).unwrap();
        assert_eq!(document.root_element().attribute("type"), Some("result"));
        let catalog = document.root_element().first_element_child().unwrap();
        assert_eq!(catalog.attribute("to"), Some("wt@wthome.ru"));
        let entries: Vec<_> = catalog
            .children()
            .filter(|node| node.is_element())
            .collect();
        let names = ["Unclassified", "Confidential", "Secret", "Top Secret"];
        assert_eq!(entries.len(), names.len());
        for (index, (entry, name)) in entries.iter().zip(names).enumerate() {
            assert_eq!(entry.attribute("selector"), Some(name));
            assert_eq!(entry.attribute("default"), (index == 0).then_some("true"));
            let label = entry
                .descendants()
                .find(|node| node.has_tag_name(("urn:xmpp:sec-label:0", "label")))
                .unwrap();
            assert_eq!(label.text(), Some(name));
        }
    }
}

#[test]
fn policy_catalog_selects_default_policy_and_maps_display_and_explicit_label() {
    let mut config = config();
    config.global.insert("security_labels".into(), json!({
        "default_policy": "selected", "policies": {
            "other": {"classifications": [{"name": "Other"}]},
            "selected": {"classifications": [{"name": "Secret", "label": "CLASSIFIED", "display": "Restricted", "color": "black", "bgcolor": "red", "default": true}]}
        }
    }));
    let response = request(&config, "urn:xmpp:sec-label:catalog:2", "");
    let document = roxmltree::Document::parse(&response).unwrap();
    let item = document
        .descendants()
        .find(|node| node.has_tag_name(("urn:xmpp:sec-label:catalog:2", "item")))
        .unwrap();
    assert_eq!(item.attribute("selector"), Some("Secret"));
    assert_eq!(item.attribute("default"), Some("true"));
    let display = item
        .descendants()
        .find(|node| node.has_tag_name(("urn:xmpp:sec-label:0", "displaymarking")))
        .unwrap();
    assert_eq!(display.text(), Some("Restricted"));
    assert_eq!(display.attribute("fgcolor"), Some("black"));
    assert_eq!(display.attribute("bgcolor"), Some("red"));
    assert!(
        item.descendants()
            .any(|node| node.has_tag_name(("urn:xmpp:sec-label:0", "label"))
                && node.text() == Some("CLASSIFIED"))
    );
    assert!(!response.contains("Other"));
}

#[test]
fn malformed_or_unknown_policy_catalog_schemas_are_rejected() {
    let cases = [
        json!({"policies": {}}),
        json!({"default_policy": "default", "policies": {}}),
        json!({"default_policy": "default", "policies": []}),
        json!({"default_policy": "default", "policies": {"default": {}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": {}}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": [{}]}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": [{"name": "  "}]}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": [{"name": 1}]}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": [{"name": "Public", "default": "yes"}]}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": [{"name": "Public", "color": 1}]}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": [{"name": "Public", "label": false}]}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": [{"name": "Public", "label": "<invalid"}]}}}),
        json!({"default_policy": "default", "enforce": true, "policies": {"default": {"classifications": []}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": [], "members": ["alice"]}}}),
        json!({"default_policy": "default", "policies": {"default": {"classifications": [{"name": "Secret", "acl": "admins"}]}}}),
    ];
    for value in cases {
        let mut config = config();
        config
            .global
            .insert("security_labels".into(), value.clone());
        for namespace in [
            "urn:xmpp:sec-label:catalog:2",
            "urn:xmpp:sec-label:catalog:0",
        ] {
            let response = request(&config, namespace, "");
            let document = roxmltree::Document::parse(&response).unwrap();
            assert_eq!(
                document.root_element().attribute("type"),
                Some("error"),
                "{value}"
            );
            assert!(
                document.descendants().any(|node| node
                    .has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", "not-acceptable"))),
                "{value}"
            );
        }
    }
}
