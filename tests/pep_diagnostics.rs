use rust_xmpp::pep_diagnostics::{event_fields, item_fields};
use std::collections::BTreeMap;

fn item(xml: &str) -> BTreeMap<&'static str, String> {
    let doc = roxmltree::Document::parse(xml).unwrap();
    item_fields(doc.root_element()).into_iter().collect()
}

#[test]
fn nonempty_xml_can_be_an_empty_android_device_list() {
    let fields = item(
        "<items xmlns='http://jabber.org/protocol/pubsub'><item><list xmlns='eu.siacs.conversations.axolotl'><device id='2147483648'/><device id='bad-secret-id'/><device/><device id=' 123'/></list></item></items>",
    );
    assert_eq!(fields["device_protocol"], "legacy");
    assert_eq!(fields["valid_device_count"], "0");
    assert_eq!(fields["invalid_device_count"], "4");
    assert!(!format!("{fields:?}").contains("bad-secret-id"));
}

#[test]
fn signed_integer_limits_and_duplicates_match_java_parser() {
    let fields = item(
        "<items><item><list xmlns='eu.siacs.conversations.axolotl'><device id='2147483647'/><device id='-2147483648'/><device id='-2147483649'/><device id='+1'/><device id='01'/><device id='١'/><device id='１'/><device id='0'/><device id='-0'/><device id='+'/><device id='1 '/><device id='𝟙'/></list></item></items>",
    );
    assert_eq!(fields["valid_device_count"], "4");
    assert_eq!(fields["invalid_device_count"], "4");
}

#[test]
fn payloadless_notification_is_visible_without_identifiers() {
    let doc = roxmltree::Document::parse("<message from='private@example.test' to='secret@example.test/resource'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='eu.siacs.conversations.axolotl.devicelist'><item id='private-item'/></items></event></message>").unwrap();
    let fields: BTreeMap<_, _> = event_fields(doc.root_element())
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(fields["node_kind"], "omemo-devices");
    assert_eq!(fields["items_count"], "1");
    assert_eq!(fields["content_present"], "false");
    assert_eq!(fields["valid_device_count"], "0");
    assert_eq!(fields["device_protocol"], "other");
    let rendered = format!("{fields:?}");
    for secret in ["private", "secret", "resource", "devicelist"] {
        assert!(!rendered.contains(secret));
    }
}

#[test]
fn only_first_direct_item_is_parsed_and_protocols_are_distinct() {
    let doc = roxmltree::Document::parse("<message><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:xmpp:omemo:2:devices'><item><devices xmlns='urn:xmpp:omemo:2'><device id='8'/><device id='8'/><wrapper><device id='9'/></wrapper></devices></item><item><devices xmlns='urn:xmpp:omemo:2'><device id='10'/></devices></item></items></event></message>").unwrap();
    let fields: BTreeMap<_, _> = event_fields(doc.root_element())
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(fields["device_protocol"], "omemo2");
    assert_eq!(fields["items_count"], "2");
    assert_eq!(fields["content_present"], "true");
    assert_eq!(fields["valid_device_count"], "1");
}

#[test]
fn arbitrary_node_payload_and_wrong_namespace_do_not_leak() {
    let doc = roxmltree::Document::parse("<message><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='PRIVATE-NODE'><item id='PRIVATE-ID'><list xmlns='PRIVATE-NS'><device id='PRIVATE-DEVICE'>PRIVATE-KEY</device></list></item></items></event></message>").unwrap();
    let fields: BTreeMap<_, _> = event_fields(doc.root_element())
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(fields["node_kind"], "other");
    assert_eq!(fields["device_protocol"], "other");
    assert_eq!(fields["content_present"], "true");
    assert!(!format!("{fields:?}").contains("PRIVATE"));
    for xml in [
        "<iq><event xmlns='http://jabber.org/protocol/pubsub#event'><items/></event></iq>",
        "<message><event xmlns='WRONG'><items/></event></message>",
        "<message><event xmlns='http://jabber.org/protocol/pubsub#event'><purge/></event></message>",
    ] {
        let doc = roxmltree::Document::parse(xml).unwrap();
        assert!(event_fields(doc.root_element()).is_none());
    }
}

#[test]
fn avatar_classification_does_not_inspect_or_expose_avatar_data() {
    for (node, expected) in [
        ("urn:xmpp:avatar:metadata", "avatar-metadata"),
        ("urn:xmpp:avatar:data", "avatar-data"),
    ] {
        let xml = format!(
            "<message><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='{node}'><item><data xmlns='urn:xmpp:avatar:data'>PRIVATE-IMAGE</data></item></items></event></message>"
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let fields: BTreeMap<_, _> = event_fields(doc.root_element())
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(fields["node_kind"], expected);
        assert!(!format!("{fields:?}").contains("PRIVATE"));
    }
}
