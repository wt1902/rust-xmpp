use rust_xmpp::protocol;

#[test]
fn pep_errors_identify_the_account_and_echo_the_request() {
    let doc = roxmltree::Document::parse("<iq id='bundle' type='get' to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.bundles:123'/></pubsub></iq>").unwrap();
    let reply = protocol::iq_error(doc.root_element(), "item-not-found");
    let parsed = roxmltree::Document::parse(&reply).unwrap();
    let iq = parsed.root_element();
    assert_eq!(iq.attribute("from"), Some("alice@example.test"));
    assert_eq!(iq.attribute("id"), Some("bundle"));
    assert!(
        iq.first_element_child()
            .unwrap()
            .has_tag_name(("http://jabber.org/protocol/pubsub", "pubsub"))
    );
    assert!(
        iq.descendants()
            .any(|n| n.has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", "item-not-found")))
    );
}

#[test]
fn server_errors_without_target_remain_unaddressed_and_escape_attributes() {
    for target in ["", " to='alice&amp;bob@example.test'"] {
        let request = format!("<iq id='a&amp;b' type='get'{target}><query xmlns='urn:test'/></iq>");
        let doc = roxmltree::Document::parse(&request).unwrap();
        let reply = protocol::iq_error(doc.root_element(), "service-unavailable");
        let parsed = roxmltree::Document::parse(&reply).unwrap();
        assert_eq!(
            parsed.root_element().attribute("from"),
            doc.root_element().attribute("to")
        );
        assert_eq!(parsed.root_element().attribute("id"), Some("a&b"));
    }
}
