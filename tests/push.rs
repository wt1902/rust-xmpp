use rust_xmpp::{auth, config::Config, push::Push, storage};
fn config() -> Config {
    serde_json::from_value(serde_json::json!({"global":{"modules_enabled":["cloud_notify"],"push_notification_with_body":false,"push_notification_with_sender":true,"push_notification_important_body":"New message"},"hosts":{"example.test":{"options":{}}}})).unwrap()
}
#[test]
fn registrations_notifications_and_authenticated_errors() {
    let dir = tempfile::tempdir().unwrap();
    auth::create(dir.path(), "example.test", "alice", "secret", "SHA-256").unwrap();
    let mut push = Push::default();
    let enable=roxmltree::Document::parse("<iq type='set' id='enable'><enable xmlns='urn:xmpp:push:0' jid='push.test' node='device'><x xmlns='jabber:x:data' type='submit'><field var='secret'><value>token</value></field></x></enable></iq>").unwrap();
    assert!(
        push.handle(
            dir.path(),
            "example.test",
            "alice@example.test/mobile",
            enable.root_element(),
            50
        )
        .unwrap()
        .unwrap()
        .replies[0]
            .contains("type='result'")
    );
    let data = storage::load(dir.path(), "example.test", Some("alice"), "cloud_notify")
        .unwrap()
        .unwrap();
    assert!(data.get("push.test<device").is_some());
    let message=roxmltree::Document::parse("<message xmlns='jabber:client' from='bob@example.test'><body>private text</body></message>").unwrap();
    for (i, sender) in ["forged.test", "push.test", "push.test"].iter().enumerate() {
        let notifications = push
            .notify(
                dir.path(),
                "example.test",
                "alice",
                message.root_element(),
                &config(),
            )
            .unwrap();
        assert_eq!(notifications.len(), 1);
        let xml = &notifications[0].1;
        assert!(!xml.contains("private text"));
        assert!(xml.contains("New message") && xml.contains("token"));
        let d = roxmltree::Document::parse(xml).unwrap();
        let id = d.root_element().attribute("id").unwrap();
        let reply =
            format!("<iq type='error' id='{id}' from='{sender}'><error type='cancel'/></iq>");
        let d = roxmltree::Document::parse(&reply).unwrap();
        assert_eq!(
            push.result(dir.path(), "example.test", d.root_element(), 2)
                .unwrap(),
            i > 0
        );
    }
    assert!(
        storage::load(dir.path(), "example.test", Some("alice"), "cloud_notify")
            .unwrap()
            .is_none()
    );
}
#[test]
fn foreign_account_cannot_register() {
    let dir = tempfile::tempdir().unwrap();
    let mut push = Push::default();
    let d=roxmltree::Document::parse("<iq type='set' to='bob@example.test'><enable xmlns='urn:xmpp:push:0' jid='push.test'/></iq>").unwrap();
    let r = push
        .handle(
            dir.path(),
            "example.test",
            "alice@example.test/r",
            d.root_element(),
            50,
        )
        .unwrap()
        .unwrap();
    assert!(r.replies[0].contains("forbidden"));
}

#[test]
fn stable_client_registration_and_targeted_notification() {
    use rust_xmpp::push::client_device;
    let dir = tempfile::tempdir().unwrap();
    let mut push = Push::default();
    for (node, resource, client) in [
        ("phone", "old", Some("stable-phone")),
        ("tablet", "tablet", None),
    ] {
        let xml = format!(
            "<iq type='set' xml:lang='ru'><enable xmlns='urn:xmpp:push:0' jid='push.test' node='{node}'/></iq>"
        );
        let document = roxmltree::Document::parse(&xml).unwrap();
        push.handle_with_client(
            dir.path(),
            "example.test",
            &format!("alice@example.test/{resource}"),
            document.root_element(),
            50,
            client,
        )
        .unwrap();
    }
    let table = storage::load(dir.path(), "example.test", Some("alice"), "cloud_notify")
        .unwrap()
        .unwrap();
    let phone = table.get("push.test<phone").unwrap();
    assert!(phone.get("client_id").is_some());
    assert!(phone.get("resource").is_none());
    assert!(phone.get("language").is_some());
    assert_eq!(
        client_device(
            dir.path(),
            "example.test",
            "alice",
            Some("stable-phone"),
            "new"
        )
        .unwrap()
        .as_deref(),
        Some("push.test<phone")
    );
    assert_eq!(
        client_device(
            dir.path(),
            "example.test",
            "alice",
            Some("other-device"),
            "old"
        )
        .unwrap(),
        None
    );
    assert_eq!(
        client_device(dir.path(), "example.test", "alice", None, "tablet")
            .unwrap()
            .as_deref(),
        Some("push.test<tablet")
    );
    let message = roxmltree::Document::parse("<message><body>hello</body></message>").unwrap();
    let sent = push
        .notify_for_identifier(
            dir.path(),
            "example.test",
            "alice",
            message.root_element(),
            &config(),
            Some("push.test<phone"),
        )
        .unwrap();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].1.contains("node='phone'"));
    assert!(
        push.notify_for_identifier(
            dir.path(),
            "example.test",
            "alice",
            message.root_element(),
            &config(),
            Some("missing")
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        push.notify(
            dir.path(),
            "example.test",
            "alice",
            message.root_element(),
            &config()
        )
        .unwrap()
        .len(),
        2
    );
}
#[test]
fn queue_coalesces_and_importance_matches_native() {
    let dir = tempfile::tempdir().unwrap();
    let mut push = Push::default();
    let enable = roxmltree::Document::parse(
        "<iq type='set'><enable xmlns='urn:xmpp:push:0' jid='push.test' node='device'/></iq>",
    )
    .unwrap();
    push.handle(
        dir.path(),
        "example.test",
        "alice@example.test/r",
        enable.root_element(),
        5,
    )
    .unwrap();
    let messages = vec![
        "<message type='headline'><body>not important</body></message>".into(),
        "<message><active xmlns='http://jabber.org/protocol/chatstates'/></message>".into(),
        "<message><body>important</body></message>".into(),
        "<message><body>second important</body></message>".into(),
    ];
    let result = push
        .notify_queue(
            dir.path(),
            "example.test",
            "alice",
            &messages,
            &config(),
            "push.test<device",
        )
        .unwrap();
    assert_eq!(result.deliveries.len(), 2);
    assert!(result.reset_watchdog);
    assert!(!result.deliveries[0].1.contains("last-message-body"));
    assert!(result.deliveries[1].1.contains("last-message-body"));
    for (xml, expected) in [
        (
            "<message type='groupchat'><subject>Topic</subject><body>topic text</body></message>",
            false,
        ),
        ("<message><x xmlns='jabber:x:encrypted'/></message>", true),
        (
            "<message><finish xmlns='urn:xmpp:jingle-message:0'/></message>",
            false,
        ),
        (
            "<message><propose xmlns='urn:xmpp:jingle-message:0'/></message>",
            true,
        ),
        (
            "<message><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'><body>outgoing</body></message></forwarded></sent></message>",
            false,
        ),
    ] {
        let doc = roxmltree::Document::parse(xml).unwrap();
        assert_eq!(
            rust_xmpp::push::is_important(doc.root_element()),
            expected,
            "{xml}"
        );
    }
}
#[test]
fn reenable_cancels_old_errors_and_failure_counts_are_per_account() {
    let dir = tempfile::tempdir().unwrap();
    let mut push = Push::default();
    let enable = roxmltree::Document::parse(
        "<iq type='set'><enable xmlns='urn:xmpp:push:0' jid='push.test' node='shared'/></iq>",
    )
    .unwrap();
    for user in ["alice", "bob"] {
        push.handle(
            dir.path(),
            "example.test",
            &format!("{user}@example.test/r"),
            enable.root_element(),
            5,
        )
        .unwrap();
    }
    let message = roxmltree::Document::parse("<message><body>hello</body></message>").unwrap();
    let fail = |push: &mut Push, user: &str| {
        let out = push
            .notify(
                dir.path(),
                "example.test",
                user,
                message.root_element(),
                &config(),
            )
            .unwrap();
        let doc = roxmltree::Document::parse(&out[0].1).unwrap();
        let id = doc.root_element().attribute("id").unwrap();
        let error =
            format!("<iq type='error' from='push.test' id='{id}'><error type='cancel'/></iq>");
        let doc = roxmltree::Document::parse(&error).unwrap();
        push.result(dir.path(), "example.test", doc.root_element(), 2)
            .unwrap();
    };
    fail(&mut push, "alice");
    fail(&mut push, "bob");
    assert!(push.take_removed().is_empty());
    fail(&mut push, "alice");
    assert_eq!(
        push.take_removed(),
        vec![("alice".into(), "push.test<shared".into())]
    );
    assert!(
        storage::load(dir.path(), "example.test", Some("bob"), "cloud_notify")
            .unwrap()
            .is_some()
    );
    let out = push
        .notify(
            dir.path(),
            "example.test",
            "bob",
            message.root_element(),
            &config(),
        )
        .unwrap();
    let doc = roxmltree::Document::parse(&out[0].1).unwrap();
    let id = doc.root_element().attribute("id").unwrap();
    let error = format!("<iq type='error' from='push.test' id='{id}'><error type='cancel'/></iq>");
    push.handle(
        dir.path(),
        "example.test",
        "bob@example.test/r",
        enable.root_element(),
        5,
    )
    .unwrap();
    let doc = roxmltree::Document::parse(&error).unwrap();
    assert!(
        !push
            .result(dir.path(), "example.test", doc.root_element(), 1)
            .unwrap()
    );
    assert!(push.take_removed().is_empty());
}

#[test]
fn push_summary_never_copies_foreign_namespace_body() {
    let dir = tempfile::tempdir().unwrap();
    let mut push = Push::default();
    let enable = roxmltree::Document::parse(
        "<iq type='set'><enable xmlns='urn:xmpp:push:0' jid='push.test' node='phone'/></iq>",
    )
    .unwrap();
    push.handle(
        dir.path(),
        "example.test",
        "alice@example.test/r",
        enable.root_element(),
        5,
    )
    .unwrap();
    let mut settings = config();
    settings.global.insert(
        "push_notification_with_body".into(),
        serde_json::json!(true),
    );
    for (message, expected) in [
        (
            "<message xmlns='jabber:client'><body xmlns='urn:private'>extension-secret</body></message>",
            None,
        ),
        (
            "<message xmlns='jabber:client'><private xmlns='urn:private'><body>nested-secret</body></private></message>",
            None,
        ),
        (
            "<message xmlns='jabber:client'><body xmlns='urn:private'>extension-secret</body><body>visible text</body></message>",
            Some("visible text"),
        ),
        (
            "<message xmlns='jabber:client'><body><private xmlns='urn:private'>nested-secret</private></body></message>",
            None,
        ),
        (
            "<message xmlns='jabber:client'><body>visible <!-- comment -->text</body></message>",
            Some("visible text"),
        ),
        (
            "<message xmlns='jabber:client' type='groupchat'><subject xmlns='urn:private'>extension-secret</subject><body>visible text</body></message>",
            Some("visible text"),
        ),
    ] {
        let doc = roxmltree::Document::parse(message).unwrap();
        let notifications = push
            .notify(
                dir.path(),
                "example.test",
                "alice",
                doc.root_element(),
                &settings,
            )
            .unwrap();
        assert_eq!(notifications.len(), 1);
        let xml = &notifications[0].1;
        assert!(
            !xml.contains("extension-secret") && !xml.contains("nested-secret"),
            "foreign body leaked: {xml}"
        );
        let result = roxmltree::Document::parse(xml).unwrap();
        let summary = result.descendants().find(|n| {
            n.has_tag_name(("jabber:x:data", "field"))
                && n.attribute("var") == Some("last-message-body")
        });
        let body = summary
            .and_then(|n| {
                n.children()
                    .find(|n| n.has_tag_name(("jabber:x:data", "value")))
            })
            .and_then(|n| n.text());
        assert_eq!(body, expected);
        assert_eq!(
            rust_xmpp::push::is_important(doc.root_element()),
            expected.is_some()
        );
    }
}

#[test]
#[ignore = "requires PROSODY_REFERENCE_SOURCE and PROSODY_REFERENCE_LUA"]
fn native_push_body_lookup_excludes_extensions() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let source = std::env::var("PROSODY_REFERENCE_SOURCE").unwrap();
    let mut lua = Command::new(std::env::var("PROSODY_REFERENCE_LUA").unwrap())
        .args(["-", &source])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    lua.stdin.take().unwrap().write_all(br#"
local source=assert(arg[1]);
package.path=source..'/?.lua;'..package.path;
package.cpath=source..'/?.so;'..package.cpath;
dofile(source..'/loader.lua');
local st=require 'prosody.util.stanza';
-- mod_cloud_notify uses this real helper for notification bodies and importance.
local foreign=st.message({xmlns='jabber:client'}):tag('body',{xmlns='urn:private'}):text('extension-secret'):reset();
assert(foreign:get_child_text('body') == nil);
local mixed=foreign:tag('body'):text('visible text'):reset();
assert(mixed:get_child_text('body') == 'visible text');
local nested=st.message({xmlns='jabber:client'}):tag('private',{xmlns='urn:private'}):tag('body'):text('nested-secret'):reset();
assert(nested:get_child_text('body') == nil);
local embedded=st.message({xmlns='jabber:client'}):tag('body'):tag('private',{xmlns='urn:private'}):text('nested-secret'):reset();
assert(embedded:get_child_text('body') == nil);
"#).unwrap();
    let output = lua.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
