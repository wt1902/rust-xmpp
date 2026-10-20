//! Multi-item PEP nodes must expose their newest item first, as native Prosody does.
use rust_xmpp::{auth, pubsub};
use std::path::Path;

const DEVICES: &str = "eu.siacs.conversations.axolotl.devicelist";
const PUBSUB: &str = "http://jabber.org/protocol/pubsub";

fn request(root: &Path, typ: &str, body: &str) -> String {
    let stanza = format!(
        "<iq type='{typ}' id='order' to='alice@example.org'><pubsub xmlns='{PUBSUB}'>{body}</pubsub></iq>"
    );
    let doc = roxmltree::Document::parse(&stanza).unwrap();
    let result = pubsub::handle(
        root,
        "example.org",
        "alice@example.org/phone",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    let reply = result.replies.into_iter().next().unwrap();
    assert!(reply.contains("type='result'"), "{reply}");
    reply
}

fn setup(root: &Path) {
    auth::create(root, "example.org", "alice", "test-only", "SHA-256").unwrap();
    request(
        root,
        "set",
        &format!(
            "<create node='{DEVICES}'/><configure><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#max_items'><value>4</value></field></x></configure>"
        ),
    );
    for (id, devices) in [("old", ""), ("current", "<device id='42'/>")] {
        request(
            root,
            "set",
            &format!(
                "<publish node='{DEVICES}'><item id='{id}'><list xmlns='eu.siacs.conversations.axolotl'>{devices}</list></item></publish>"
            ),
        );
    }
}

#[test]
fn first_pep_item_is_current_device_list_even_with_retained_old_items() {
    let d = tempfile::tempdir().unwrap();
    setup(d.path());
    for limit in ["", " max_items='2'", " max_items='1'"] {
        let reply = request(
            d.path(),
            "get",
            &format!("<items node='{DEVICES}'{limit}/>"),
        );
        let doc = roxmltree::Document::parse(&reply).unwrap();
        // Conversations-family parsers read pubsub/items/item's first child.
        // A descendant-only assertion would also accept an obsolete first item.
        let items = doc
            .root_element()
            .children()
            .find(|n| n.has_tag_name((PUBSUB, "pubsub")))
            .unwrap()
            .children()
            .find(|n| n.has_tag_name((PUBSUB, "items")))
            .unwrap();
        let first = items.first_element_child().unwrap();
        assert_eq!(first.attribute("id"), Some("current"), "{reply}");
        let list = first.first_element_child().unwrap();
        assert!(list.has_tag_name(("eu.siacs.conversations.axolotl", "list")));
        assert_eq!(
            list.first_element_child().unwrap().attribute("id"),
            Some("42")
        );
        let ids: Vec<_> = items
            .children()
            .filter(|n| n.is_element())
            .map(|n| n.attribute("id").unwrap())
            .collect();
        assert_eq!(
            ids,
            if limit.contains("'1'") {
                vec!["current"]
            } else {
                vec!["current", "old"]
            }
        );
    }
}

#[test]
#[ignore = "requires PROSODY_REFERENCE_SOURCE and PROSODY_REFERENCE_LUA"]
fn native_prosody_orders_retained_pep_items_newest_first() {
    let d = tempfile::tempdir().unwrap();
    setup(d.path());
    let bootstrap = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/prosody_compat/oracle.lua"
    ))
    .unwrap();
    let bootstrap = bootstrap.split("if phase == 'probe' then").next().unwrap();
    let script = format!(
        "{bootstrap}\n{}",
        r#"
assert(mm.unload('example.org','auth_internal_hashed'));
require('prosody.core.usermanager').initialize_host('example.org');
assert(mm.load('example.org','pep'));
local service = mm.get_module('example.org','pep').get_pep_service('alice');
local ok, items = service:get_items('eu.siacs.conversations.axolotl.devicelist','alice@example.org');
assert(ok, items);
assert(items[1] == 'current', tostring(items[1]));
assert(items[2] == 'old', tostring(items[2]));
assert(items.current.tags[1].tags[1].attr.id == '42');
print('NATIVE_PEP_NEWEST_FIRST_OK');
"#
    );
    let path = d.path().join("native-order.lua");
    std::fs::write(&path, script).unwrap();
    let output = std::process::Command::new(
        std::env::var("PROSODY_REFERENCE_LUA").unwrap_or("lua5.4".into()),
    )
    .arg(path)
    .arg(std::env::var("PROSODY_REFERENCE_SOURCE").unwrap())
    .arg(d.path())
    .arg("pubsub")
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
