//! Exercises the actual supplied mod_pep/util.pubsub, not a duplicate storage decoder.
use rust_xmpp::{auth, pubsub};
#[test]
#[ignore = "requires PROSODY_REFERENCE_SOURCE and PROSODY_REFERENCE_LUA"]
fn native_prosody_pep_reads_rust_and_rust_reads_native() {
    let d = tempfile::tempdir().unwrap();
    auth::create(d.path(), "example.org", "alice", "test-only", "SHA-256").unwrap();
    let xml = "<iq type='set'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:test:devices'><item id='rust'><devices xmlns='urn:test:devices'><device id='42'/></devices></item></publish></pubsub></iq>";
    let doc = roxmltree::Document::parse(xml).unwrap();
    let result = pubsub::handle(
        d.path(),
        "example.org",
        "alice@example.org/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(result.replies[0].contains("type='result'"));
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
assert(require('prosody.core.usermanager').user_exists('alice','example.org'));
assert(mm.load('example.org','pep'));
local env=assert(mm.get_module('example.org','pep'));
local service=env.get_pep_service('alice');
local ok,items=service:get_items('urn:test:devices','alice@example.org');assert(ok,items);
assert(items[1]=='rust');local item=assert(items['rust']);assert(item.tags[1].attr.xmlns=='urn:test:devices');assert(item.tags[1].tags[1].attr.id=='42');
local published=st.stanza('item',{xmlns='http://jabber.org/protocol/pubsub',id='native',publisher='alice@example.org'}):tag('devices',{xmlns='urn:test:devices'}):tag('device',{id='99'}):up():up();
local ok,err=service:publish('urn:test:devices','alice@example.org','native',published);assert(ok,err);
print('NATIVE_PEP_ROUNDTRIP_OK');
"#
    );
    let path = d.path().join("native.lua");
    std::fs::write(&path, script).unwrap();
    let source = std::env::var("PROSODY_REFERENCE_SOURCE").unwrap();
    let lua = std::env::var("PROSODY_REFERENCE_LUA").unwrap_or("lua5.4".into());
    let out = std::process::Command::new(lua)
        .arg(path)
        .arg(source)
        .arg(d.path())
        .arg("pubsub")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let get = "<iq type='get'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:test:devices'/></pubsub></iq>";
    let doc = roxmltree::Document::parse(get).unwrap();
    let out = pubsub::handle(
        d.path(),
        "example.org",
        "alice@example.org/r",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(out.replies[0].contains("id='native'"), "{:?}", out.replies);
    assert!(out.replies[0].contains("id='99'"));
    assert!(!out.replies[0].contains("id='rust'"));
}
