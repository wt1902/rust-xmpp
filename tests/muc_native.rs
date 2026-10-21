//! Exact upstream MUC + muc_mam oracle, with no replacement storage/module API.
use rust_xmpp::{muc::Muc, protocol::ModuleResult};
fn send(muc: &mut Muc, xml: &str) -> ModuleResult {
    let doc = roxmltree::Document::parse(xml).unwrap();
    muc.handle("alice@example.org/r", doc.root_element())
        .unwrap()
        .unwrap()
}
#[test]
#[ignore = "requires PROSODY_REFERENCE_SOURCE and PROSODY_REFERENCE_LUA"]
fn actual_prosody_muc_mam_reads_rust_and_writes_native_archive() {
    let root = tempfile::tempdir().unwrap();
    let mut muc = Muc::new(root.path().into(), "rooms.example.org".into());
    muc.set_defaults(serde_json::json!({"persistent":true,"archiving":true,"whois":"moderators"}));
    send(
        &mut muc,
        "<presence to='room@rooms.example.org/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>",
    );
    send(
        &mut muc,
        "<iq type='set' to='room@rooms.example.org'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'/></query></iq>",
    );
    send(
        &mut muc,
        "<message type='groupchat' to='room@rooms.example.org' id='rust-message'><body>Rust archived body</body></message>",
    );
    drop(muc);
    // Transfer archive write ownership before native Prosody appends in place.
    assert_eq!(rust_xmpp::archive::checkpoint_all(root.path()).unwrap(), 1);
    let bootstrap = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/prosody_compat/oracle.lua"
    ))
    .unwrap();
    let bootstrap = bootstrap.split("if phase == 'probe' then").next().unwrap();
    let script = format!(
        "{bootstrap}\n{}",
        r#"
config.set('rooms.example.org','component_module','muc');
config.set('rooms.example.org','modules_enabled',{'muc_mam'});
config.set('rooms.example.org','muc_log_expires_after','never');
assert(require('prosody.core.hostmanager').activate('rooms.example.org'));
if not mm.get_module('rooms.example.org','muc_mam') then assert(mm.load('rooms.example.org','muc_mam')); end
local muc=assert(mm.get_module('rooms.example.org','muc'));
local room=assert(muc.get_room_from_jid('room@rooms.example.org'));
assert(room:get_affiliation('alice@example.org')=='owner');
assert(room:get_persistent());assert(room._data.archiving);
local archive=assert(sm.open('rooms.example.org','muc_log','archive'));
local count=0;
for id,item,when,peer in assert(archive:find('room',{with='message<groupchat'})) do
 count=count+1;assert(peer=='message<groupchat');assert(item:get_child_text('body')=='Rust archived body');
end
assert(count==1,'Rust records not visible through native MUC archive query');
room:broadcast_message(st.message({xmlns='jabber:client',type='groupchat',from='room@rooms.example.org/Alice',id='native-message'},'Native archived body'));
local found=false;
for id,item,when,peer in assert(archive:find('room',{with='message<groupchat'})) do
 assert(peer=='message<groupchat');if item:get_child_text('body')=='Native archived body' then found=true;end
end
assert(found,'actual mod_muc_mam did not archive native broadcast');
room:set_name('Native room name');assert(room:save(true));
print('NATIVE_MUC_MAM_ROUNDTRIP_OK');
"#
    );
    let script_path = root.path().join("native-muc.lua");
    std::fs::write(&script_path, script).unwrap();
    let output = std::process::Command::new(
        std::env::var("PROSODY_REFERENCE_LUA").unwrap_or("lua5.4".into()),
    )
    .arg(&script_path)
    .arg(std::env::var("PROSODY_REFERENCE_SOURCE").unwrap())
    .arg(root.path())
    .arg("muc")
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut muc = Muc::new(root.path().into(), "rooms.example.org".into());
    let result = send(
        &mut muc,
        "<iq type='set' to='room@rooms.example.org'><query xmlns='urn:xmpp:mam:2'/></iq>",
    );
    assert!(
        result
            .replies
            .iter()
            .any(|s| s.contains("Native archived body")),
        "{:?}",
        result.replies
    );
    let disco = send(
        &mut muc,
        "<iq type='get' to='room@rooms.example.org'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
    );
    assert!(disco.replies[0].contains("Native room name"));
}
