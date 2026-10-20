//! Native freeze(true)/restore differential coverage for MUC occupant checkpoints.
use rust_xmpp::{
    muc::Muc,
    muc_recovery::{OccupantSnapshot, load_room, save_room},
};

const DOMAIN: &str = "rooms.example.org";
const ROOM: &str = "room@rooms.example.org";

#[test]
#[ignore = "requires PROSODY_REFERENCE_SOURCE and PROSODY_REFERENCE_LUA"]
fn actual_prosody_restores_rust_checkpoint_and_rust_reads_native_freeze() {
    let root = tempfile::tempdir().unwrap();
    // Let the real room implementation create its normal configuration/index.
    let mut muc = Muc::new(root.path().into(), DOMAIN.into());
    muc.set_defaults(serde_json::json!({"persistent":true,"whois":"moderators"}));
    let join = roxmltree::Document::parse(
        "<presence to='room@rooms.example.org/Alice'><status>Rust desktop</status></presence>",
    )
    .unwrap();
    muc.handle("alice@example.org/desktop", join.root_element())
        .unwrap()
        .unwrap();
    drop(muc);

    let snapshots = vec![
        OccupantSnapshot {
            jid: "alice@example.org/desktop".into(),
            nick: "Alice".into(),
            role: "moderator".into(),
            presence_payload: "<show>away</show><status>Rust desktop</status>".into(),
        },
        OccupantSnapshot {
            jid: "alice@example.org/mobile".into(),
            nick: "Alice".into(),
            role: "moderator".into(),
            presence_payload: "<status>Rust mobile</status><priority>3</priority>".into(),
        },
        OccupantSnapshot {
            jid: "bob@example.org/native".into(),
            nick: "Bob".into(),
            role: "participant".into(),
            presence_payload: "<status>Rust Bob</status>".into(),
        },
    ];
    save_room(root.path(), DOMAIN, ROOM, &snapshots).unwrap();

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
assert(require('prosody.core.hostmanager').activate('rooms.example.org'));
local muc=assert(mm.get_module('rooms.example.org','muc'));
local room=assert(muc.get_room_from_jid('room@rooms.example.org'));
assert(room:get_persistent());
local alice=assert(room:get_occupant_by_nick('room@rooms.example.org/Alice'));
assert(alice.bare_jid=='alice@example.org' and alice.role=='moderator');
local sessions=0;
for jid,presence in alice:each_session() do
 sessions=sessions+1;
 assert(presence.attr.from=='room@rooms.example.org/Alice');
 if jid=='alice@example.org/desktop' then
  assert(presence:get_child_text('show')=='away');
  assert(presence:get_child_text('status')=='Rust desktop');
 elseif jid=='alice@example.org/mobile' then
  assert(presence:get_child_text('status')=='Rust mobile');
  assert(presence:get_child_text('priority')=='3');
 else error('unexpected Alice session '..jid); end
end
assert(sessions==2,'native restore lost a resource');
local bob=assert(room:get_occupant_by_nick('room@rooms.example.org/Bob'));
assert(bob.bare_jid=='bob@example.org' and bob.role=='participant');
assert(bob:get_presence():get_child_text('status')=='Rust Bob');

-- Change the native occupant and serialize through upstream freeze(true).
bob.role='visitor';
bob:set_session('bob@example.org/native',st.presence({xmlns='jabber:client'})
 :tag('show'):text('dnd'):up():tag('status'):text('Native Bob & ready'):up());
room:save_occupant(bob);
local frozen,state=room:freeze(true);
assert(state['room@rooms.example.org/Alice'].role=='moderator');
assert(state['room@rooms.example.org/Bob'].role=='visitor');
assert(state['alice@example.org/desktop'].name=='presence');
assert(state['alice@example.org/mobile'].name=='presence');
assert(room:save(nil,true));
print('NATIVE_MUC_STATE_ROUNDTRIP_OK');
"#
    );
    let script_path = root.path().join("native-muc-state.lua");
    std::fs::write(&script_path, script).unwrap();
    let output = std::process::Command::new(
        std::env::var("PROSODY_REFERENCE_LUA").unwrap_or("lua5.4".into()),
    )
    .arg(&script_path)
    .arg(std::env::var("PROSODY_REFERENCE_SOURCE").unwrap())
    .arg(root.path())
    .arg("muc-state")
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("NATIVE_MUC_STATE_ROUNDTRIP_OK"));

    let recovered = load_room(root.path(), DOMAIN, ROOM).unwrap();
    assert_eq!(recovered.len(), 3, "{recovered:?}");
    for original in &snapshots[..2] {
        assert_eq!(
            recovered.iter().find(|o| o.jid == original.jid),
            Some(original),
            "native freeze must preserve both Alice sessions"
        );
    }
    let bob = recovered
        .iter()
        .find(|o| o.jid == "bob@example.org/native")
        .unwrap();
    assert_eq!(bob.nick, "Bob");
    assert_eq!(bob.role, "visitor");
    let wrapped = format!("<presence>{}</presence>", bob.presence_payload);
    let payload = roxmltree::Document::parse(&wrapped).unwrap();
    let text = |name: &str| {
        payload
            .root_element()
            .children()
            .find(|n| n.has_tag_name(name))
            .and_then(|n| n.text())
    };
    assert_eq!(text("show"), Some("dnd"));
    assert_eq!(text("status"), Some("Native Bob & ready"));
}
