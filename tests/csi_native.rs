//! Compare importance decisions with the supplied, unmodified mod_csi_simple.
#[test]
#[ignore = "requires PROSODY_REFERENCE_SOURCE and PROSODY_REFERENCE_LUA"]
fn native_prosody_csi_importance_matches() {
    let cases = [
        ("<presence/>", "st.presence()"),
        (
            "<presence type='unavailable'/>",
            "st.presence({type='unavailable'})",
        ),
        (
            "<presence type='subscribe'/>",
            "st.presence({type='subscribe'})",
        ),
        (
            "<iq type='result' id='a'/>",
            "st.iq({type='result',id='a'})",
        ),
        ("<message><body>hi</body></message>", "st.message({},'hi')"),
        (
            "<message type='headline'><body>hi</body></message>",
            "st.message({type='headline'},'hi')",
        ),
        (
            "<message><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
            "st.message():tag('composing',{xmlns='http://jabber.org/protocol/chatstates'}):up()",
        ),
        (
            "<message><encryption xmlns='urn:xmpp:eme:0'/></message>",
            "st.message():tag('encryption',{xmlns='urn:xmpp:eme:0'}):up()",
        ),
        (
            "<message><encrypted xmlns='eu.siacs.conversations.axolotl'/></message>",
            "st.message():tag('encrypted',{xmlns='eu.siacs.conversations.axolotl'}):up()",
        ),
        (
            "<message><sent xmlns='urn:xmpp:carbons:2'/></message>",
            "st.message():tag('sent',{xmlns='urn:xmpp:carbons:2'}):up()",
        ),
        (
            "<message><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'><body>hi</body></message></forwarded></received></message>",
            "st.message():tag('received',{xmlns='urn:xmpp:carbons:2'}):tag('forwarded',{xmlns='urn:xmpp:forward:0'}):add_child(st.message({xmlns='jabber:client'},'hi')):reset()",
        ),
        (
            "<message><propose xmlns='urn:xmpp:jingle-message:0'/></message>",
            "st.message():tag('propose',{xmlns='urn:xmpp:jingle-message:0'}):up()",
        ),
        (
            "<message><x xmlns='http://jabber.org/protocol/muc#user'><invite/></x></message>",
            "st.message():tag('x',{xmlns='http://jabber.org/protocol/muc#user'}):tag('invite'):reset()",
        ),
        (
            "<message><payload xmlns='urn:test'/></message>",
            "st.message():tag('payload',{xmlns='urn:test'}):up()",
        ),
        (
            "<r xmlns='urn:xmpp:sm:3'/>",
            "st.stanza('r',{xmlns='urn:xmpp:sm:3'})",
        ),
    ];
    let bootstrap = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/prosody_compat/oracle.lua"
    ))
    .unwrap();
    let bootstrap = bootstrap.split("if phase == 'probe' then").next().unwrap();
    let mut script = format!(
        "{bootstrap}\nconfig.set('example.org','csi_important_payloads',{{'{{urn:test}}payload'}});\nassert(mm.load('example.org','csi_simple'));\nlocal csi=assert(mm.get_module('example.org','csi_simple'));\n"
    );
    for (index, (_, expression)) in cases.iter().enumerate() {
        script.push_str(&format!(
            "print('CSI_CASE_{index}='..tostring(not not csi.is_important({expression})));\n"
        ));
    }
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("csi.lua");
    std::fs::write(&path, script).unwrap();
    let output = std::process::Command::new(
        std::env::var("PROSODY_REFERENCE_LUA").unwrap_or_else(|_| "lua5.4".into()),
    )
    .arg(path)
    .arg(std::env::var("PROSODY_REFERENCE_SOURCE").unwrap())
    .arg(folder.path())
    .arg("csi")
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    for (index, (xml, _)) in cases.iter().enumerate() {
        let expected = format!(
            "CSI_CASE_{index}={}",
            rust_xmpp::csi::important(xml, &["{urn:test}payload".into()])
        );
        assert!(
            stdout.lines().any(|line| line == expected),
            "{xml}: expected {expected}, native output {stdout}"
        );
    }
}
