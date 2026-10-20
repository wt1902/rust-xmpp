use rust_xmpp::storage::{self, LuaValue as V};
#[test]
fn mixed_binary_roundtrip() {
    let src=b"return { [false]={version=4;pending={};}; [1]='one'; ['a\\000\\255']='\\001\\254'; ['alice@example.test']={subscription='both';groups={Friends=true}} }";
    let a = storage::parse(src).unwrap();
    let b = storage::parse(storage::serialize(&a).unwrap().as_bytes()).unwrap();
    assert_eq!(a.get_key(&V::Bool(false)), b.get_key(&V::Bool(false)));
    assert_eq!(
        a.get_key(&V::String(vec![b'a', 0, 255])),
        Some(&V::String(vec![1, 254]))
    );
    assert_eq!(a.get_key(&V::Integer(1)), b.get_key(&V::Integer(1)));
    let lua = mlua::Lua::new();
    let t: mlua::Table = lua.load(storage::serialize(&a).unwrap()).eval().unwrap();
    assert_eq!(
        t.get::<mlua::Table>(false)
            .unwrap()
            .get::<i64>("version")
            .unwrap(),
        4
    );
}
#[test]
fn path_and_atomic_update() {
    let t = tempfile::tempdir().unwrap();
    assert_eq!(
        storage::path(t.path(), "example.test", Some("a_b"), "pep_node")
            .strip_prefix(t.path())
            .unwrap()
            .to_str()
            .unwrap(),
        "example%2etest/pep_node/a%5fb.dat"
    );
    storage::update(t.path(), "example.test", Some("alice"), "roster", |v| {
        v.set("a", "old".into());
        Ok(())
    })
    .unwrap();
    let result = storage::update(t.path(), "example.test", Some("alice"), "roster", |v| {
        v.set("a", "new".into());
        anyhow::bail!("abort")
    });
    assert!(result.is_err());
    assert_eq!(
        storage::load(t.path(), "example.test", Some("alice"), "roster")
            .unwrap()
            .unwrap()
            .get("a")
            .and_then(V::as_str),
        Some("old")
    );
}
#[test]
fn rejects_cycles_code_and_bad_files() {
    assert!(storage::parse(b"return os.execute('true')").is_err());
    assert!(storage::parse(b"local t={};t.self=t;return t").is_err());
    assert!(storage::parse(b"while true do end").is_err());
    assert!(storage::parse(b"return {x=function()end}").is_err());
}
#[test]
fn stanza_roundtrip() {
    let d=roxmltree::Document::parse("<vCard xmlns='vcard-temp' xml:lang='ru'><FN>A &amp; B</FN><x xmlns='other' a='b'/></vCard>").unwrap();
    let v = storage::stanza_value(d.root_element());
    assert_eq!(
        v.get("attr").unwrap().get("xml:lang").and_then(V::as_str),
        Some("ru")
    );
    let s =
        storage::stanza_xml(&storage::parse(storage::serialize(&v).unwrap().as_bytes()).unwrap())
            .unwrap();
    let doc = roxmltree::Document::parse(&s).unwrap();
    assert_eq!(
        doc.root_element()
            .attribute(("http://www.w3.org/XML/1998/namespace", "lang")),
        Some("ru")
    );
    assert_eq!(
        doc.root_element().first_element_child().unwrap().text(),
        Some("A & B")
    );
}
#[test]
fn concurrent_updates_do_not_lose_entries() {
    let t = tempfile::tempdir().unwrap();
    std::thread::scope(|scope| {
        for n in 0..12 {
            let p = t.path();
            scope.spawn(move || {
                storage::update(p, "d", Some("a"), "test", |v| {
                    v.set(&n.to_string(), V::Integer(n));
                    Ok(())
                })
                .unwrap();
            });
        }
    });
    assert_eq!(
        storage::load(t.path(), "d", Some("a"), "test")
            .unwrap()
            .unwrap()
            .entries()
            .len(),
        12
    );
}
#[test]
fn empty_namespace_preserved() {
    let d = roxmltree::Document::parse("<x xmlns='one'><y xmlns=''/></x>").unwrap();
    let s = storage::stanza_xml(&storage::stanza_value(d.root_element())).unwrap();
    let d = roxmltree::Document::parse(&s).unwrap();
    assert_eq!(
        d.root_element()
            .first_element_child()
            .unwrap()
            .tag_name()
            .namespace(),
        Some("")
    );
}
