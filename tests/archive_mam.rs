use rust_xmpp::{archive, mam, storage};
fn query(root: &std::path::Path, xml: &str) -> Vec<String> {
    let d = roxmltree::Document::parse(xml).unwrap();
    mam::handle(
        root,
        "example.org",
        "alice@example.org/phone",
        d.root_element(),
    )
    .unwrap()
    .unwrap()
    .replies
}
#[test]
fn legacy_records_binary_cache_and_roundtrip() {
    let t = tempfile::tempdir().unwrap();
    let p = storage::path(t.path(), "example.org", Some("alice"), "archive").with_extension("list");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p,b"item({name='message';attr={xmlns='jabber:client';stamp='2026-01-01T00:00:00Z'};key='old';with='bob@example.org';{name='body';attr={};'hello'}});\n").unwrap();
    std::fs::write(p.with_extension("lidx"), b"binary cache").unwrap();
    let rows = archive::load(t.path(), "example.org", "alice").unwrap();
    assert_eq!(rows[0].id, "old");
    assert!(rows[0].xml.contains("hello"));
    assert!(!rows[0].xml.contains("stamp="));
    archive::archive_message(
        t.path(),
        "example.org",
        "alice",
        "bob@example.org",
        "<message xmlns='jabber:client'><body>Привет &amp; test</body></message>",
        1767225601.,
    )
    .unwrap();
    assert!(!p.with_extension("lidx").exists());
    let rows = archive::load(t.path(), "example.org", "alice").unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows[1].xml.contains("Привет"));
    // Verify written syntax through actual Lua item callback, independent of Rust decoder.
    let lua = mlua::Lua::new();
    let code = format!(
        "local count=0; local function item(v) assert(v.name=='message'); assert(v.attr.stamp);count=count+1 end; {}; return count",
        std::fs::read_to_string(p).unwrap()
    );
    assert_eq!(lua.load(&code).eval::<usize>().unwrap(), 2);
}
#[test]
fn mam_paging_filters_and_forbidden() {
    let t = tempfile::tempdir().unwrap();
    let mut ids = vec![];
    for i in 0..4 {
        ids.push(
            archive::archive_message(
                t.path(),
                "example.org",
                "alice",
                if i % 2 == 0 {
                    "bob@example.org"
                } else {
                    "carol@example.org"
                },
                "<message xmlns='jabber:client'><body>x</body></message>",
                1767225600. + i as f64,
            )
            .unwrap(),
        );
    }
    let r = query(
        t.path(),
        "<iq type='set' id='q'><query xmlns='urn:xmpp:mam:2' queryid='client'><set xmlns='http://jabber.org/protocol/rsm'><max>2</max></set></query></iq>",
    );
    assert_eq!(r.len(), 3);
    assert!(r[0].contains(&ids[0]));
    assert!(r[2].contains("complete='false'"));
    assert!(r[2].contains("<count>4</count>"));
    let r = query(
        t.path(),
        "<iq type='set' id='q'><query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>1</max><before/></set></query></iq>",
    );
    assert!(r[0].contains(&ids[3]));
    let r = query(
        t.path(),
        "<iq type='set' id='q'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>bob@example.org</value></field></x></query></iq>",
    );
    assert_eq!(r.len(), 3);
    assert!(r[2].contains("<count>2</count>"));
    assert!(
        query(
            t.path(),
            "<iq type='set' to='bob@example.org'><query xmlns='urn:xmpp:mam:2'/></iq>"
        )[0]
        .contains("forbidden")
    );
    assert!(query(t.path(),"<iq type='set'><query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><after>missing</after></set></query></iq>")[0].contains("item-not-found"));
}
#[test]
fn mam_preferences_persist() {
    let t = tempfile::tempdir().unwrap();
    let r = query(
        t.path(),
        "<iq type='set'><prefs xmlns='urn:xmpp:mam:2' default='never'><always><jid>bob@example.org</jid></always><never/></prefs></iq>",
    );
    assert!(r[0].contains("default='never'"));
    assert!(
        mam::should_archive(
            t.path(),
            "example.org",
            "alice",
            "bob@example.org",
            "always"
        )
        .unwrap()
    );
    assert!(
        !mam::should_archive(
            t.path(),
            "example.org",
            "alice",
            "carol@example.org",
            "always"
        )
        .unwrap()
    );
    let p = storage::load(t.path(), "example.org", Some("alice"), "archive_prefs")
        .unwrap()
        .unwrap();
    assert_eq!(
        p.get_key(&storage::LuaValue::Bool(false)),
        Some(&storage::LuaValue::Bool(false))
    );
}
#[test]
fn namespaces_expiry_and_concurrent_append() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().to_path_buf();
    std::thread::scope(|scope| {
        for i in 0..12 {
            let r = &root;
            scope.spawn(move||{archive::archive_message(r,"example.org","alice","bob@example.org","<message xmlns='jabber:client' xml:lang='ru'><body>test</body><x xmlns='urn:test'/></message>",1767225600.+i as f64).unwrap();});
        }
    });
    let rows = archive::load(&root, "example.org", "alice").unwrap();
    assert_eq!(rows.len(), 12);
    let doc = roxmltree::Document::parse(&rows[0].xml).unwrap();
    assert_eq!(
        doc.root_element()
            .attribute(("http://www.w3.org/XML/1998/namespace", "lang")),
        Some("ru")
    );
    assert_eq!(
        archive::expire_before(&root, "example.org", Some("alice"), "archive", 1767225606.)
            .unwrap(),
        6
    );
    assert_eq!(
        archive::load(&root, "example.org", "alice").unwrap().len(),
        6
    );
}
#[test]
fn zero_page_dates_and_invalid_forms() {
    let t = tempfile::tempdir().unwrap();
    archive::archive_message(
        t.path(),
        "example.org",
        "alice",
        "bob@example.org",
        "<message xmlns='jabber:client'><body>x</body></message>",
        1767225600.,
    )
    .unwrap();
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>0</max></set></query></iq>",
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].contains("<count>1</count>"));
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='start'><value>2026-01-02T00:00:00Z</value></field></x></query></iq>",
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].contains("<count>0</count>"));
    assert!(query(t.path(),"<iq type='set'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='start'><value>2026-01-02T00:00:00Z</value></field></x></query></iq>")[0].contains("bad-request"));
}
#[test]
fn append_is_incremental_and_recovers_torn_tail() {
    use std::io::Write;
    let t = tempfile::tempdir().unwrap();
    let p = storage::path(t.path(), "example.org", Some("alice"), "archive").with_extension("list");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let original=b"item({\n name='message'; attr={xmlns='jabber:client'}; key='legacy'; when=1767225600; with='bob@example.org';\n {name='body';attr={};'original'}\n});\n";
    std::fs::write(&p, original).unwrap();
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&p).unwrap().ino()
    };
    archive::archive_message(
        t.path(),
        "example.org",
        "alice",
        "bob@example.org",
        "<message xmlns='jabber:client'><body>new</body></message>",
        1767225601.,
    )
    .unwrap();
    let intact = std::fs::read(&p).unwrap();
    assert!(intact.starts_with(original));
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(inode, std::fs::metadata(&p).unwrap().ino());
    }
    std::fs::write(
        p.with_extension("rappend"),
        (intact.len() as u64).to_le_bytes(),
    )
    .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&p)
        .unwrap()
        .write_all(b"item({bad torn write")
        .unwrap();
    assert_eq!(
        archive::load(t.path(), "example.org", "alice")
            .unwrap()
            .len(),
        2
    );
    assert_eq!(std::fs::read(&p).unwrap(), intact);
    assert!(!p.with_extension("rappend").exists());
}
#[test]
fn smart_enable_and_message_selection() {
    let t = tempfile::tempdir().unwrap();
    assert!(
        !mam::should_archive_with_options(
            t.path(),
            "example.org",
            "alice",
            "bob@example.org",
            "always",
            true
        )
        .unwrap()
    );
    let doc =
        roxmltree::Document::parse("<iq type='get'><query xmlns='urn:xmpp:mam:2'/></iq>").unwrap();
    mam::handle_with_options(
        t.path(),
        "example.org",
        "alice@example.org/r",
        doc.root_element(),
        "always",
        true,
    )
    .unwrap();
    assert!(
        mam::should_archive_with_options(
            t.path(),
            "example.org",
            "alice",
            "bob@example.org",
            "always",
            true
        )
        .unwrap()
    );
    for (xml, expected) in [
        ("<message><body>x</body></message>", true),
        (
            "<message><received xmlns='urn:xmpp:receipts'/></message>",
            true,
        ),
        ("<message type='headline'><body>x</body></message>", false),
        (
            "<message><body>x</body><no-permanent-store xmlns='urn:xmpp:hints'/></message>",
            false,
        ),
        (
            "<message><active xmlns='http://jabber.org/protocol/chatstates'/></message>",
            false,
        ),
        ("<message type='error' to='alice@example.org/r'/>", true),
    ] {
        let d = roxmltree::Document::parse(xml).unwrap();
        assert_eq!(mam::should_store(d.root_element()), expected, "{xml}");
    }
}
#[test]
#[ignore = "large-file scalability regression; run explicitly"]
fn archive_larger_than_128mib_streams() {
    use std::io::Write;
    let t = tempfile::tempdir().unwrap();
    let p = storage::path(t.path(), "example.org", Some("alice"), "archive").with_extension("list");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let mut f = std::fs::File::create(&p).unwrap();
    let padding = vec![b' '; 1024 * 1024];
    for i in 0..130 {
        writeln!(f,"item({{name='message';attr={{xmlns='jabber:client'}};key='{i}';when=1767225600;with='bob@example.org';{{name='body';attr={{}};'x'}}}});").unwrap();
        f.write_all(&padding).unwrap();
        f.write_all(b"\n").unwrap();
    }
    drop(f);
    assert!(std::fs::metadata(&p).unwrap().len() > 128 * 1024 * 1024);
    let mut count = 0;
    archive::scan_store(t.path(), "example.org", Some("alice"), "archive", |_| {
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, 130);
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>0</max></set></query></iq>",
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].contains("<count>130</count>"));
}
#[test]
fn extended_ids_ranges_flip_and_metadata() {
    let t = tempfile::tempdir().unwrap();
    for i in 1..=8 {
        archive::append_new(
            t.path(),
            "example.org",
            Some("alice"),
            "archive",
            archive::Entry {
                id: format!("id{i}"),
                when: 1767225600. + i as f64,
                peer: "bob@example.org".into(),
                xml: "<message xmlns='jabber:client'><body>x</body></message>".into(),
            },
        )
        .unwrap();
    }
    let r = query(
        t.path(),
        "<iq type='get'><metadata xmlns='urn:xmpp:mam:2'/></iq>",
    );
    let doc = roxmltree::Document::parse(&r[0]).unwrap();
    assert_eq!(
        doc.descendants()
            .find(|n| n.has_tag_name((mam::NS, "start")))
            .unwrap()
            .attribute("id"),
        Some("id1")
    );
    assert_eq!(
        doc.descendants()
            .find(|n| n.has_tag_name((mam::NS, "end")))
            .unwrap()
            .attribute("id"),
        Some("id8")
    );
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='before-id'><value>id7</value></field><field var='after-id'><value>id2</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>1</max></set></query></iq>",
    );
    assert_eq!(r.len(), 2);
    assert!(r[0].contains("id='id3'"));
    assert!(r[1].contains("complete='false'"));
    assert!(!r[1].contains("<count>"));
    assert!(!r[1].contains("index="));
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='ids'><value>id2</value><value>id5</value><value>id2</value></field></x><flip-page/></query></iq>",
    );
    assert_eq!(r.len(), 3);
    assert!(r[0].contains("id='id5'"));
    assert!(r[1].contains("id='id2'"));
    assert!(r[2].contains(">id2</first><last>id5</last>"));
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>2</max><before>id6</before></set><flip-page/></query></iq>",
    );
    assert!(r[0].contains("id='id5'"));
    assert!(r[1].contains("id='id4'"));
    assert!(r[2].contains(">id4</first><last>id5</last>"));
    let r = query(
        t.path(),
        "<iq type='get'><query xmlns='urn:xmpp:mam:2'/></iq>",
    );
    assert!(r[0].contains("var='before-id'"));
    assert!(r[0].contains("var='ids'"));
}
#[test]
fn real_archive_sid_and_sender_privacy() {
    let t = tempfile::tempdir().unwrap();
    let input = "<message xmlns='jabber:client' from='alice@example.org/r' to='bob@example.org'><body>test</body><active xmlns='http://jabber.org/protocol/chatstates'/><origin-id xmlns='urn:xmpp:sid:0' id='origin'/><stanza-id xmlns='urn:xmpp:sid:0' by='ALICE@EXAMPLE.ORG' id='forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='remote.example' id='remote'/></message>";
    let (id, delivery) = mam::archive_for_user(
        t.path(),
        "example.org",
        "alice",
        "bob@example.org/r",
        input,
        1767225600.,
    )
    .unwrap();
    assert!(!delivery.contains("forged"));
    assert!(delivery.contains("remote"));
    assert!(delivery.contains("origin"));
    assert!(delivery.contains(&id));
    assert!(delivery.contains("chatstates"));
    let saved = archive::load(t.path(), "example.org", "alice").unwrap();
    assert_eq!(saved[0].id, id);
    assert_eq!(saved[0].peer, "bob@example.org");
    assert!(!saved[0].xml.contains(&id));
    assert!(!saved[0].xml.contains("chatstates"));
    let stripped = mam::strip_owner_stanza_ids(&delivery, "example.org", "alice").unwrap();
    assert!(!stripped.contains(&id));
    assert!(stripped.contains("remote"));
    assert!(stripped.contains("origin"));
}
#[test]
fn equal_cursors_and_normalized_query_jids() {
    let t = tempfile::tempdir().unwrap();
    for i in 1..=3 {
        archive::append_new(
            t.path(),
            "example.org",
            Some("alice"),
            "archive",
            archive::Entry {
                id: format!("id{i}"),
                when: 1767225600. + i as f64,
                peer: "bob@example.org".into(),
                xml: "<message xmlns='jabber:client'><body>x</body></message>".into(),
            },
        )
        .unwrap();
    }
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><before>id2</before><after>id2</after></set></query></iq>",
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].contains("type='result'"));
    assert!(r[0].contains("complete='true'"));
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>BOB@EXAMPLE.ORG/phone</value></field></x></query></iq>",
    );
    assert_eq!(r.len(), 4);
    assert!(r[3].contains("<count>3</count>"));
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>bob@example.org</value><value>carol@example.org</value></field></x></query></iq>",
    );
    assert!(r[0].contains("bad-request"));
    assert!(r[0].contains("type='modify'"));
}
#[test]
fn corrupt_archive_reports_server_error_and_namespace_stripping_is_precise() {
    let t = tempfile::tempdir().unwrap();
    let p = storage::path(t.path(), "example.org", Some("alice"), "archive").with_extension("list");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"item({ broken").unwrap();
    let r = query(
        t.path(),
        "<iq type='set'><query xmlns='urn:xmpp:mam:2'/></iq>",
    );
    assert!(r[0].contains("internal-server-error"));
    assert!(!r[0].contains("bad-request"));
    std::fs::remove_file(p).unwrap();
    let input = "<message xmlns='jabber:client'><body>x</body><active xmlns='http://jabber.org/protocol/chatstates'/><private xmlns='urn:custom:private'/><stanza-id xmlns='urn:unrelated' by='alice@example.org' id='unrelated'/><stanza-id xmlns='urn:xmpp:sid:0' by='alice@example.org/r' id='resource'/><stanza-id xmlns='urn:xmpp:sid:0' by='alice@example.org' id='fake'/></message>";
    let (id, delivery) = mam::archive_for_user_with_namespaces(
        t.path(),
        "example.org",
        "alice",
        "bob@example.org",
        input,
        1767225600.,
        &["urn:custom:private"],
    )
    .unwrap();
    assert!(delivery.contains("unrelated"));
    assert!(delivery.contains("resource"));
    assert!(!delivery.contains("id='fake'"));
    assert!(delivery.contains("urn:custom:private"));
    let stored = archive::load(t.path(), "example.org", "alice").unwrap();
    assert!(stored[0].xml.contains("chatstates"));
    assert!(!stored[0].xml.contains("urn:custom:private"));
    assert!(!stored[0].xml.contains(&id));
}

#[test]
fn muc_archive_filters_stanza_kind_instead_of_sender_jid() {
    let t = tempfile::tempdir().unwrap();
    for (id, peer) in [
        ("group", "message<groupchat"),
        ("presence", "presence<available"),
    ] {
        archive::append_new(
            t.path(),
            "rooms.example.org",
            Some("room"),
            "muc_log",
            archive::Entry {
                id: id.into(),
                peer: peer.into(),
                when: 1767225600.,
                xml: "<message xmlns='jabber:client' type='groupchat'><body>hello</body></message>"
                    .into(),
            },
        )
        .unwrap();
    }
    for value in ["", "alice@example.org", "message&lt;groupchat"] {
        let xml = format!(
            "<iq type='set' id='q'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>{value}</value></field></x></query></iq>"
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let iq = doc.root_element();
        let q = iq.children().find(|n| n.is_element()).unwrap();
        let replies = mam::handle_archive_query(
            t.path(),
            "rooms.example.org",
            Some("room"),
            "muc_log",
            "room@rooms.example.org",
            iq,
            q,
        )
        .unwrap()
        .replies;
        assert_eq!(replies.len(), 2);
        assert!(replies[0].contains("id='group'") || replies[0].contains("id=\"group\""));
        assert!(!replies[0].contains("id='presence'"));
        assert!(replies[1].contains("<count>1</count>"));
    }
}

#[test]
fn archive_roundtrip_preserves_default_namespace_resets() {
    let temp = tempfile::tempdir().unwrap();
    let id = archive::archive_message(
        temp.path(),
        "example.org",
        "alice",
        "bob@example.org",
        "<message xmlns='jabber:client'><body>saved</body><payload xmlns=''><plain/><nested xmlns='urn:test'><empty xmlns=''/></nested></payload></message>",
        1767225600.,
    ).unwrap();
    // Retention rewrites records, so also check that namespace resets survive it.
    archive::append_new(
        temp.path(),
        "example.org",
        Some("alice"),
        "archive",
        archive::Entry {
            id: "old".into(),
            when: 1767225500.,
            peer: "bob@example.org".into(),
            xml: "<message xmlns='jabber:client'><body>old</body></message>".into(),
        },
    )
    .unwrap();
    assert_eq!(
        archive::expire_before(
            temp.path(),
            "example.org",
            Some("alice"),
            "archive",
            1767225550.
        )
        .unwrap(),
        1
    );
    let rows = archive::load(temp.path(), "example.org", "alice").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, id);
    let doc = roxmltree::Document::parse(&rows[0].xml).unwrap();
    for name in ["payload", "plain", "empty"] {
        let node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == name)
            .unwrap();
        assert_eq!(node.tag_name().namespace(), Some(""), "{name}");
    }
    assert!(
        doc.descendants()
            .any(|n| n.has_tag_name(("urn:test", "nested")))
    );
    assert!(
        doc.descendants()
            .any(|n| n.has_tag_name(("jabber:client", "body")))
    );
}
