use roxmltree::Document;
use rust_xmpp::{
    account_modules, preauth,
    storage::{self, LuaValue as V},
};
use tempfile::tempdir;
fn account(root: &std::path::Path, user: &str) {
    let mut data = V::table();
    data.set("password", "test".into());
    storage::save(root, "example.org", Some(user), "accounts", &data).unwrap();
}
#[test]
fn invitations_expire_are_single_use_and_owner_scoped() {
    let d = tempdir().unwrap();
    account(d.path(), "alice");
    account(d.path(), "other");
    let invite =
        preauth::create_invite(d.path(), "example.org", "alice@example.org", None, 10, 100)
            .unwrap();
    assert_eq!(invite.token.len(), 32);
    assert!(
        !preauth::consume(
            d.path(),
            "example.org",
            "other@example.org",
            "bob@remote.test",
            &invite.token,
            105
        )
        .unwrap()
    );
    assert!(
        preauth::consume(
            d.path(),
            "example.org",
            "alice@example.org",
            "bob@remote.test/mobile",
            &invite.token,
            109
        )
        .unwrap()
    );
    assert!(
        !preauth::consume(
            d.path(),
            "example.org",
            "alice@example.org",
            "bob@remote.test",
            &invite.token,
            109
        )
        .unwrap()
    );
    let expired =
        preauth::create_invite(d.path(), "example.org", "alice@example.org", None, 10, 100)
            .unwrap();
    assert!(
        !preauth::consume(
            d.path(),
            "example.org",
            "alice@example.org",
            "bob@remote.test",
            &expired.token,
            110
        )
        .unwrap()
    );
}
#[test]
fn identity_scope_does_not_burn_on_wrong_sender_or_leak_to_prosody() {
    let d = tempdir().unwrap();
    account(d.path(), "alice");
    let invite = preauth::create_invite(
        d.path(),
        "example.org",
        "alice@example.org",
        Some("Bob@remote.test"),
        10,
        100,
    )
    .unwrap();
    assert!(
        storage::load(d.path(), "example.org", Some("alice"), "invite_token")
            .unwrap()
            .is_none()
    );
    assert!(
        !preauth::consume(
            d.path(),
            "example.org",
            "alice@example.org",
            "eve@remote.test",
            &invite.token,
            101
        )
        .unwrap()
    );
    assert!(
        preauth::consume(
            d.path(),
            "example.org",
            "alice@example.org",
            "bob@remote.test",
            &invite.token,
            101
        )
        .unwrap()
    );
}
#[test]
fn prosody_numeric_expiry_is_consumed_and_other_entries_preserved() {
    let d = tempdir().unwrap();
    account(d.path(), "alice");
    let mut tokens = V::table();
    tokens.set("legacy", V::Number(200.0));
    tokens.set("unrelated", V::Integer(300));
    storage::save(
        d.path(),
        "example.org",
        Some("alice"),
        "invite_token",
        &tokens,
    )
    .unwrap();
    assert!(
        preauth::consume(
            d.path(),
            "example.org",
            "alice@example.org",
            "bob@remote.test",
            "legacy",
            100
        )
        .unwrap()
    );
    let data = storage::load(d.path(), "example.org", Some("alice"), "invite_token")
        .unwrap()
        .unwrap();
    assert!(data.get("legacy").is_none());
    assert_eq!(data.get("unrelated"), Some(&V::Integer(300)));
}
#[test]
fn duplicate_or_wrong_namespace_tokens_do_not_qualify() {
    for xml in [
        "<presence type='subscribe'><preauth xmlns='wrong' token='x'/></presence>",
        "<presence type='subscribed'><preauth xmlns='urn:xmpp:pars:0' token='x'/></presence>",
        "<presence type='subscribe'><preauth xmlns='urn:xmpp:pars:0' token='x'/><preauth xmlns='urn:xmpp:pars:0' token='y'/></presence>",
    ] {
        let doc = Document::parse(xml).unwrap();
        assert!(preauth::token_from_presence(doc.root_element()).is_none());
    }
}
#[test]
fn standard_adhoc_command_returns_contact_uri() {
    let d = tempdir().unwrap();
    account(d.path(), "alice");
    let doc = Document::parse("<iq type='set' id='i' to='example.org'><command xmlns='http://jabber.org/protocol/commands' node='urn:xmpp:invite#invite' action='execute'/></iq>").unwrap();
    let result = preauth::handle_iq(
        d.path(),
        "example.org",
        "alice@example.org/phone",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    let answer = Document::parse(&result.replies[0]).unwrap();
    assert_eq!(answer.root_element().attribute("type"), Some("result"));
    assert!(result.replies[0].contains("xmpp:alice@example.org?roster;preauth="));
    assert!(result.replies[0].contains("var='expire'"));
    assert!(!result.replies[0].contains("ibr=y"));
}
#[test]
fn unknown_client_token_is_preserved_on_remote_and_pending_delivery() {
    let d = tempdir().unwrap();
    account(d.path(), "alice");
    let doc = Document::parse("<presence xmlns='jabber:client' to='bob@remote.test' type='subscribe'><preauth xmlns='urn:xmpp:pars:0' token='client-token'/></presence>").unwrap();
    let result = account_modules::subscription(
        d.path(),
        "example.org",
        "alice@example.org/phone",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    let forwarded = result
        .deliveries
        .iter()
        .find(|(jid, _)| jid == "bob@remote.test")
        .unwrap();
    assert!(forwarded.1.contains("client-token"));
    let doc = Document::parse("<presence xmlns='jabber:client' to='alice@example.org' type='subscribe'><preauth xmlns='urn:xmpp:pars:0' token='unknown-token'/></presence>").unwrap();
    let result = account_modules::inbound_subscription(
        d.path(),
        "example.org",
        "bob@remote.test",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(
        result
            .deliveries
            .iter()
            .any(|(jid, xml)| jid == "alice@example.org" && xml.contains("unknown-token"))
    );
    let pending = account_modules::pending_subscriptions(d.path(), "example.org", "alice").unwrap();
    assert!(pending.iter().any(|xml| xml.contains("unknown-token")));
}
#[test]
fn valid_token_autoapproves_and_sends_reciprocal_request() {
    let d = tempdir().unwrap();
    account(d.path(), "alice");
    let invite = preauth::create_invite(
        d.path(),
        "example.org",
        "alice@example.org",
        None,
        60,
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    let xml = format!(
        "<presence xmlns='jabber:client' to='alice@example.org' type='subscribe'><preauth xmlns='urn:xmpp:pars:0' token='{}'/></presence>",
        invite.token
    );
    let doc = Document::parse(&xml).unwrap();
    let result = account_modules::inbound_subscription(
        d.path(),
        "example.org",
        "bob@remote.test",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    for kind in ["subscribed", "subscribe"] {
        assert!(result.deliveries.iter().any(|(jid, xml)| {
            jid == "bob@remote.test"
                && Document::parse(xml)
                    .unwrap()
                    .root_element()
                    .attribute("type")
                    == Some(kind)
        }));
    }
    let roster = storage::load(d.path(), "example.org", Some("alice"), "roster")
        .unwrap()
        .unwrap();
    let entry = roster.get("bob@remote.test").unwrap();
    assert_eq!(entry.get("subscription").and_then(V::as_str), Some("from"));
    assert_eq!(entry.get("ask").and_then(V::as_str), Some("subscribe"));
    assert!(
        account_modules::pending_subscriptions(d.path(), "example.org", "alice")
            .unwrap()
            .is_empty()
    );
}
#[test]
fn concurrent_redemption_has_exactly_one_winner() {
    let d = tempdir().unwrap();
    account(d.path(), "alice");
    let invite =
        preauth::create_invite(d.path(), "example.org", "alice@example.org", None, 60, 100)
            .unwrap();
    let winners = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let token = &invite.token;
                let root = d.path();
                scope.spawn(move || {
                    preauth::consume(
                        root,
                        "example.org",
                        "alice@example.org",
                        "bob@remote.test",
                        token,
                        101,
                    )
                    .unwrap()
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|accepted| *accepted)
            .count()
    });
    assert_eq!(winners, 1);
}
#[test]
fn local_invitation_updates_both_rosters_without_granting_reverse_subscription() {
    let d = tempdir().unwrap();
    account(d.path(), "alice");
    account(d.path(), "bob");
    let invite = preauth::create_invite(
        d.path(),
        "example.org",
        "alice@example.org",
        None,
        60,
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    let xml = format!(
        "<presence xmlns='jabber:client' to='alice@example.org' type='subscribe'><preauth xmlns='urn:xmpp:pars:0' token='{}'/></presence>",
        invite.token
    );
    let doc = Document::parse(&xml).unwrap();
    let result = account_modules::subscription(
        d.path(),
        "example.org",
        "bob@example.org/mobile",
        doc.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(result.deliveries.iter().any(|(jid, xml)| {
        jid == "bob@example.org"
            && Document::parse(xml)
                .unwrap()
                .root_element()
                .attribute("type")
                == Some("subscribe")
    }));
    for (user, contact, subscription) in [
        ("alice", "bob@example.org", "from"),
        ("bob", "alice@example.org", "to"),
    ] {
        let data = storage::load(d.path(), "example.org", Some(user), "roster")
            .unwrap()
            .unwrap();
        assert_eq!(
            data.get(contact)
                .unwrap()
                .get("subscription")
                .and_then(V::as_str),
            Some(subscription)
        );
    }
}

#[test]
fn unknown_tokens_do_not_create_invite_stores_and_disabled_accounts_cannot_issue() {
    let d = tempdir().unwrap();
    account(d.path(), "alice");
    assert!(
        !preauth::consume(
            d.path(),
            "example.org",
            "alice@example.org",
            "bob@remote.test",
            "unknown",
            100
        )
        .unwrap()
    );
    assert!(!storage::path(d.path(), "example.org", Some("alice"), "invite_token").exists());
    assert!(!storage::path(d.path(), "example.org", Some("alice"), "preauth_scoped").exists());
    storage::update(d.path(), "example.org", Some("alice"), "accounts", |v| {
        v.set("disabled", V::Bool(true));
        Ok(())
    })
    .unwrap();
    assert!(
        preauth::create_invite(d.path(), "example.org", "alice@example.org", None, 10, 100)
            .is_err()
    );
}
