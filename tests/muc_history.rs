use rust_xmpp::muc_history::{HistoryRequest, RoomHistory};

fn packet(id: usize, content: &str) -> String {
    format!(
        "<message xmlns='jabber:client' type='groupchat' from='room@rooms.example/Alice' id='{id}'>{content}</message>"
    )
}
fn join(attributes: &str) -> String {
    format!(
        "<presence><x xmlns='http://jabber.org/protocol/muc'><history {attributes}/></x></presence>"
    )
}
fn populated() -> RoomHistory {
    let mut history = RoomHistory::new(3);
    for id in 1..=4 {
        history.push(
            &packet(id, &format!("<body>message {id}</body>")),
            id as i64 * 10,
        );
    }
    history
}
fn ids(packets: &[String]) -> Vec<String> {
    packets
        .iter()
        .map(|xml| {
            let doc = roxmltree::Document::parse(xml).unwrap();
            doc.root_element().attribute("id").unwrap().to_owned()
        })
        .collect()
}
#[test]
fn ordinary_history_is_bounded_and_returns_oldest_first() {
    let history = populated();
    assert_eq!(history.len(), 3);
    assert_eq!(
        ids(&history.replay("room@rooms.example", "bob@example/r", "<presence/>", 40)),
        ["2", "3", "4"]
    );
}
#[test]
fn explicit_count_and_zero_limit() {
    let history = populated();
    assert_eq!(
        ids(&history.replay("room", "bob@example/r", &join("maxstanzas='2'"), 40)),
        ["3", "4"]
    );
    for attrs in ["maxstanzas='0'", "maxchars='0'", "maxstanzas='-1'"] {
        assert!(
            history
                .replay("room", "bob@example/r", &join(attrs), 40)
                .is_empty()
        );
    }
}
#[test]
fn default_count_applies_only_without_valid_explicit_constraints() {
    let mut history = populated();
    history.set_default_messages(1);
    assert_eq!(
        ids(&history.replay("room", "bob/r", "<presence/>", 40)),
        ["4"]
    );
    assert_eq!(
        ids(&history.replay("room", "bob/r", &join("seconds='30'"), 40)),
        ["2", "3", "4"]
    );
    assert_eq!(
        ids(&history.replay("room", "bob/r", &join("maxstanzas='bad'"), 40)),
        ["4"]
    );
}
#[test]
fn since_and_seconds_use_stricter_cutoff_inclusive() {
    let history = populated();
    let attrs = "since='1970-01-01T00:00:20Z' seconds='10'";
    assert_eq!(
        ids(&history.replay("room", "bob/r", &join(attrs), 40)),
        ["3", "4"]
    );
    assert_eq!(
        ids(&history.replay(
            "room",
            "bob/r",
            &join("since='1970-01-01T00:00:30.001Z'"),
            40
        )),
        ["4"]
    );
}
#[test]
fn replay_carries_room_delay_and_recipient() {
    let history = populated();
    let replay = history.replay("room", "bob@example/r&device", &join("maxstanzas='1'"), 40);
    let doc = roxmltree::Document::parse(&replay[0]).unwrap();
    let message = doc.root_element();
    assert_eq!(message.attribute("to"), Some("bob@example/r&device"));
    assert_eq!(message.attribute("from"), Some("room@rooms.example/Alice"));
    let delays: Vec<_> = message
        .children()
        .filter(|n| n.has_tag_name(("urn:xmpp:delay", "delay")))
        .collect();
    assert_eq!(delays.len(), 1);
    assert_eq!(delays[0].attribute("from"), Some("room@rooms.example"));
    assert_eq!(delays[0].attribute("stamp"), Some("1970-01-01T00:00:40Z"));
}
#[test]
fn maxchars_counts_transmitted_utf8_bytes_including_address_and_delay() {
    let mut history = RoomHistory::new(3);
    history.push(&packet(1, "<body>é🦀</body>"), 10);
    let all = history.replay("room", "bob/r", "<presence/>", 10);
    let size = all[0].len();
    assert_eq!(
        history
            .replay("room", "bob/r", &join(&format!("maxchars='{size}'")), 10)
            .len(),
        1
    );
    assert!(
        history
            .replay(
                "room",
                "bob/r",
                &join(&format!("maxchars='{}'", size - 1)),
                10
            )
            .is_empty()
    );
    assert!(
        history
            .replay(
                "room",
                "a-much-longer-recipient/r",
                &join(&format!("maxchars='{size}'")),
                10
            )
            .is_empty()
    );
}
#[test]
fn subjects_and_hints_follow_native_history_eligibility() {
    let mut history = RoomHistory::new(20);
    for content in [
        "<subject>topic</subject>",
        "<body>x</body><no-store xmlns='urn:xmpp:hints'/>",
        "<body>x</body><no-permanent-store xmlns='urn:xmpp:hints'/>",
        "<active xmlns='http://jabber.org/protocol/chatstates'/>",
    ] {
        history.push(&packet(0, content), 1);
    }
    assert!(history.is_empty());
    for content in [
        "<body/>",
        "<store xmlns='urn:xmpp:hints'/>",
        "<encryption xmlns='urn:xmpp:eme:0'/>",
        "<displayed xmlns='urn:xmpp:chat-markers:0' id='1'/>",
    ] {
        history.push(&packet(1, content), 1);
    }
    assert_eq!(history.len(), 4);
}
#[test]
fn capacity_changes_trim_and_zero_disables_history() {
    let mut history = populated();
    history.set_capacity(1);
    assert_eq!(
        ids(&history.replay("room", "bob/r", "<presence/>", 40)),
        ["4"]
    );
    history.set_capacity(0);
    history.push(&packet(5, "<body>ignored</body>"), 50);
    assert!(history.is_empty());
}
#[test]
fn snapshot_restores_last_message_without_adding_another_delay() {
    let history = populated();
    let (stanza, timestamp) = history.last_message().unwrap();
    let mut restored = RoomHistory::new(20);
    restored.restore_last_message(stanza, timestamp);
    let replay = restored.replay("room", "bob/r", "<presence/>", 99);
    assert_eq!(ids(&replay), ["4"]);
    let doc = roxmltree::Document::parse(&replay[0]).unwrap();
    assert_eq!(
        doc.root_element()
            .children()
            .filter(|n| n.has_tag_name(("urn:xmpp:delay", "delay")))
            .count(),
        1
    );
}
#[test]
fn only_direct_history_children_are_parsed() {
    let request = HistoryRequest::parse(
        "<presence><wrapper><x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='0'/></x></wrapper></presence>",
        40,
    );
    assert!(!request.has_constraints());
    let request = HistoryRequest::parse(&join("seconds='NaN' maxchars='inf' maxstanzas='2.9'"), 40);
    assert_eq!(request.maxstanzas, Some(2));
    assert_eq!(request.maxchars, None);
    assert_eq!(request.since, None);
}
