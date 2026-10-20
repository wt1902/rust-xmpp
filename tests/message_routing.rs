use rust_xmpp::sessions::Hub;
use std::time::Duration;
use tokio::sync::mpsc;

#[test]
fn unknown_resource_falls_back_to_available_bare_jid() {
    let hub = Hub::default();
    let (tx, _rx) = mpsc::channel(8);
    let s = hub
        .bind("bob@example.test/phone", "c", tx, Duration::from_secs(30))
        .unwrap();
    s.lock().unwrap().available = true;
    let targets = hub.message_targets("bob@example.test/old-resource");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].lock().unwrap().jid, "bob@example.test/phone");
}

#[test]
fn headline_uses_all_nonnegative_available_resources_and_errors_never_fallback() {
    let hub = Hub::default();
    let mut receivers = vec![];
    for (resource, available, priority) in [
        ("high", true, 5),
        ("low", true, 1),
        ("negative", true, -1),
        ("unavailable", false, 10),
    ] {
        let (tx, rx) = mpsc::channel(8);
        receivers.push(rx);
        let s = hub
            .bind(
                &format!("bob@example.test/{resource}"),
                resource,
                tx,
                Duration::from_secs(30),
            )
            .unwrap();
        let mut state = s.lock().unwrap();
        state.available = available;
        state.priority = priority;
    }
    let names = |to: &str, kind: &str| {
        let mut names = hub
            .message_targets_for_type(to, kind)
            .iter()
            .map(|s| s.lock().unwrap().jid.clone())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    assert_eq!(
        names("bob@example.test", "normal"),
        ["bob@example.test/high"]
    );
    assert_eq!(
        names("bob@example.test", "headline"),
        ["bob@example.test/high", "bob@example.test/low"]
    );
    assert_eq!(
        names("bob@example.test/negative", "headline"),
        ["bob@example.test/negative"]
    );
    assert_eq!(
        names("bob@example.test/absent", "chat"),
        ["bob@example.test/high"]
    );
    for kind in ["error", "groupchat"] {
        assert!(names("bob@example.test", kind).is_empty());
        assert!(names("bob@example.test/absent", kind).is_empty());
        assert_eq!(
            names("bob@example.test/low", kind),
            ["bob@example.test/low"]
        );
    }
    assert!(names("bob@example.test/absent", "headline").is_empty());
}
