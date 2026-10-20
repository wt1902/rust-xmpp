use rust_xmpp::sessions::{ConflictPolicy, Hub};
use std::sync::{Arc, Barrier};
use std::time::Duration;
use tokio::sync::mpsc;

const JID: &str = "alice@example.test/Monal";
const TTL: Duration = Duration::from_secs(300);

#[test]
fn concurrent_default_binds_replace_atomically() {
    let hub = Hub::default();
    let barrier = Arc::new(Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let hub = hub.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let (tx, _rx) = mpsc::channel(8);
                barrier.wait();
                hub.bind_resolving(
                    JID,
                    &format!("connection-{i}"),
                    tx,
                    TTL,
                    ConflictPolicy::from_config(None),
                )
                .unwrap()
            })
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(hub.all().len(), 1);
    assert_eq!(outcomes.iter().filter(|(_, old)| old.is_some()).count(), 15);
    let current = hub.get(JID).unwrap();
    for (session, replaced) in outcomes {
        let state = session.lock().unwrap();
        assert_eq!(state.closed, !Arc::ptr_eq(&session, &current));
        if let Some(old) = replaced {
            let old = old.lock().unwrap();
            assert!(old.closed);
            assert!(old.sender.is_none());
            assert!(old.resume_id.is_none());
            assert!(old.expires.is_none());
        }
    }
}

#[test]
fn kick_new_leaves_existing_session_unchanged() {
    let hub = Hub::default();
    let (tx, mut rx) = mpsc::channel(8);
    let old = hub.bind(JID, "old", tx, TTL).unwrap();
    let id = {
        let mut state = old.lock().unwrap();
        state.enable(true).unwrap();
        state.resume_id.clone().unwrap()
    };
    let (tx, _rx) = mpsc::channel(8);
    assert!(
        hub.bind_resolving(JID, "new", tx, TTL, ConflictPolicy::KickNew)
            .is_err()
    );
    assert!(Arc::ptr_eq(&old, &hub.get(JID).unwrap()));
    let mut state = old.lock().unwrap();
    assert!(!state.closed);
    assert_eq!(state.connection, "old");
    assert_eq!(state.resume_id.as_deref(), Some(id.as_str()));
    state.transmit("still-connected".into()).unwrap();
    assert_eq!(rx.try_recv().unwrap(), "still-connected");
}

#[test]
fn increment_skips_occupied_suffixes_and_preserves_sessions() {
    let hub = Hub::default();
    for suffix in ["", "#1", "#2", "#4"] {
        let (tx, _rx) = mpsc::channel(8);
        hub.bind(&format!("{JID}{suffix}"), suffix, tx, TTL)
            .unwrap();
    }
    let (tx, _rx) = mpsc::channel(8);
    let (session, replaced) = hub
        .bind_resolving(JID, "new", tx, TTL, ConflictPolicy::Increment)
        .unwrap();
    assert_eq!(session.lock().unwrap().jid, format!("{JID}#3"));
    assert!(replaced.is_none());
    assert_eq!(hub.all().len(), 5);
    assert!(hub.all().iter().all(|s| !s.lock().unwrap().closed));
}

#[test]
fn random_conflicts_get_distinct_resources_for_same_owner() {
    let hub = Hub::default();
    let (tx, _rx) = mpsc::channel(8);
    let original = hub.bind(JID, "original", tx, TTL).unwrap();
    let mut names = std::collections::BTreeSet::new();
    names.insert(JID.to_owned());
    for i in 0..32 {
        let (tx, _rx) = mpsc::channel(8);
        let (session, replaced) = hub
            .bind_resolving(JID, &format!("new-{i}"), tx, TTL, ConflictPolicy::Random)
            .unwrap();
        let state = session.lock().unwrap();
        assert_eq!(state.owner, "alice@example.test");
        assert!(names.insert(state.jid.clone()));
        assert!(replaced.is_none());
    }
    assert!(Arc::ptr_eq(&original, &hub.get(JID).unwrap()));
    assert_eq!(hub.all().len(), 33);
}

#[tokio::test]
async fn active_resume_preserves_state_and_replaces_transport_notifier() {
    let hub = Hub::default();
    let (tx, _old_rx) = mpsc::channel(8);
    let original = hub.bind(JID, "old", tx, TTL).unwrap();
    let (id, old_cancel) = {
        let mut state = original.lock().unwrap();
        state.enable(true).unwrap();
        state.handled = 7;
        state.client_id = Some("device".into());
        state.transmit("one".into()).unwrap();
        state.transmit("two".into()).unwrap();
        (state.resume_id.clone().unwrap(), state.cancel.clone())
    };
    let (tx, mut new_rx) = mpsc::channel(8);
    let (resumed, replay) = hub.resume("alice@example.test", &id, 1, "new", tx).unwrap();
    assert!(!Arc::ptr_eq(&original, &resumed));
    assert!(original.lock().unwrap().closed);
    assert_eq!(replay.len(), 2);
    assert!(replay[0].contains("h='7'"));
    assert_eq!(replay[1], "two");
    {
        let mut retired = original.lock().unwrap();
        assert!(retired.acknowledge(2).is_err());
        assert!(retired.transmit("stale".into()).is_err());
        // Even in-flight code holding the retired Arc cannot touch the new counters.
        retired.handled = 999;
        retired.pending.push_back("stale".into());
    }
    let new_cancel = {
        let state = resumed.lock().unwrap();
        assert_eq!((state.handled, state.sent, state.acked), (7, 2, 1));
        assert_eq!(
            state.pending.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["two"]
        );
        assert_eq!(state.client_id.as_deref(), Some("device"));
        assert_eq!(state.resume_id.as_deref(), Some(id.as_str()));
        assert_eq!(state.connection, "new");
        assert!(state.expires.is_none());
        assert!(!state.closed);
        assert!(!Arc::ptr_eq(&old_cancel, &state.cancel));
        state.cancel.clone()
    };
    tokio::time::timeout(Duration::from_secs(1), old_cancel.notified())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), new_cancel.notified())
            .await
            .is_err()
    );
    resumed.lock().unwrap().transmit("three".into()).unwrap();
    assert_eq!(new_rx.try_recv().unwrap(), "three");
    for graceful in [false, true] {
        assert!(hub.disconnect("old", graceful).is_empty());
        assert!(Arc::ptr_eq(&resumed, &hub.get(JID).unwrap()));
    }
}

#[test]
fn invalid_resume_owner_or_ack_does_not_evict_active_session() {
    let hub = Hub::default();
    let (tx, mut old_rx) = mpsc::channel(8);
    let original = hub.bind(JID, "old", tx, TTL).unwrap();
    let (id, cancel) = {
        let mut state = original.lock().unwrap();
        state.enable(true).unwrap();
        state.transmit("one".into()).unwrap();
        (state.resume_id.clone().unwrap(), state.cancel.clone())
    };
    for (owner, h) in [("mallory@example.test", 0), ("alice@example.test", 2)] {
        let (tx, _rx) = mpsc::channel(8);
        assert!(hub.resume(owner, &id, h, "intruder", tx).is_err());
        let state = original.lock().unwrap();
        assert_eq!(state.connection, "old");
        assert_eq!((state.sent, state.acked, state.pending.len()), (1, 0, 1));
        assert!(Arc::ptr_eq(&cancel, &state.cancel));
        assert!(!state.closed);
        assert!(Arc::ptr_eq(&original, &hub.get(JID).unwrap()));
    }
    assert_eq!(old_rx.try_recv().unwrap(), "one");
    original.lock().unwrap().transmit("two".into()).unwrap();
    assert_eq!(old_rx.try_recv().unwrap(), "two");
}

#[test]
fn replacement_revokes_hibernating_resume_and_survives_old_cleanup() {
    let hub = Hub::default();
    let (tx, _rx) = mpsc::channel(8);
    let old = hub.bind(JID, "old", tx, TTL).unwrap();
    let id = {
        let mut state = old.lock().unwrap();
        state.enable(true).unwrap();
        state.resume_id.clone().unwrap()
    };
    assert!(hub.disconnect("old", false).is_empty());
    assert!(old.lock().unwrap().expires.is_some());
    let (tx, _rx) = mpsc::channel(8);
    let (new, replaced) = hub
        .bind_resolving(JID, "new", tx, TTL, ConflictPolicy::KickOld)
        .unwrap();
    assert!(Arc::ptr_eq(&old, &replaced.unwrap()));
    {
        let state = old.lock().unwrap();
        assert!(state.closed);
        assert!(state.resume_id.is_none());
        assert!(state.expires.is_none());
    }
    for graceful in [false, true] {
        assert!(hub.disconnect("old", graceful).is_empty());
        assert!(Arc::ptr_eq(&new, &hub.get(JID).unwrap()));
    }
    let (tx, _rx) = mpsc::channel(8);
    assert!(
        hub.resume("alice@example.test", &id, 0, "resurrect", tx)
            .is_err()
    );
    assert!(Arc::ptr_eq(&new, &hub.get(JID).unwrap()));
}
