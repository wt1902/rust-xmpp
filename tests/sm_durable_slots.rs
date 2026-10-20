//! Process-independent durable SM slots; network SIGKILL coverage lives in sm_restart_network.py.
use rust_xmpp::sessions::{ConflictPolicy, Hub};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[test]
fn restart_restores_owner_presence_and_only_unacknowledged_output() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let session = hub
        .bind("a@x/mobile", "original", tx, Duration::from_secs(60))
        .unwrap();
    let token;
    {
        let mut state = session.lock().unwrap();
        state.enable(true).unwrap();
        token = state.resume_id.clone().unwrap();
        state.available = true;
        state.priority = 3;
        state.presence = Some("<presence><show>away</show></presence>".into());
        state.client_id = Some("mobile-client".into());
        state.csi.set_inactive(true);
        state.mark_handled().unwrap();
        state.transmit("first".into()).unwrap();
        state.transmit("second".into()).unwrap();
        state.acknowledge(1).unwrap();
    }
    assert_eq!(rx.try_recv().unwrap(), "first");
    drop(hub);
    let recovered = Hub::persistent(dir.path()).unwrap();
    let state = recovered.get("a@x/mobile").unwrap();
    {
        let state = state.lock().unwrap();
        assert!(state.sender.is_none());
        assert!(state.available);
        assert_eq!(state.priority, 3);
        assert_eq!(state.handled, 1);
        assert_eq!(state.client_id.as_deref(), Some("mobile-client"));
        assert_eq!(
            state.pending.iter().cloned().collect::<Vec<_>>(),
            ["second"]
        );
    }
    let (tx, _rx) = mpsc::channel(8);
    assert!(
        recovered
            .resume("attacker@x", &token, 1, "bad", tx.clone())
            .is_err()
    );
    assert!(
        recovered
            .resume("a@x", &token, 3, "bad", tx.clone())
            .is_err()
    );
    let (resumed, replay) = recovered
        .resume("a@x", &token, 1, "replacement", tx)
        .unwrap();
    assert!(replay[0].contains("h='1'"));
    assert_eq!(replay[1], "second");
    assert!(state.lock().unwrap().acknowledge(2).is_err());
    resumed.lock().unwrap().acknowledge(2).unwrap();
    drop(recovered);
    let recovered = Hub::persistent(dir.path()).unwrap();
    assert!(
        recovered
            .get("a@x/mobile")
            .unwrap()
            .lock()
            .unwrap()
            .pending
            .is_empty()
    );
}

#[test]
fn disconnected_deadline_is_fixed_across_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    session.lock().unwrap().enable(true).unwrap();
    hub.disconnect("c", false);
    let deadline = session.lock().unwrap().expires.unwrap();
    hub.disconnect("c", false);
    assert_eq!(session.lock().unwrap().expires.unwrap(), deadline);
    drop(hub);
    let recovered = Hub::persistent(dir.path()).unwrap();
    let recovered_deadline = recovered
        .get("a@x/r")
        .unwrap()
        .lock()
        .unwrap()
        .expires
        .unwrap();
    assert!(recovered_deadline <= deadline + Duration::from_millis(2));
    assert!(recovered_deadline >= deadline - Duration::from_millis(5));
}

#[test]
fn graceful_close_conflict_account_purge_and_expiration_remove_tokens() {
    for action in ["close", "conflict", "purge", "expire"] {
        let dir = tempfile::tempdir().unwrap();
        let hub = Hub::persistent(dir.path()).unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let session = hub
            .bind("a@x/r", "c", tx.clone(), Duration::from_secs(60))
            .unwrap();
        session.lock().unwrap().enable(true).unwrap();
        let token = session.lock().unwrap().resume_id.clone().unwrap();
        match action {
            "close" => {
                hub.disconnect("c", true);
            }
            "purge" => hub.kick_owner("a@x"),
            "conflict" => {
                hub.bind_resolving(
                    "a@x/r",
                    "new",
                    tx.clone(),
                    Duration::from_secs(60),
                    ConflictPolicy::KickOld,
                )
                .unwrap();
            }
            _ => {
                session.lock().unwrap().expires = Some(Instant::now());
                hub.expired();
            }
        }
        drop(hub);
        let recovered = Hub::persistent(dir.path()).unwrap();
        assert!(
            recovered.resume("a@x", &token, 0, "after", tx).is_err(),
            "{action}"
        );
    }
}

#[test]
fn store_has_one_process_owner_and_enforces_output_byte_bound() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    assert!(Hub::persistent(dir.path()).is_err());
    let (tx, mut rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    let mut state = session.lock().unwrap();
    state.enable(true).unwrap();
    assert!(state.transmit("x".repeat(8 * 1024 * 1024 + 1)).is_err());
    // Fits the payload limit but exceeds the serialized slot limit: persistence
    // failure must also roll counters back and keep bytes off the transport.
    assert!(state.transmit("x".repeat(8 * 1024 * 1024)).is_err());
    assert_eq!(state.sent, 0);
    assert!(state.pending.is_empty());
    assert!(rx.try_recv().is_err());
}

#[test]
fn shutdown_freeze_retires_old_transport_before_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let old = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    old.lock().unwrap().enable(true).unwrap();
    old.lock().unwrap().transmit("pending".into()).unwrap();
    let token = old.lock().unwrap().resume_id.clone().unwrap();
    hub.freeze().unwrap();
    assert!(old.lock().unwrap().acknowledge(1).is_err());
    assert!(old.lock().unwrap().transmit("stale".into()).is_err());
    assert!(hub.disconnect("c", true).is_empty());
    drop(hub);
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let (_, replay) = hub.resume("a@x", &token, 0, "fresh", tx).unwrap();
    assert_eq!(replay[1], "pending");
}

#[test]
fn durable_counters_wrap_without_accepting_stale_acknowledgements() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    {
        let mut state = session.lock().unwrap();
        state.enable(true).unwrap();
        state.sent = u32::MAX;
        state.acked = u32::MAX;
        state.handled = u32::MAX;
        state.mark_handled().unwrap();
        state.transmit("wrapped".into()).unwrap();
    }
    drop(hub);
    let hub = Hub::persistent(dir.path()).unwrap();
    let session = hub.get("a@x/r").unwrap();
    let mut state = session.lock().unwrap();
    assert_eq!(state.handled, 0);
    assert_eq!(state.sent, 0);
    assert!(state.acknowledge(u32::MAX - 1).is_err());
    state.acknowledge(0).unwrap();
    assert!(state.pending.is_empty());
}

#[test]
#[cfg(unix)]
fn durable_tokens_and_private_pending_output_have_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    session.lock().unwrap().enable(true).unwrap();
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn recovery_discards_owned_crash_temps_and_keeps_last_committed_slot() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    let token;
    {
        let mut state = session.lock().unwrap();
        state.enable(true).unwrap();
        state.transmit("committed".into()).unwrap();
        token = state.resume_id.clone().unwrap();
    }
    drop(hub);
    let interrupted = dir.path().join(format!("{token}.tmp"));
    let orphan = dir.path().join(format!("{}.tmp", uuid::Uuid::new_v4()));
    let unknown = dir.path().join("notes.tmp");
    let unknown_dir = dir.path().join(format!("{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&interrupted, b"{\"pending\": [\"uncommitted").unwrap();
    std::fs::write(&orphan, b"incomplete").unwrap();
    std::fs::write(&unknown, b"preserve").unwrap();
    std::fs::create_dir(&unknown_dir).unwrap();
    let recovered = Hub::persistent(dir.path()).unwrap();
    assert!(!interrupted.exists());
    assert!(!orphan.exists());
    assert!(unknown.exists());
    assert!(unknown_dir.is_dir());
    let session = recovered.get("a@x/r").unwrap();
    let state = session.lock().unwrap();
    assert_eq!(state.sent, 1);
    assert_eq!(
        state.pending.iter().cloned().collect::<Vec<_>>(),
        ["committed"]
    );
}

#[test]
fn corrupt_committed_slot_fails_recovery_closed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(format!("{}.json", uuid::Uuid::new_v4())),
        b"{incomplete",
    )
    .unwrap();
    assert!(Hub::persistent(dir.path()).is_err());
}

#[test]
fn independent_hubs_with_identical_connection_names_keep_their_own_slots() {
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let first = Hub::persistent(first_dir.path()).unwrap();
    let second = Hub::persistent(second_dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let a = first
        .bind("a@x/r", "c", tx.clone(), Duration::from_secs(60))
        .unwrap();
    let b = second
        .bind("a@x/r", "c", tx, Duration::from_secs(60))
        .unwrap();
    a.lock().unwrap().enable(true).unwrap();
    b.lock().unwrap().enable(true).unwrap();
    a.lock().unwrap().transmit("first hub".into()).unwrap();
    b.lock().unwrap().transmit("second hub".into()).unwrap();
    first.disconnect("c", true);
    drop(first);
    drop(second);
    let first = Hub::persistent(first_dir.path()).unwrap();
    let second = Hub::persistent(second_dir.path()).unwrap();
    assert!(first.get("a@x/r").is_none());
    let b = second.get("a@x/r").unwrap();
    assert_eq!(
        b.lock().unwrap().pending.front().map(String::as_str),
        Some("second hub")
    );
}

#[test]
fn session_reference_does_not_keep_store_locked_or_allow_unpersisted_writes() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let old = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    old.lock().unwrap().enable(true).unwrap();
    drop(hub);
    let recovered = Hub::persistent(dir.path()).unwrap();
    assert!(old.lock().unwrap().checkpoint().is_err());
    assert!(old.lock().unwrap().transmit("orphaned".into()).is_err());
    assert_eq!(old.lock().unwrap().sent, 0);
    assert!(
        recovered
            .get("a@x/r")
            .unwrap()
            .lock()
            .unwrap()
            .pending
            .is_empty()
    );
}
