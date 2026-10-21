use rust_xmpp::sessions::Hub;
use std::{sync::mpsc, thread, time::Duration};
use tokio::sync::mpsc as async_mpsc;

#[test]
fn unrelated_busy_session_does_not_block_account_routing_or_carbons_selection() {
    let hub = Hub::default();
    let (a_tx, _a_rx) = async_mpsc::channel(8);
    let (b_tx, mut b_rx) = async_mpsc::channel(8);
    let a = hub
        .bind("alice@x/r", "a", a_tx, Duration::from_secs(30))
        .unwrap();
    let b = hub
        .bind("bob@x/r", "b", b_tx, Duration::from_secs(30))
        .unwrap();
    b.lock().unwrap().available = true;
    let held = a.lock().unwrap();
    let (done, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        assert_eq!(hub.message_targets("bob@x").len(), 1);
        assert_eq!(hub.for_owners(&["bob@x", "bob@x"]).len(), 1);
        assert_eq!(hub.deliver("bob@x", "bare"), 1);
        assert_eq!(hub.deliver("bob@x/r", "full"), 1);
        done.send(()).unwrap();
    });
    let completed_while_locked = result.recv_timeout(Duration::from_secs(2)).is_ok();
    drop(held);
    worker.join().unwrap();
    assert!(
        completed_while_locked,
        "routing waited on unrelated account's session lock"
    );
    assert_eq!(b_rx.try_recv().unwrap(), "bare");
    assert_eq!(b_rx.try_recv().unwrap(), "full");
}

#[test]
fn duplicate_acknowledgement_does_not_rewrite_durable_slot() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = async_mpsc::channel(8);
    let session = hub
        .bind("bob@x/r", "b", tx, Duration::from_secs(30))
        .unwrap();
    let mut state = session.lock().unwrap();
    state.enable(true).unwrap();
    let path = dir
        .path()
        .join(format!("{}.json", state.resume_id.as_deref().unwrap()));
    let marker = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(marker))
        .unwrap();
    state.ack_requested = true;
    state.acknowledge(0).unwrap();
    assert!(!state.ack_requested);
    assert_eq!(std::fs::metadata(path).unwrap().modified().unwrap(), marker);
    assert!(state.acknowledge(1).is_err());
}
