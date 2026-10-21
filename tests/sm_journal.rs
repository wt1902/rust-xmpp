//! Redo recovery is independent of the best-effort readable JSON export.
use rust_xmpp::sessions::Hub;
use std::{fs, io::Write, path::Path, time::Duration};
use tokio::sync::mpsc;

fn committed(dir: &Path) -> (String, Vec<u8>) {
    let hub = Hub::persistent(dir).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    let mut state = session.lock().unwrap();
    state.enable(true).unwrap();
    state.transmit("durable".into()).unwrap();
    let token = state.resume_id.clone().unwrap();
    let json = fs::read(dir.join(format!("{token}.json"))).unwrap();
    drop(state);
    drop(hub);
    (token, json)
}

#[test]
fn redo_repairs_missing_or_torn_export_before_json_validation() {
    for torn in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (token, _) = committed(dir.path());
        let json = dir.path().join(format!("{token}.json"));
        if torn {
            fs::write(&json, b"{torn").unwrap();
        } else {
            fs::remove_file(&json).unwrap();
        }
        let hub = Hub::persistent(dir.path()).unwrap();
        assert_eq!(
            hub.get("a@x/r")
                .unwrap()
                .lock()
                .unwrap()
                .pending
                .front()
                .map(String::as_str),
            Some("durable")
        );
        let export: serde_json::Value = serde_json::from_slice(&fs::read(json).unwrap()).unwrap();
        assert_eq!(export["pending"][0], "durable");
    }
}

#[test]
fn partial_tail_is_discarded_and_subsequent_commits_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (token, _) = committed(dir.path());
    let wal = dir.path().join(format!("{token}.wal"));
    let good_len = fs::metadata(&wal).unwrap().len();
    fs::OpenOptions::new()
        .append(true)
        .open(&wal)
        .unwrap()
        .write_all(&[42, 0, 0])
        .unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    assert_eq!(fs::metadata(&wal).unwrap().len(), good_len);
    hub.get("a@x/r")
        .unwrap()
        .lock()
        .unwrap()
        .mark_handled()
        .unwrap();
    drop(hub);
    let hub = Hub::persistent(dir.path()).unwrap();
    assert_eq!(hub.get("a@x/r").unwrap().lock().unwrap().handled, 1);
}

#[test]
fn complete_corrupt_frame_fails_closed_even_with_valid_export() {
    let dir = tempfile::tempdir().unwrap();
    let (token, _) = committed(dir.path());
    let wal = dir.path().join(format!("{token}.wal"));
    let mut bytes = fs::read(&wal).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(wal, bytes).unwrap();
    assert!(Hub::persistent(dir.path()).is_err());
}

#[test]
fn durable_tombstone_overrides_resurrected_stale_json() {
    let dir = tempfile::tempdir().unwrap();
    let (token, old) = committed(dir.path());
    let hub = Hub::persistent(dir.path()).unwrap();
    hub.kick_owner("a@x");
    drop(hub);
    fs::write(dir.path().join(format!("{token}.json")), old).unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    assert!(hub.get("a@x/r").is_none());
}

#[test]
fn legacy_json_migrates_and_baseline_survives_partial_first_append() {
    let dir = tempfile::tempdir().unwrap();
    let (token, _) = committed(dir.path());
    let wal = dir.path().join(format!("{token}.wal"));
    fs::remove_file(&wal).unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    hub.get("a@x/r")
        .unwrap()
        .lock()
        .unwrap()
        .mark_handled()
        .unwrap();
    drop(hub);
    let bytes = fs::read(&wal).unwrap();
    let baseline_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    fs::write(&wal, &bytes[..8 + 40 + baseline_len + 12]).unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let session = hub.get("a@x/r").unwrap();
    let state = session.lock().unwrap();
    assert_eq!(state.handled, 0);
    assert_eq!(state.pending.front().map(String::as_str), Some("durable"));
}

#[test]
fn rotation_preserves_latest_snapshot_and_bounds_redo_size() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    let token;
    {
        let mut state = session.lock().unwrap();
        state.enable(true).unwrap();
        token = state.resume_id.clone().unwrap();
        state.transmit("x".repeat(1024 * 1024)).unwrap();
        for _ in 0..35 {
            state.mark_handled().unwrap();
        }
    }
    let wal = dir.path().join(format!("{token}.wal"));
    assert!(fs::metadata(wal).unwrap().len() < 18 * 1024 * 1024);
    drop(hub);
    let hub = Hub::persistent(dir.path()).unwrap();
    let session = hub.get("a@x/r").unwrap();
    let state = session.lock().unwrap();
    assert_eq!(state.handled, 35);
    assert_eq!(state.pending.front().unwrap().len(), 1024 * 1024);
}

#[test]
fn incomplete_baseline_or_magic_never_falls_back_to_json() {
    for keep in [0, 4, 8, 12, 48] {
        let dir = tempfile::tempdir().unwrap();
        let (token, _) = committed(dir.path());
        let wal = dir.path().join(format!("{token}.wal"));
        let bytes = fs::read(&wal).unwrap();
        fs::write(wal, &bytes[..keep]).unwrap();
        assert!(
            Hub::persistent(dir.path()).is_err(),
            "truncated baseline at {keep}"
        );
    }
}

#[test]
#[cfg(unix)]
fn journal_symlink_is_rejected_without_following_target() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let (token, _) = committed(dir.path());
    let wal = dir.path().join(format!("{token}.wal"));
    let other = tempfile::NamedTempFile::new().unwrap();
    fs::remove_file(&wal).unwrap();
    symlink(other.path(), wal).unwrap();
    assert!(Hub::persistent(dir.path()).is_err());
}

#[test]
fn export_failure_after_commit_advances_memory_and_fences_later_writes() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    session.lock().unwrap().enable(true).unwrap();
    let token = session.lock().unwrap().resume_id.clone().unwrap();
    let obstruction = dir.path().join(format!("{token}.tmp"));
    fs::create_dir(&obstruction).unwrap();
    {
        let mut state = session.lock().unwrap();
        state.mark_handled().unwrap();
        assert_eq!(state.handled, 1);
        assert!(state.mark_handled().is_err());
        assert_eq!(state.handled, 1);
    }
    drop(hub);
    fs::remove_dir(obstruction).unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    assert_eq!(hub.get("a@x/r").unwrap().lock().unwrap().handled, 1);
}

#[test]
fn retired_journals_are_collected_in_bounded_batches() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    for index in 0..64 {
        let (tx, _rx) = mpsc::channel(1);
        let connection = format!("c{index}");
        let session = hub
            .bind("a@x/r", &connection, tx, Duration::from_secs(60))
            .unwrap();
        session.lock().unwrap().enable(true).unwrap();
        hub.disconnect(&connection, true);
    }
    assert_eq!(
        fs::read_dir(dir.path())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "wal")
            })
            .count(),
        0
    );
    drop(hub);
    assert!(Hub::persistent(dir.path()).unwrap().get("a@x/r").is_none());
}

#[test]
fn offline_checkpoint_repairs_exports_removes_redo_and_allows_legacy_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (token, _) = committed(dir.path());
    let json = dir.path().join(format!("{token}.json"));
    fs::write(&json, b"{torn").unwrap();
    assert_eq!(
        rust_xmpp::session_store::checkpoint_exports(dir.path()).unwrap(),
        1
    );
    assert!(!dir.path().join(format!("{token}.wal")).exists());
    let export: serde_json::Value = serde_json::from_slice(&fs::read(json).unwrap()).unwrap();
    assert_eq!(export["pending"][0], "durable");
    let hub = Hub::persistent(dir.path()).unwrap();
    let session = hub.get("a@x/r").unwrap();
    assert_eq!(
        session.lock().unwrap().pending.front().map(String::as_str),
        Some("durable")
    );
    session.lock().unwrap().mark_handled().unwrap();
    assert!(dir.path().join(format!("{token}.wal")).exists());
}

#[test]
fn offline_checkpoint_refuses_live_store_and_preserves_redo() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    session.lock().unwrap().enable(true).unwrap();
    let token = session.lock().unwrap().resume_id.clone().unwrap();
    assert!(rust_xmpp::session_store::checkpoint_exports(dir.path()).is_err());
    assert!(dir.path().join(format!("{token}.wal")).exists());
}

#[test]
fn offline_checkpoint_durably_applies_expiration_and_tombstones() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    let token;
    {
        let mut state = session.lock().unwrap();
        state.enable(true).unwrap();
        token = state.resume_id.clone().unwrap();
        state.expires = Some(std::time::Instant::now());
        state.checkpoint().unwrap();
    }
    drop(hub);
    assert_eq!(
        rust_xmpp::session_store::checkpoint_exports(dir.path()).unwrap(),
        0
    );
    assert!(!dir.path().join(format!("{token}.json")).exists());
    assert!(!dir.path().join(format!("{token}.wal")).exists());
    assert!(Hub::persistent(dir.path()).unwrap().get("a@x/r").is_none());
}

#[test]
fn superseded_frames_still_require_valid_checksums_json_and_baseline_flags() {
    use sha2::{Digest, Sha256};
    for damage in ["checksum", "json", "baseline"] {
        let dir = tempfile::tempdir().unwrap();
        let (token, _) = committed(dir.path());
        let wal = dir.path().join(format!("{token}.wal"));
        let mut bytes = fs::read(&wal).unwrap();
        // Damage the baseline, leaving both later committed snapshots intact.
        let mut len = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let mut payload = 48..48 + len as usize;
        match damage {
            "checksum" => bytes[payload.end - 1] ^= 1,
            "json" => bytes[payload.end - 1] = b'!',
            "baseline" => {
                let start = bytes[payload.clone()]
                    .windows(4)
                    .position(|part| part == b"true")
                    .unwrap()
                    + payload.start;
                // Preserve valid JSON, but make the first frame a continuation.
                bytes.splice(start..start + 4, b"false".iter().copied());
                len += 1;
                payload.end += 1;
                bytes[8..12].copy_from_slice(&len.to_le_bytes());
                bytes[12..16].copy_from_slice(&(!len).to_le_bytes());
            }
            _ => unreachable!(),
        }
        if damage != "checksum" {
            let checksum = Sha256::digest(&bytes[payload]);
            bytes[16..48].copy_from_slice(&checksum);
        }
        fs::write(wal, bytes).unwrap();
        assert!(Hub::persistent(dir.path()).is_err(), "{damage}");
    }
}

#[test]
fn deferred_online_commits_are_flushed_and_recovered() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    hub.set_defer_online(true);
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("a@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    let token;
    let durable_after_enable;
    {
        let mut state = session.lock().unwrap();
        state.enable(true).unwrap();
        token = state.resume_id.clone().unwrap();
        durable_after_enable = fs::read(dir.path().join(format!("{token}.wal"))).unwrap();
        // A live session's outbound stanza must not force a durable fsync in
        // deferred mode: the WAL stays exactly as written by enable(), while the
        // session records dirty state for the background flush.
        state.transmit("online-deferred".into()).unwrap();
        assert_eq!(
            fs::read(dir.path().join(format!("{token}.wal"))).unwrap(),
            durable_after_enable,
            "live deferred transmit changed durable WAL"
        );
        assert!(
            state.dirty,
            "deferred online commit did not mark session dirty"
        );
    }
    // The background flush persists the deferred queue durably.
    hub.flush_dirty().unwrap();
    drop(session);
    drop(hub);
    let hub = Hub::persistent(dir.path()).unwrap();
    let session = hub.get("a@x/r").unwrap();
    let state = session.lock().unwrap();
    assert_eq!(
        state.pending.iter().map(String::as_str).collect::<Vec<_>>(),
        ["online-deferred"]
    );
    assert!(!state.dirty);
}

#[test]
fn deferred_mode_keeps_offline_targets_durable() {
    let dir = tempfile::tempdir().unwrap();
    let hub = Hub::persistent(dir.path()).unwrap();
    hub.set_defer_online(true);
    let (tx, _rx) = mpsc::channel(8);
    let session = hub.bind("b@x/r", "c", tx, Duration::from_secs(60)).unwrap();
    let token;
    {
        let mut state = session.lock().unwrap();
        state.enable(true).unwrap();
        token = state.resume_id.clone().unwrap();
        // Hibernated/offline transports (sender == None) still commit durably
        // before the pending queue is consumed, even under deferred mode.
        state.sender = None;
        state.track_outbound("offline-durable").unwrap();
        state.checkpoint().unwrap();
        let durable: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join(format!("{token}.json"))).unwrap())
                .unwrap();
        assert_eq!(durable["pending"][0], "offline-durable");
    }
    drop(hub);
    let hub = Hub::persistent(dir.path()).unwrap();
    let session = hub.get("b@x/r").unwrap();
    let state = session.lock().unwrap();
    assert_eq!(
        state.pending.iter().map(String::as_str).collect::<Vec<_>>(),
        ["offline-durable"]
    );
}
