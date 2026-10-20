use rust_xmpp::auth;
#[test]
fn create_and_read_hashed_accounts() {
    for hash in ["SHA-1", "SHA-256"] {
        let dir = tempfile::tempdir().unwrap();
        auth::create(dir.path(), "test.local", "alice", "pässword", hash).unwrap();
        assert!(auth::verify(dir.path(), "test.local", "alice", "pässword", hash).unwrap());
        assert!(!auth::verify(dir.path(), "test.local", "alice", "incorrect", hash).unwrap());
        assert!(!auth::verify(dir.path(), "test.local", "missing", "pässword", hash).unwrap());
        assert!(auth::create(dir.path(), "test.local", "alice", "replacement", hash).is_err());
        assert!(auth::verify(dir.path(), "test.local", "alice", "pässword", hash).unwrap());
        let path = dir.path().join("test%2elocal/accounts/alice.dat");
        let bytes = std::fs::read_to_string(&path).unwrap();
        assert!(!bytes.contains("pässword"));
        std::fs::write(
            &path,
            bytes.replace("return {", "return { disabled = true;"),
        )
        .unwrap();
        assert!(!auth::verify(dir.path(), "test.local", "alice", "pässword", hash).unwrap());
    }
}
#[test]
fn traversal_and_malicious_account_records_rejected() {
    let dir = tempfile::tempdir().unwrap();
    assert!(auth::create(dir.path(), "test.local", "../escape", "x", "SHA-1").is_err());
    auth::create(dir.path(), "test.local", "alice", "x", "SHA-1").unwrap();
    std::fs::write(
        dir.path().join("test%2elocal/accounts/alice.dat"),
        "return os.execute('false')",
    )
    .unwrap();
    assert!(auth::verify(dir.path(), "test.local", "alice", "x", "SHA-1").is_err());
}

#[test]
fn authentication_prepares_names_without_relaxing_account_management() {
    for hash in ["SHA-1", "SHA-256"] {
        let dir = tempfile::tempdir().unwrap();
        auth::create(dir.path(), "test.local", "alice", "secret", hash).unwrap();
        for supplied in ["ALICE", "Ａlice", "al\u{00ad}ice"] {
            assert_eq!(auth::prepared_auth_username(supplied).unwrap(), "alice");
            assert!(auth::verify(dir.path(), "test.local", supplied, "secret", hash).unwrap());
            assert!(!auth::verify(dir.path(), "test.local", supplied, "wrong", hash).unwrap());
            assert!(
                auth::load_scram(dir.path(), "test.local", supplied, hash)
                    .unwrap()
                    .is_none()
            );
            assert!(auth::create(dir.path(), "test.local", supplied, "secret", hash).is_err());
        }
        for invalid in ["", "alice@example.com", "../escape", "alice\u{0007}"] {
            assert!(auth::prepared_auth_username(invalid).is_err());
            assert!(!auth::verify(dir.path(), "test.local", invalid, "secret", hash).unwrap());
        }
    }
}
