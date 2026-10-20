use rust_xmpp::{
    admin::{AdminBackend, AdminServer, AdminSnapshot, query},
    auth,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
#[tokio::test]
#[ignore = "requires AF_UNIX socket permission; run on target host with --ignored"]
async fn prosody_wire_commands_password_prompt_and_safe_errors() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("prosody.sock");
    let backend = AdminBackend {
        data: dir.path().into(),
        hosts: BTreeMap::from([("example.com".into(), "SHA-256".into())]),
        modules: BTreeMap::from([(
            "example.com".into(),
            vec!["admin_shell".into(), "tls".into()],
        )]),
        snapshot: Arc::new(|| AdminSnapshot {
            uptime: Duration::from_secs(123),
            sessions: vec!["alice@example.com/r".into()],
        }),
        delete_user: None,
        disconnect_user: None,
    };
    let server = AdminServer::bind(&socket, backend.clone()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(AdminServer::bind(&socket, backend).is_err());
    let task = tokio::spawn(server.serve());
    let result = query(&socket, "server:status()", None).await.unwrap();
    assert!(!result.error);
    assert_eq!(result.message, "OK: running");
    let result = query(&socket, "{\"c2s\",\"count\"}", None).await.unwrap();
    assert_eq!(result.message, "OK: Total: 1 clients");
    {
        use tokio::io::AsyncWriteExt;
        let mut client = tokio::net::UnixStream::connect(&socket).await.unwrap();
        client.write_all(b"<a:stream xmlns:a='http://etherx.jabber.org/streams' xmlns='xmpp:prosody.im/admin' xmlns:q='xmpp:prosody.im/admin'><q:repl-input>server:version()</q:repl-input>").await.unwrap();
        let mut framer = rust_xmpp::wire::Framer::default();
        framer.next(&mut client).await.unwrap();
        let response = framer.next(&mut client).await.unwrap();
        assert!(response.contains("rust-xmpp"));
    }
    let result = query(&socket, "c2s:show()", None).await.unwrap();
    assert_eq!(result.output, vec!["alice@example.com/r"]);
    let result = query(
        &socket,
        "user:create('alice@example.com')",
        Some("initial<&password"),
    )
    .await
    .unwrap();
    assert!(!result.error, "{}", result.message);
    assert!(
        auth::verify(
            dir.path(),
            "example.com",
            "alice",
            "initial<&password",
            "SHA-256"
        )
        .unwrap()
    );
    let result = query(
        &socket,
        "user:password('alice@example.com','changed')",
        None,
    )
    .await
    .unwrap();
    assert!(!result.error);
    assert!(auth::verify(dir.path(), "example.com", "alice", "changed", "SHA-256").unwrap());
    let result = query(&socket, "user:disable('alice@example.com')", None)
        .await
        .unwrap();
    assert!(!result.error);
    assert!(!auth::verify(dir.path(), "example.com", "alice", "changed", "SHA-256").unwrap());
    let result = query(&socket, "user:enable('alice@example.com')", None)
        .await
        .unwrap();
    assert!(!result.error);
    assert!(auth::verify(dir.path(), "example.com", "alice", "changed", "SHA-256").unwrap());
    for command in [
        "module:reload('tls')",
        "os.execute('echo unauthorized')",
        "user:delete('alice@example.com')",
        "user:create('bob@example.com',nil,'prosody:admin')",
    ] {
        let result = query(&socket, command, None).await.unwrap();
        assert!(result.error, "{command}");
    }
    let result = query(&socket, "user:password('alice@example.com')", None)
        .await
        .unwrap();
    assert!(result.error);
    assert!(auth::verify(dir.path(), "example.com", "alice", "changed", "SHA-256").unwrap());
    task.abort();
    let _ = task.await;
    assert!(!socket.exists());
}
