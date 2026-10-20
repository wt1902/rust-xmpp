use rust_xmpp::federation::Federation;
use std::{fs, io::BufReader, path::Path, process::Command};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_rustls::rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
fn fixture(dir: &Path) {
    openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Federation Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
    );
    for domain in ["alpha.test", "beta.test"] {
        let key = format!("{domain}.key");
        let csr = format!("{domain}.csr");
        let cert = format!("{domain}.pem");
        let ext = format!("{domain}.ext");
        fs::write(dir.join(&ext),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{domain}\n")).unwrap();
        openssl(
            dir,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &key,
                "-out",
                &csr,
                "-subj",
                &format!("/CN={domain}"),
            ],
        );
        openssl(
            dir,
            &[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                &cert,
                "-days",
                "1",
                "-extfile",
                &ext,
            ],
        );
    }
}
fn material(
    dir: &Path,
    domain: &str,
) -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    RootCertStore,
) {
    let certs = rustls_pemfile::certs(&mut BufReader::new(
        fs::File::open(dir.join(format!("{domain}.pem"))).unwrap(),
    ))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let key = rustls_pemfile::private_key(&mut BufReader::new(
        fs::File::open(dir.join(format!("{domain}.key"))).unwrap(),
    ))
    .unwrap()
    .unwrap();
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(
        fs::File::open(dir.join("ca.pem")).unwrap(),
    )) {
        roots.add(cert.unwrap()).unwrap();
    }
    (certs, key, roots)
}
#[tokio::test(flavor = "multi_thread")]
async fn mutual_tls_external_delivery_and_certificate_identity_rejection() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path());
    let (a_cert, a_key, a_roots) = material(temp.path(), "alpha.test");
    let mut alice = Federation::new("alpha.test".into(), a_cert, a_key, a_roots).unwrap();
    let (b_cert, b_key, b_roots) = material(temp.path(), "beta.test");
    let bob = Federation::new("beta.test".into(), b_cert, b_key, b_roots).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    alice
        .set_target("beta.test".into(), "127.0.0.1".into(), port)
        .unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let bob = bob.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = bob.accept(tcp, tx).await;
            });
        }
    });
    let xml = "<message xmlns='jabber:client' from='alice@alpha.test/r' to='bob@beta.test' type='chat'><body>Hello</body><encrypted xmlns='urn:xmpp:omemo:2'>opaque</encrypted></message>";
    alice
        .route("alpha.test", "bob@beta.test", xml)
        .await
        .unwrap();
    let inbound = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inbound.from_domain, "alpha.test");
    assert!(inbound.xml.contains("jabber:server"));
    assert!(inbound.xml.contains("urn:xmpp:omemo:2"));
    // An operator routing override changes only the TCP endpoint: beta's trusted
    // certificate must never authenticate it as gamma.test.
    alice
        .set_target("gamma.test".into(), "127.0.0.1".into(), port)
        .unwrap();
    assert!(
        alice
            .route(
                "alpha.test",
                "bob@gamma.test",
                "<message from='alice@alpha.test' to='bob@gamma.test'/>",
            )
            .await
            .is_err()
    );
    assert!(rx.try_recv().is_err());
    // Domain matching, target lookup and certificate authentication use the same
    // case-insensitive DNS identity.
    alice
        .route(
            "ALPHA.TEST",
            "bob@BETA.TEST",
            "<message from='alice@ALPHA.TEST/r' to='bob@BETA.TEST' id='mixed-case'/>",
        )
        .await
        .unwrap();
    let received = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(received.xml.contains("mixed-case"));
    // Identity matching cannot compensate for an untrusted certificate chain.
    let (certs, key, _) = material(temp.path(), "alpha.test");
    let mut unrelated_roots = RootCertStore::empty();
    unrelated_roots.add(certs[0].clone()).unwrap();
    let mut untrusted = Federation::new("alpha.test".into(), certs, key, unrelated_roots).unwrap();
    untrusted
        .set_target("beta.test".into(), "127.0.0.1".into(), port)
        .unwrap();
    assert!(
        untrusted
            .route("alpha.test", "bob@beta.test", xml)
            .await
            .is_err()
    );
    assert!(rx.try_recv().is_err());
    // Owning a valid certificate for alpha.test never authorizes gamma.test.
    alice.add_local_domain("gamma.test".into()).unwrap();
    assert!(
        alice
            .route(
                "gamma.test",
                "bob@beta.test",
                "<message from='alice@gamma.test' to='bob@beta.test'><body>forged</body></message>"
            )
            .await
            .is_err()
    );
    assert!(rx.try_recv().is_err());
    assert!(
        alice
            .route(
                "alpha.test",
                "bob@beta.test",
                "<message from='admin@gamma.test' to='bob@beta.test'/>"
            )
            .await
            .is_err()
    );
    // Source-domain authentication cannot be reused to deliver to a third domain.
    assert!(
        alice
            .route(
                "alpha.test",
                "bob@beta.test",
                "<message from='alice@alpha.test' to='bob@gamma.test'/>"
            )
            .await
            .is_err()
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn reuses_connections_serializes_writes_and_retires_idle_or_closed_peers() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path());
    let (c, k, r) = material(temp.path(), "alpha.test");
    let mut alice = Federation::new("alpha.test".into(), c, k, r)
        .unwrap()
        .with_outbound_idle_timeout(Duration::from_millis(300))
        .unwrap();
    let (c, k, r) = material(temp.path(), "beta.test");
    let bob = Federation::new("beta.test".into(), c, k, r).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    alice
        .set_target(
            "beta.test".into(),
            "127.0.0.1".into(),
            listener.local_addr().unwrap().port(),
        )
        .unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let peers = Arc::new(Mutex::new(Vec::<tokio::task::AbortHandle>::new()));
    let (tx, mut rx) = mpsc::channel(64);
    let server = {
        let accepted = accepted.clone();
        let completed = completed.clone();
        let peers = peers.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                let bob = bob.clone();
                let tx = tx.clone();
                let completed = completed.clone();
                let handle = tokio::spawn(async move {
                    let _ = bob.accept(tcp, tx).await;
                    completed.fetch_add(1, Ordering::SeqCst);
                });
                peers.lock().unwrap().push(handle.abort_handle());
            }
        })
    };
    let stanza = |id: usize| {
        format!(
            "<message xmlns='jabber:client' from='alice@alpha.test/r' to='bob@beta.test' id='message-{id}'><body>payload-{id}</body></message>"
        )
    };
    for id in 0..3 {
        alice
            .route("alpha.test", "bob@beta.test", &stanza(id))
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(received.xml.contains(&format!("message-{id}")));
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "sequential sends should reuse one authenticated TLS connection"
    );
    assert!(
        alice
            .route(
                "alpha.test",
                "bob@beta.test",
                "<message from='forged@gamma.test' to='bob@beta.test'/>"
            )
            .await
            .is_err()
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "source checks apply before reuse"
    );
    let mut jobs = vec![];
    for id in 3..23 {
        let alice = alice.clone();
        let xml = stanza(id);
        jobs.push(tokio::spawn(async move {
            alice
                .route("alpha.test", "bob@beta.test", &xml)
                .await
                .unwrap()
        }));
    }
    for job in jobs {
        job.await.unwrap();
    }
    let mut ids = std::collections::BTreeSet::new();
    for _ in 3..23 {
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let d = roxmltree::Document::parse(&received.xml).unwrap();
        ids.insert(d.root_element().attribute("id").unwrap().to_owned());
    }
    assert_eq!(ids.len(), 20);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "concurrent clones share a per-pair connection"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        completed.load(Ordering::SeqCst) >= 1,
        "idle connection must close without another route call"
    );
    alice
        .route("alpha.test", "bob@beta.test", &stanza(23))
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(received.xml.contains("message-23"));
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    peers.lock().unwrap().last().unwrap().abort();
    tokio::time::sleep(Duration::from_millis(100)).await;
    alice
        .route("alpha.test", "bob@beta.test", &stanza(24))
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(received.xml.contains("message-24"));
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
    assert!(rx.try_recv().is_err(), "no automatic duplicate deliveries");
    drop(alice);
    server.abort();
    for peer in peers.lock().unwrap().iter() {
        peer.abort();
    }
}

/// Native interop test, deliberately opt-in: needs a built Prosody source tree,
/// Lua 5.4, LuaSocket, LuaSec, LuaExpat and LuaFileSystem.
///
/// PROSODY_SOURCE=/path/to/prosody-cafd74b9c5ea PROSODY_LUA=/path/to/lua5.4 \
///   cargo test --test federation_tls native_prosody_tls_external_bidirectional -- --ignored --nocapture
///
/// Lua's LUA_PATH/LUA_CPATH and the platform library path are inherited. The
/// probe plugin overrides TCP discovery only; both peers still authenticate the
/// original alpha.test/beta.test identities and trust only the generated CA.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires native Prosody cafd74b9c5ea and Lua TLS dependencies"]
async fn native_prosody_tls_external_bidirectional() {
    use std::process::{Child, Stdio};
    use std::time::Duration;
    struct Native(Child);
    impl Drop for Native {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn lua_path(path: &Path) -> String {
        format!(
            "'{}'",
            path.to_string_lossy()
                .replace('\\', "\\\\")
                .replace('\'', "\\'")
        )
    }
    let source = std::env::var_os("PROSODY_SOURCE")
        .map(std::path::PathBuf::from)
        .expect("set PROSODY_SOURCE to the built Prosody cafd74b9c5ea source tree");
    let source = source.canonicalize().unwrap();
    assert_eq!(
        fs::read_to_string(source.join("prosody.version"))
            .unwrap()
            .trim(),
        "cafd74b9c5ea"
    );
    let lua = std::env::var_os("PROSODY_LUA").unwrap_or_else(|| "lua5.4".into());
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path());
    // OpenSSL's TLS client validation requires clientAuth as well as serverAuth
    // for s2s certificates, unlike rustls's server-identity verifier.
    let ext = temp.path().join("alpha.test.ext");
    let extensions = fs::read_to_string(&ext).unwrap().replace(
        "extendedKeyUsage=serverAuth",
        "extendedKeyUsage=serverAuth,clientAuth",
    );
    fs::write(ext, extensions).unwrap();
    openssl(
        temp.path(),
        &[
            "x509",
            "-req",
            "-in",
            "alpha.test.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "alpha.test.pem",
            "-days",
            "1",
            "-extfile",
            "alpha.test.ext",
        ],
    );
    let (certs, key, roots) = material(temp.path(), "alpha.test");
    let mut rust = Federation::new("alpha.test".into(), certs, key, roots).unwrap();
    let rust_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rust_port = rust_listener.local_addr().unwrap().port();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let prosody_port = reservation.local_addr().unwrap().port();
    drop(reservation);
    rust.set_target("beta.test".into(), "127.0.0.1".into(), prosody_port)
        .unwrap();
    let plugins = temp.path().join("plugins");
    fs::create_dir(&plugins).unwrap();
    fs::create_dir(temp.path().join("data")).unwrap();
    let received_marker = temp.path().join("received");
    fs::write(plugins.join("mod_native_probe.lua"), format!(r#"
local st = require "prosody.util.stanza";
local basic = require "prosody.net.resolvers.basic";
module:hook("s2sout-pre-connect", function(event)
    assert(event.session.to_host == "alpha.test");
    event.resolver = basic.new("127.0.0.1", {rust_port}, "tcp");
end);
module:hook("message/bare", function(event)
    local stanza = event.stanza;
    if stanza.attr.id ~= "rust-to-prosody" then return; end
    assert(event.origin.secure and event.origin.type == "s2sin");
    assert(event.origin.external_auth == "succeeded");
    assert(event.origin.cert_chain_status == "valid");
    assert(event.origin.cert_identity_status == "valid");
    local marker = assert(io.open({}, "w"));
    marker:write(stanza:get_child_text("body")); marker:close();
    module:send(st.message({{ from="bob@beta.test"; to="alice@alpha.test"; id="prosody-to-rust"; type="chat" }}):body("native-prosody-reply"));
    return true;
end, 1000);
"#, lua_path(&received_marker))).unwrap();
    let config = temp.path().join("prosody.cfg.lua");
    fs::write(
        &config,
        format!(
            r#"
daemonize = false;
run_as_root = true;
interfaces = {{ "127.0.0.1" }};
c2s_ports = {{}};
s2s_ports = {{ {prosody_port} }};
http_ports = {{}};
https_ports = {{}};
plugin_paths = {{ {} }};
data_path = {};
modules_enabled = {{ "tls"; "saslauth"; "native_probe" }};
modules_disabled = {{ "dialback"; "s2s_bidi"; "offline"; "c2s" }};
s2s_secure_auth = true;
s2s_require_encryption = true;
log = "*console";
ssl = {{ key = {}; certificate = {}; cafile = {}; capath = false; }};
VirtualHost "beta.test"
authentication = "internal_hashed";
"#,
            lua_path(&plugins),
            lua_path(&temp.path().join("data")),
            lua_path(&temp.path().join("beta.test.key")),
            lua_path(&temp.path().join("beta.test.pem")),
            lua_path(&temp.path().join("ca.pem"))
        ),
    )
    .unwrap();
    let log_path = temp.path().join("prosody.log");
    let log = fs::File::create(&log_path).unwrap();
    let mut native = Native(
        Command::new(lua)
            .current_dir(&source)
            .env("PROSODY_SRCDIR", &source)
            .env("PROSODY_PLUGINDIR", source.join("plugins"))
            .arg(source.join("prosody"))
            .args(["-F", "--config"])
            .arg(&config)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start native Prosody"),
    );
    let log_text = || fs::read_to_string(&log_path).unwrap_or_default();
    let startup = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                native.0.try_wait().unwrap().is_none(),
                "Prosody exited:\n{}",
                log_text()
            );
            if tokio::net::TcpStream::connect(("127.0.0.1", prosody_port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await;
    assert!(startup.is_ok(), "Prosody did not listen:\n{}", log_text());
    let (tx, mut rx) = mpsc::channel(4);
    let receiving = {
        let rust = rust.clone();
        tokio::spawn(async move {
            let (tcp, _) = rust_listener.accept().await.unwrap();
            rust.accept(tcp, tx).await
        })
    };
    let outcome = rust.route("alpha.test", "bob@beta.test", "<message from='alice@alpha.test' to='bob@beta.test' id='rust-to-prosody' type='chat'><body>native-rust-probe</body></message>").await;
    assert!(
        outcome.is_ok(),
        "Rust -> Prosody: {outcome:?}\n{}",
        log_text()
    );
    let reply = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await;
    assert!(
        matches!(&reply, Ok(Some(_))),
        "Prosody -> Rust: {reply:?}\n{}",
        log_text()
    );
    let reply = reply.unwrap().unwrap();
    assert_eq!(reply.from_domain, "beta.test");
    assert!(reply.xml.contains("prosody-to-rust"));
    assert!(reply.xml.contains("native-prosody-reply"));
    assert_eq!(
        fs::read_to_string(received_marker).unwrap(),
        "native-rust-probe"
    );
    let logs = log_text();
    assert!(
        logs.contains("Accepting SASL EXTERNAL identity from alpha.test"),
        "{logs}"
    );
    assert!(
        logs.contains("SASL EXTERNAL with alpha.test succeeded"),
        "{logs}"
    );
    receiving.abort();
}
