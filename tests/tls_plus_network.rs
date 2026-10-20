//! Independent SCRAM-PLUS client against the actual STARTTLS listener.
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use rust_xmpp::{auth, wire::Framer};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::BufReader,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, RootCertStore, pki_types::ServerName},
};

const STREAM: &str = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
const SASL1: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const SASL2: &str = "urn:xmpp:sasl:2";
const CB_NS: &str = "urn:xmpp:sasl-cb:0";
const WAIT: Duration = Duration::from_secs(5);
const PASSWORD: &str = "loopback-plus-password";

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Server {
    process: Process,
    _dir: tempfile::TempDir,
    port: u16,
    cert: rustls::pki_types::CertificateDer<'static>,
}
impl Server {
    async fn start(disable_plus: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = fs::File::create(dir.path().join("openssl.log")).unwrap();
        let mut openssl = Process(
            Command::new("openssl")
                .current_dir(dir.path())
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-sha256",
                    "-nodes",
                    "-days",
                    "1",
                    "-keyout",
                    "key.pem",
                    "-out",
                    "cert.pem",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost",
                    "-addext",
                    "basicConstraints=critical,CA:FALSE",
                    "-addext",
                    "extendedKeyUsage=serverAuth",
                ])
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .expect("openssl must be installed"),
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = openssl.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "openssl failed: {}",
                    fs::read_to_string(dir.path().join("openssl.log")).unwrap()
                );
                break;
            }
            assert!(Instant::now() < deadline, "openssl timed out");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let cert = rustls_pemfile::certs(&mut BufReader::new(
            fs::File::open(dir.path().join("cert.pem")).unwrap(),
        ))
        .next()
        .unwrap()
        .unwrap();
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let data = dir.path().join("data");
        auth::create(&data, "localhost", "alice", PASSWORD, "SHA-256").unwrap();
        let mut config = serde_json::json!({
            "global": {"data_path": data, "interfaces": ["127.0.0.1"], "c2s_ports": [port],
                "s2s_ports": [], "http_ports": [], "https_ports": [],
                "modules_enabled": ["tls", "saslauth", "sasl2", "sasl_ssdp"]},
            "hosts": {"localhost": {"options": {"authentication": "internal_hashed", "password_hash": "SHA-256",
                "ssl": {"key": dir.path().join("key.pem"), "certificate": dir.path().join("cert.pem")}}}}
        });
        if disable_plus {
            config["hosts"]["localhost"]["options"]["disable_sasl_mechanisms"] =
                serde_json::json!(["SCRAM-SHA-256-PLUS"]);
        }
        let path = dir.path().join("config.json");
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let log = fs::File::create(dir.path().join("server.log")).unwrap();
        drop(reservation);
        let process = Process(
            Command::new(env!("CARGO_BIN_EXE_rust-xmpp"))
                .arg("serve")
                .arg(path)
                .arg("--experimental")
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let mut server = Self {
            process,
            _dir: dir,
            port,
            cert,
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                assert!(
                    server.process.0.try_wait().unwrap().is_none(),
                    "server exited: {}",
                    server.logs()
                );
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("server startup timed out: {}", server.logs()));
        server
    }
    fn logs(&self) -> String {
        fs::read_to_string(self._dir.path().join("server.log")).unwrap_or_default()
    }
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, xml: &str) {
    tokio::time::timeout(WAIT, stream.write_all(xml.as_bytes()))
        .await
        .expect("write timeout")
        .unwrap();
}
async fn next<S: AsyncRead + Unpin>(framer: &mut Framer, stream: &mut S) -> String {
    tokio::time::timeout(WAIT, framer.next(stream))
        .await
        .expect("read timeout")
        .unwrap()
}
async fn features<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    framer: &mut Framer,
) -> String {
    send(stream, STREAM).await;
    loop {
        let xml = next(framer, stream).await;
        if xml.contains("<stream:features") {
            return framer.wrap(&xml);
        }
    }
}
fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
    h.update(data);
    h.finalize().into_bytes().to_vec()
}

async fn exchange(
    server: &Server,
    tls13: bool,
    binding_name: &str,
    sasl2: bool,
    bad_binding: bool,
) {
    let mut tcp = tokio::time::timeout(WAIT, TcpStream::connect(("127.0.0.1", server.port)))
        .await
        .unwrap()
        .unwrap();
    let mut f = Framer::default();
    let plain = features(&mut tcp, &mut f).await;
    assert!(plain.contains("starttls"), "{plain}");
    assert!(
        !plain.contains("SCRAM-SHA-256-PLUS"),
        "PLUS must not be offered before TLS"
    );
    send(
        &mut tcp,
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
    )
    .await;
    let proceed = next(&mut f, &mut tcp).await;
    assert!(proceed.contains("proceed"), "{proceed}");
    assert!(f.buffer.is_empty());
    let mut roots = RootCertStore::empty();
    roots.add(server.cert.clone()).unwrap();
    let versions = if tls13 {
        &[&rustls::version::TLS13][..]
    } else {
        &[&rustls::version::TLS12][..]
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut tls = tokio::time::timeout(
        WAIT,
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp),
    )
    .await
    .expect("TLS timeout")
    .unwrap();
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(if tls13 {
            rustls::ProtocolVersion::TLSv1_3
        } else {
            rustls::ProtocolVersion::TLSv1_2
        })
    );
    let plus = binding_name != "none";
    let mechanism = if plus {
        "SCRAM-SHA-256-PLUS"
    } else {
        "SCRAM-SHA-256"
    };
    let mut binding = if !plus {
        Vec::new()
    } else if binding_name == "tls-exporter" {
        tls.get_ref()
            .1
            .export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", Some(b""))
            .unwrap()
            .to_vec()
    } else {
        Sha256::digest(server.cert.as_ref()).to_vec()
    };
    let mut f = Framer::default();
    let advertised = features(&mut tls, &mut f).await;
    let doc = roxmltree::Document::parse(&advertised).unwrap();
    let mechanism_ns = if sasl2 { SASL2 } else { SASL1 };
    let mut mechanisms: Vec<_> = doc
        .descendants()
        .filter(|n| n.has_tag_name((mechanism_ns, "mechanism")))
        .map(|n| n.text().unwrap().to_owned())
        .collect();
    mechanisms.sort();
    mechanisms.dedup();
    assert!(mechanisms.iter().any(|m| m == mechanism));
    assert_eq!(mechanisms.iter().any(|m| m == "SCRAM-SHA-256-PLUS"), plus);
    let mut bindings: Vec<_> = doc
        .descendants()
        .filter(|n| n.has_tag_name((CB_NS, "channel-binding")))
        .map(|n| n.attribute("type").unwrap().to_owned())
        .collect();
    bindings.sort();
    bindings.dedup();
    assert_eq!(
        bindings,
        if !plus {
            vec![]
        } else if tls13 {
            vec!["tls-exporter", "tls-server-end-point"]
        } else {
            vec!["tls-server-end-point"]
        }
    );
    let gs2 = if plus {
        format!("p={binding_name},,")
    } else {
        "y,,".to_owned()
    };
    let bare = "n=alice,r=independent-client-nonce";
    let first = B64.encode(format!("{gs2}{bare}"));
    let ns = mechanism_ns;
    if sasl2 {
        send(&mut tls, &format!("<authenticate xmlns='{ns}' mechanism='{mechanism}'><initial-response>{first}</initial-response></authenticate>")).await;
    } else {
        send(
            &mut tls,
            &format!("<auth xmlns='{ns}' mechanism='{mechanism}'>{first}</auth>"),
        )
        .await;
    }
    let xml = next(&mut f, &mut tls).await;
    let doc = roxmltree::Document::parse(&xml).unwrap();
    assert!(doc.root_element().has_tag_name((ns, "challenge")), "{xml}");
    let challenge =
        String::from_utf8(B64.decode(doc.root_element().text().unwrap()).unwrap()).unwrap();
    let attrs: BTreeMap<_, _> = challenge
        .split(',')
        .map(|a| a.split_once('=').unwrap())
        .collect();
    assert!(attrs["r"].starts_with("independent-client-nonce"));
    assert!(attrs["r"].len() > "independent-client-nonce".len());
    let ssdp_source = if bindings.is_empty() {
        mechanisms.join("\x1e")
    } else {
        format!("{}\x1f{}", mechanisms.join("\x1e"), bindings.join("\x1e"))
    };
    assert_eq!(
        attrs.get("h").copied(),
        Some(B64.encode(Sha256::digest(ssdp_source.as_bytes())).as_str()),
        "SSDP must authenticate the entire advertised mechanism and binding lists"
    );
    let iterations: u32 = attrs["i"].parse().unwrap();
    assert!((1..=1_000_000).contains(&iterations));
    let mut salted = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        PASSWORD.as_bytes(),
        &B64.decode(attrs["s"]).unwrap(),
        iterations,
        &mut salted,
    );
    if bad_binding {
        binding[0] ^= 1;
    }
    let mut cbind = gs2.into_bytes();
    cbind.extend_from_slice(&binding);
    let without = format!("c={},r={}", B64.encode(cbind), attrs["r"]);
    let auth_message = format!("{bare},{challenge},{without}");
    let client_key = mac(&salted, b"Client Key");
    let signature = mac(&Sha256::digest(&client_key), auth_message.as_bytes());
    let proof: Vec<_> = client_key
        .iter()
        .zip(signature)
        .map(|(a, b)| a ^ b)
        .collect();
    // Even the tampered-binding exchange has a valid password proof for its transcript.
    let final_message = format!("{without},p={}", B64.encode(proof));
    send(
        &mut tls,
        &format!(
            "<response xmlns='{ns}'>{}</response>",
            B64.encode(final_message)
        ),
    )
    .await;
    let xml = next(&mut f, &mut tls).await;
    let doc = roxmltree::Document::parse(&xml).unwrap();
    let result = doc.root_element();
    if bad_binding {
        assert!(
            result.has_tag_name((ns, "failure")),
            "tampered binding authenticated: {xml}"
        );
        assert!(
            result
                .descendants()
                .any(|n| n.has_tag_name((SASL1, "not-authorized"))),
            "{xml}"
        );
        return;
    }
    assert!(result.has_tag_name((ns, "success")), "{xml}");
    let final_data = if sasl2 {
        assert_eq!(
            result
                .children()
                .find(|n| n.has_tag_name((SASL2, "authorization-identifier")))
                .and_then(|n| n.text()),
            Some("alice@localhost")
        );
        result
            .children()
            .find(|n| n.has_tag_name((SASL2, "additional-data")))
            .unwrap()
            .text()
            .unwrap()
    } else {
        result.text().unwrap()
    };
    let expected = format!(
        "v={}",
        B64.encode(mac(&mac(&salted, b"Server Key"), auth_message.as_bytes()))
    );
    assert_eq!(
        String::from_utf8(B64.decode(final_data).unwrap()).unwrap(),
        expected,
        "verify the full server signature"
    );
    if !sasl2 {
        f = Framer::default();
    }
    let post_auth = if sasl2 {
        let xml = next(&mut f, &mut tls).await;
        f.wrap(&xml)
    } else {
        features(&mut tls, &mut f).await
    };
    assert!(
        post_auth.contains("urn:ietf:params:xml:ns:xmpp-bind"),
        "{post_auth}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starttls_scram_plus_binds_real_tls_and_authenticates_ssdp_sasl1_and_sasl2() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let server = Server::start(false).await;
        for (tls13, binding) in [
            (true, "tls-exporter"),
            (true, "tls-server-end-point"),
            (false, "tls-server-end-point"),
        ] {
            for sasl2 in [false, true] {
                exchange(&server, tls13, binding, sasl2, false).await;
                exchange(&server, tls13, binding, sasl2, true).await;
            }
        }
    })
    .await
    .expect("bounded STARTTLS integration test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabling_plus_hides_bindings_and_accepts_scram_y_with_mechanisms_only_ssdp() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let server = Server::start(true).await;
        for sasl2 in [false, true] {
            exchange(&server, true, "none", sasl2, false).await;
        }
    })
    .await
    .expect("bounded no-PLUS STARTTLS integration test");
}
