//! Authenticated XMPP server-to-server transport: STARTTLS + SASL EXTERNAL.
//! No dialback or plaintext fallback: a peer must prove ownership of its source domain
//! through a trusted certificate and the TLS CertificateVerify signature.
use crate::wire::{Framer, escape};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hickory_resolver::{TokioAsyncResolver, error::ResolveErrorKind};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, mpsc, oneshot},
    time::{Instant, timeout},
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        self, ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
        SignatureScheme,
        client::{
            WebPkiServerVerifier,
            danger::{HandshakeSignatureValid, ServerCertVerifier},
        },
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
        server::danger::{ClientCertVerified, ClientCertVerifier},
    },
};
const STREAM: &str = "http://etherx.jabber.org/streams";
const SERVER: &str = "jabber:server";
const TLS: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const SASL: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const HANDSHAKE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct FederatedStanza {
    pub from_domain: String,
    pub xml: String,
}
#[derive(Clone)]
pub struct Federation {
    inner: Arc<Inner>,
    local_domains: BTreeSet<String>,
    /// Explicit operator routing overrides; TLS identity is always checked against the JID domain.
    targets: BTreeMap<String, (String, u16)>,
    outbound_idle: Duration,
}
type PoolKey = (String, String, Option<(String, u16)>);
type PeerConnection = Arc<Mutex<Option<Outbound>>>;
const MAX_OUTBOUND: usize = 128;
struct Delivery {
    stanza: String,
    complete: oneshot::Sender<Result<()>>,
}
struct Outbound {
    sender: mpsc::Sender<Delivery>,
    last_used: Instant,
}
struct Authenticated {
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    framer: Framer,
}
struct Inner {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    roots: Arc<RootCertStore>,
    client: Arc<ClientConfig>,
    resolver: TokioAsyncResolver,
    outbound: Mutex<BTreeMap<PoolKey, PeerConnection>>,
}
impl Federation {
    pub fn new(
        domain: String,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        roots: RootCertStore,
    ) -> Result<Self> {
        let domain = canonical_domain(&domain)?;
        ensure!(!roots.is_empty(), "empty federation trust store");
        let roots = Arc::new(roots);
        let client = ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(certs.clone(), key.clone_key())?;
        Ok(Self {
            inner: Arc::new(Inner {
                certs,
                key,
                roots,
                client: Arc::new(client),
                resolver: TokioAsyncResolver::tokio_from_system_conf()?,
                outbound: Mutex::new(BTreeMap::new()),
            }),
            local_domains: BTreeSet::from([domain]),
            targets: BTreeMap::new(),
            outbound_idle: Duration::from_secs(60),
        })
    }
    pub fn add_local_domain(&mut self, domain: String) -> Result<()> {
        self.local_domains.insert(canonical_domain(&domain)?);
        Ok(())
    }
    pub fn set_target(&mut self, domain: String, host: String, port: u16) -> Result<()> {
        let domain = canonical_domain(&domain)?;
        ensure!(port != 0 && !host.is_empty(), "invalid federation target");
        self.targets.insert(domain, (host, port));
        Ok(())
    }
    pub fn native_roots() -> Result<RootCertStore> {
        let native = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        for cert in native.certs {
            roots.add(cert)?;
        }
        ensure!(!roots.is_empty(), "no native trust anchors available");
        Ok(roots)
    }
    async fn targets(&self, domain: &str) -> Result<Vec<(String, u16)>> {
        if let Some(target) = self.targets.get(domain) {
            return Ok(vec![target.clone()]);
        }
        let lookup = self
            .inner
            .resolver
            .srv_lookup(format!("_xmpp-server._tcp.{domain}."))
            .await;
        let mut records = match lookup {
            Ok(v) => v.iter().cloned().collect::<Vec<_>>(),
            Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => {
                return Ok(vec![(domain.into(), 5269)]);
            }
            Err(e) => return Err(e.into()),
        };
        ensure!(
            !records.iter().any(|r| r.target().is_root()),
            "domain explicitly disables XMPP federation"
        );
        records.sort_by_key(|r| r.priority());
        let mut targets = Vec::new();
        while !records.is_empty() {
            let priority = records[0].priority();
            let end = records
                .iter()
                .take_while(|r| r.priority() == priority)
                .count();
            let sum: u64 = records[..end].iter().map(|r| r.weight() as u64).sum();
            let random =
                u64::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
            let chosen = if sum == 0 {
                random as usize % end
            } else {
                let draw = random % sum;
                let mut acc = 0;
                records[..end]
                    .iter()
                    .position(|r| {
                        acc += r.weight() as u64;
                        draw < acc
                    })
                    .unwrap_or(0)
            };
            let r = records.remove(chosen);
            targets.push((r.target().to_utf8().trim_end_matches('.').into(), r.port()));
        }
        if targets.is_empty() {
            targets.push((domain.into(), 5269));
        }
        Ok(targets)
    }
    pub async fn route(&self, from_domain: &str, to_jid: &str, xml: &str) -> Result<()> {
        let from_domain = canonical_domain(from_domain)?;
        ensure!(
            self.local_domains.contains(&from_domain),
            "unowned federation sender domain"
        );
        let to_domain = jid_domain(to_jid)?;
        validate_stanza(xml, &from_domain, &to_domain)?;
        timeout(HANDSHAKE, self.route_inner(&from_domain, &to_domain, xml))
            .await
            .context("federation route timeout")?
    }
    /// Configure before routing. Idle sockets close independently of subsequent traffic.
    pub fn with_outbound_idle_timeout(mut self, duration: Duration) -> Result<Self> {
        ensure!(
            duration >= Duration::from_millis(10) && duration <= Duration::from_secs(3600),
            "invalid federation idle timeout"
        );
        self.outbound_idle = duration;
        Ok(self)
    }
    async fn route_inner(&self, from: &str, to: &str, xml: &str) -> Result<()> {
        let key = (
            from.to_owned(),
            to.to_owned(),
            self.targets.get(to).cloned(),
        );
        let peer = {
            let mut pool = self.inner.outbound.lock().await;
            // Closed actors cannot retain TLS sockets. Never await peer locks under the map lock.
            pool.retain(|_, peer| {
                if Arc::strong_count(peer) > 1 {
                    return true;
                }
                peer.try_lock().map_or(true, |connection| {
                    connection.as_ref().is_some_and(|c| !c.sender.is_closed())
                })
            });
            if let Some(peer) = pool.get(&key) {
                peer.clone()
            } else {
                ensure!(
                    pool.len() < MAX_OUTBOUND,
                    "federation connection pool is full"
                );
                let peer = Arc::new(Mutex::new(None));
                pool.insert(key, peer.clone());
                peer
            }
        };
        let mut connection = peer.lock().await;
        for attempt in 0..2 {
            if connection.as_ref().is_some_and(|c| {
                c.sender.is_closed() || c.last_used.elapsed() >= self.outbound_idle
            }) {
                *connection = None;
            }
            if connection.is_none() {
                let targets = self.targets(to).await?;
                let mut last = None;
                let mut authenticated = None;
                for (host, port) in targets {
                    match self.connect(&host, port, from, to).await {
                        Ok(c) => {
                            authenticated = Some(c);
                            break;
                        }
                        Err(e) => last = Some(e),
                    }
                }
                let authenticated = authenticated.ok_or_else(|| {
                    last.unwrap_or_else(|| anyhow::anyhow!("no federation endpoints"))
                })?;
                let (sender, receiver) = mpsc::channel(1);
                tokio::spawn(outbound_actor(authenticated, receiver, self.outbound_idle));
                *connection = Some(Outbound {
                    sender,
                    last_used: Instant::now(),
                });
            }
            let (complete, result) = oneshot::channel();
            let delivery = Delivery {
                stanza: server_stanza(xml)?,
                complete,
            };
            let ready = connection.as_mut().unwrap();
            if ready.sender.send(delivery).await.is_err() {
                *connection = None;
                // send() returns the owned delivery only when the actor never took it.
                // Reconnecting is safe in this case; writes with ambiguous outcomes
                // below are deliberately never replayed.
                if attempt == 0 {
                    continue;
                }
                anyhow::bail!("federation connection closed before delivery");
            }
            // A canceled route or failed write has an ambiguous delivery outcome. Never replay it.
            let outcome = result.await.unwrap_or_else(|_| {
                Err(anyhow::anyhow!(
                    "federation connection closed during delivery"
                ))
            });
            if outcome.is_err() {
                *connection = None;
            } else {
                ready.last_used = Instant::now();
            }
            return outcome;
        }
        unreachable!("bounded delivery attempts return or fail")
    }

    async fn connect(&self, host: &str, port: u16, from: &str, to: &str) -> Result<Authenticated> {
        let mut tcp = timeout(Duration::from_secs(8), TcpStream::connect((host, port))).await??;
        tcp.set_nodelay(true)?;
        let mut f = Framer::default();
        send(&mut tcp, &header(from, to)).await?;
        read_header(&mut tcp, &mut f, Some(to), Some(from)).await?;
        let features = frame(&mut tcp, &mut f).await?;
        ensure!(
            feature(&features, TLS, "starttls")?,
            "peer does not offer STARTTLS"
        );
        send(&mut tcp, &format!("<starttls xmlns='{TLS}'/>")).await?;
        let proceed = frame(&mut tcp, &mut f).await?;
        ensure!(element(&proceed, TLS, "proceed")?, "STARTTLS rejected");
        ensure!(f.buffer.is_empty(), "unexpected cleartext after proceed");
        let name = ServerName::try_from(to.to_owned())?;
        let mut tls = TlsConnector::from(self.inner.client.clone())
            .connect(name, tcp)
            .await?;
        let mut f = Framer::default();
        send(&mut tls, &header(from, to)).await?;
        read_header(&mut tls, &mut f, Some(to), Some(from)).await?;
        let features = frame(&mut tls, &mut f).await?;
        ensure!(
            external_feature(&features)?,
            "peer does not offer SASL EXTERNAL"
        );
        send(
            &mut tls,
            &format!(
                "<auth xmlns='{SASL}' mechanism='EXTERNAL'>{}</auth>",
                B64.encode(from)
            ),
        )
        .await?;
        let success = frame(&mut tls, &mut f).await?;
        ensure!(
            element(&success, SASL, "success")?,
            "peer rejected EXTERNAL"
        );
        send(&mut tls, &header(from, to)).await?;
        read_header(&mut tls, &mut f, Some(to), Some(from)).await?;
        let features = frame(&mut tls, &mut f).await?;
        ensure!(
            element(&features, STREAM, "features")?,
            "missing postauth features"
        );
        Ok(Authenticated { tls, framer: f })
    }
    pub async fn accept(
        &self,
        tcp: TcpStream,
        inbound: mpsc::Sender<FederatedStanza>,
    ) -> Result<()> {
        // One deadline covers the entire unauthenticated protocol, including SASL
        // and stream restarts; per-frame deadlines otherwise let peers pin sockets.
        let (mut tls, mut f, from) = timeout(HANDSHAKE, self.authenticate(tcp))
            .await
            .context("federation authentication timeout")??;
        loop {
            let text = frame(&mut tls, &mut f).await?;
            if f.is_stream_end(&text) {
                send(&mut tls, "</stream:stream>").await?;
                return Ok(());
            }
            let destination = {
                let w = wrap(&text);
                let d = roxmltree::Document::parse(&w)?;
                let n = d
                    .root_element()
                    .first_element_child()
                    .context("missing stanza")?;
                ensure!(
                    n.tag_name().namespace() == Some(SERVER),
                    "invalid S2S stanza namespace"
                );
                jid_domain(n.attribute("to").context("missing destination")?)?
            };
            ensure!(
                self.local_domains.contains(&destination),
                "unserved destination domain"
            );
            validate_stanza(&text, &from, &destination)?;
            timeout(
                Duration::from_secs(15),
                inbound.send(FederatedStanza {
                    from_domain: from.clone(),
                    xml: text,
                }),
            )
            .await??;
        }
    }
    async fn authenticate(
        &self,
        mut tcp: TcpStream,
    ) -> Result<(tokio_rustls::server::TlsStream<TcpStream>, Framer, String)> {
        tcp.set_nodelay(true)?;
        let mut f = Framer::default();
        let (from, to) = read_header(&mut tcp, &mut f, None, None).await?;
        ensure!(
            self.local_domains.contains(&to),
            "unknown destination domain"
        );
        send(&mut tcp,&format!("{}<stream:features><starttls xmlns='{TLS}'><required/></starttls></stream:features>",header(&to,&from))).await?;
        let start = frame(&mut tcp, &mut f).await?;
        ensure!(element(&start, TLS, "starttls")?, "TLS required");
        ensure!(f.buffer.is_empty(), "TLS pipelining rejected");
        let verifier = Arc::new(DomainVerifier {
            inner: WebPkiServerVerifier::builder(self.inner.roots.clone()).build()?,
            name: ServerName::try_from(from.clone())?,
        });
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.inner.certs.clone(), self.inner.key.clone_key())?;
        send(&mut tcp, &format!("<proceed xmlns='{TLS}'/>")).await?;
        let mut tls = timeout(HANDSHAKE, TlsAcceptor::from(Arc::new(config)).accept(tcp)).await??;
        let mut f = Framer::default();
        read_header(&mut tls, &mut f, Some(&from), Some(&to)).await?;
        send(&mut tls,&format!("{}<stream:features><mechanisms xmlns='{SASL}'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>",header(&to,&from))).await?;
        let auth = frame(&mut tls, &mut f).await?;
        {
            let w = wrap(&auth);
            let d = roxmltree::Document::parse(&w)?;
            let n = d
                .root_element()
                .first_element_child()
                .context("missing auth")?;
            ensure!(
                n.tag_name().namespace() == Some(SASL)
                    && n.tag_name().name() == "auth"
                    && n.attribute("mechanism") == Some("EXTERNAL"),
                "EXTERNAL required"
            );
            let payload = n.text().unwrap_or("");
            let authz = if payload == "=" {
                Vec::new()
            } else {
                B64.decode(payload)?
            };
            ensure!(
                authz.is_empty()
                    || std::str::from_utf8(&authz)
                        .ok()
                        .and_then(|value| canonical_domain(value).ok())
                        .is_some_and(|value| value == from),
                "EXTERNAL identity mismatch"
            );
        }
        send(&mut tls, &format!("<success xmlns='{SASL}'/>")).await?;
        read_header(&mut tls, &mut f, Some(&from), Some(&to)).await?;
        send(
            &mut tls,
            &format!("{}<stream:features/>", header(&to, &from)),
        )
        .await?;
        Ok((tls, f, from))
    }
}
/// One task owns each TLS stream so peer closure is observed even when no writes occur.
async fn outbound_actor(
    mut connection: Authenticated,
    mut queue: mpsc::Receiver<Delivery>,
    idle: Duration,
) {
    let mut deadline = Instant::now() + idle;
    loop {
        tokio::select! {
            biased;
            // Outbound S2S is unidirectional; bidi was never negotiated. Any peer stanza,
            // stream error, closing tag or EOF ends this connection without replaying data.
            _ = connection.framer.next(&mut connection.tls) => break,
            _ = tokio::time::sleep_until(deadline) => break,
            delivery = queue.recv() => {
                let Some(delivery)=delivery else{break};
                if delivery.complete.is_closed(){continue}
                let outcome=send(&mut connection.tls,&delivery.stanza).await;
                let failed=outcome.is_err();let _=delivery.complete.send(outcome);
                if failed{break}deadline=Instant::now()+idle;
            }
        }
    }
    queue.close();
    while let Ok(delivery) = queue.try_recv() {
        let _ = delivery.complete.send(Err(anyhow::anyhow!(
            "federation connection retired before write"
        )));
    }
    let _ = timeout(
        Duration::from_secs(1),
        send(&mut connection.tls, "</stream:stream>"),
    )
    .await;
    let _ = timeout(Duration::from_secs(1), connection.tls.shutdown()).await;
}
#[derive(Debug)]
struct DomainVerifier {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}
impl ClientCertVerifier for DomainVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end, intermediates, &self.name, &[], now)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
fn canonical_domain(name: &str) -> Result<String> {
    // Domain identities use canonical DNS label syntax. IPv4 literals remain
    // supported; rustls requires an IP SAN for them rather than a DNS SAN.
    ensure!(
        !name.is_empty()
            && name.len() <= 253
            && name.is_ascii()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
        "invalid federation domain"
    );
    ServerName::try_from(name.to_owned())?;
    Ok(name.to_ascii_lowercase())
}
fn jid_domain(jid: &str) -> Result<String> {
    let bare = jid.split('/').next().context("missing JID")?;
    let domain = match bare.split_once('@') {
        Some((local, domain)) => {
            ensure!(!local.is_empty() && !domain.contains('@'), "invalid JID");
            domain
        }
        None => bare,
    };
    canonical_domain(domain)
}
fn header(from: &str, to: &str) -> String {
    format!(
        "<stream:stream xmlns='{SERVER}' xmlns:stream='{STREAM}' from='{}' to='{}' id='{}' version='1.0'>",
        escape(from),
        escape(to),
        uuid::Uuid::new_v4()
    )
}
fn wrap(xml: &str) -> String {
    format!("<root xmlns='{SERVER}' xmlns:stream='{STREAM}'>{xml}</root>")
}
async fn send<S: AsyncWrite + Unpin>(s: &mut S, xml: &str) -> Result<()> {
    timeout(Duration::from_secs(15), s.write_all(xml.as_bytes())).await??;
    Ok(())
}
async fn frame<S: AsyncRead + Unpin>(s: &mut S, f: &mut Framer) -> Result<String> {
    let text = timeout(Duration::from_secs(120), f.next(s)).await??;
    if text.starts_with("<?xml")
        || f.is_stream_end(&text)
        || crate::wire::StreamHeader::parse(&text).is_ok()
    {
        return Ok(text);
    }
    let w = f.wrap(&text);
    let doc = roxmltree::Document::parse(&w)?;
    let node = doc
        .root_element()
        .first_element_child()
        .context("missing S2S frame")?;
    Ok(crate::protocol::xml(node))
}
async fn read_header<S: AsyncRead + Unpin>(
    s: &mut S,
    f: &mut Framer,
    expected_from: Option<&str>,
    expected_to: Option<&str>,
) -> Result<(String, String)> {
    let mut text = frame(s, f).await?;
    if text.starts_with("<?xml ") {
        text = frame(s, f).await?;
    }
    let header = crate::wire::StreamHeader::parse(&text)?;
    ensure!(
        header.default_namespace() == Some(SERVER) && header.version.as_deref() == Some("1.0"),
        "invalid S2S header"
    );
    let from = header.from.as_deref().context("missing from domain")?;
    let to = header.to.as_deref().context("missing to domain")?;
    let from = canonical_domain(from)?;
    let to = canonical_domain(to)?;
    ensure!(
        expected_from.is_none_or(|v| v.eq_ignore_ascii_case(&from))
            && expected_to.is_none_or(|v| v.eq_ignore_ascii_case(&to)),
        "stream domain changed"
    );
    Ok((from, to))
}
fn element(xml: &str, ns: &str, name: &str) -> Result<bool> {
    let w = wrap(xml);
    let d = roxmltree::Document::parse(&w)?;
    Ok(d.root_element()
        .first_element_child()
        .is_some_and(|n| n.tag_name().namespace() == Some(ns) && n.tag_name().name() == name))
}
fn feature(xml: &str, ns: &str, name: &str) -> Result<bool> {
    let w = wrap(xml);
    let d = roxmltree::Document::parse(&w)?;
    let features = d
        .root_element()
        .first_element_child()
        .context("missing features")?;
    ensure!(
        features.has_tag_name((STREAM, "features")),
        "missing stream features"
    );
    Ok(features.children().any(|n| n.has_tag_name((ns, name))))
}
fn external_feature(xml: &str) -> Result<bool> {
    let w = wrap(xml);
    let d = roxmltree::Document::parse(&w)?;
    let features = d
        .root_element()
        .first_element_child()
        .context("missing features")?;
    ensure!(
        features.has_tag_name((STREAM, "features")),
        "missing SASL features"
    );
    Ok(features
        .children()
        .filter(|n| n.has_tag_name((SASL, "mechanisms")))
        .flat_map(|n| n.children())
        .any(|n| n.has_tag_name((SASL, "mechanism")) && n.text() == Some("EXTERNAL")))
}
fn validate_stanza(xml: &str, from_domain: &str, to_domain: &str) -> Result<()> {
    let w = wrap(xml);
    let d = roxmltree::Document::parse(&w)?;
    let root = d.root_element();
    ensure!(
        root.children().filter(|n| n.is_element()).count() == 1,
        "multiple stanzas"
    );
    let n = root.first_element_child().context("missing stanza")?;
    ensure!(
        matches!(n.tag_name().name(), "iq" | "message" | "presence")
            && matches!(
                n.tag_name().namespace(),
                Some(SERVER) | Some("jabber:client")
            ),
        "invalid federation stanza"
    );
    ensure!(
        jid_domain(n.attribute("from").context("missing stanza from")?)? == from_domain,
        "forged source domain"
    );
    ensure!(
        jid_domain(n.attribute("to").context("missing stanza to")?)? == to_domain,
        "wrong destination domain"
    );
    Ok(())
}
fn server_stanza(xml: &str) -> Result<String> {
    let w = wrap(xml);
    let d = roxmltree::Document::parse(&w)?;
    let n = d
        .root_element()
        .first_element_child()
        .context("missing stanza")?;
    Ok(crate::protocol::xml_namespace(
        n,
        Some(("jabber:client", SERVER)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_domains_are_dns_names_and_case_insensitive() {
        assert_eq!(canonical_domain("Alpha.TEST").unwrap(), "alpha.test");
        for invalid in [
            "",
            "::1",
            "[::1]",
            "alpha.test.",
            ".test",
            "a..test",
            "-alpha.test",
            "alpha-.test",
            "_xmpp.test",
            "alpha@beta.test",
            "alpha/test",
        ] {
            assert!(canonical_domain(invalid).is_err(), "{invalid}");
        }
        assert!(canonical_domain(&format!("{}.test", "a".repeat(64))).is_err());
        assert_eq!(jid_domain("alice@ALPHA.TEST/r").unwrap(), "alpha.test");
        for invalid in [
            "@alpha.test",
            "alice@@alpha.test",
            "alice@",
            "alice@bad_domain.test",
        ] {
            assert!(jid_domain(invalid).is_err(), "{invalid}");
        }
        validate_stanza(
            "<message from='alice@ALPHA.TEST/r' to='bob@BETA.TEST'/>",
            "alpha.test",
            "beta.test",
        )
        .unwrap();
    }

    #[test]
    fn starttls_must_be_an_immediate_stream_feature() {
        assert!(
            feature(
                &format!("<stream:features><starttls xmlns='{TLS}'/></stream:features>"),
                TLS,
                "starttls",
            )
            .unwrap()
        );
        assert!(
            feature(
                &format!("<message><starttls xmlns='{TLS}'/></message>"),
                TLS,
                "starttls"
            )
            .is_err()
        );
        assert!(
            !feature(
                &format!(
                    "<stream:features><nested><starttls xmlns='{TLS}'/></nested></stream:features>"
                ),
                TLS,
                "starttls",
            )
            .unwrap()
        );
    }

    #[test]
    fn external_must_be_in_the_advertised_mechanisms() {
        let mechanisms =
            format!("<mechanisms xmlns='{SASL}'><mechanism>EXTERNAL</mechanism></mechanisms>");
        assert!(
            external_feature(&format!("<stream:features>{mechanisms}</stream:features>")).unwrap()
        );
        assert!(
            !external_feature(&format!(
                "<stream:features><extension>{mechanisms}</extension></stream:features>"
            ))
            .unwrap()
        );
        assert!(!external_feature(&format!("<stream:features><extension><stream:features>{mechanisms}</stream:features></extension></stream:features>")).unwrap());
        assert!(external_feature(&format!("<message>{mechanisms}</message>")).is_err());
    }

    #[tokio::test]
    async fn stream_restarts_compare_canonical_domains() {
        let text = header("Alpha.TEST", "BETA.TEST");
        let mut input = text.as_bytes();
        let domains = read_header(
            &mut input,
            &mut Framer::default(),
            Some("alpha.test"),
            Some("beta.test"),
        )
        .await
        .unwrap();
        assert_eq!(domains, ("alpha.test".into(), "beta.test".into()));
        let text = header("gamma.test", "beta.test");
        let mut input = text.as_bytes();
        assert!(
            read_header(
                &mut input,
                &mut Framer::default(),
                Some("alpha.test"),
                Some("beta.test")
            )
            .await
            .is_err()
        );
    }
}
