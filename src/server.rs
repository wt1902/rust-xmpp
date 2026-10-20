use crate::{
    auth,
    config::{self, Config},
    logging::{Level, Logger},
    protocol::{self, ModuleResult},
    sasl,
    sessions::{Hub, SharedSession},
    wire::{Framer, escape},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    collections::BTreeMap,
    fs,
    io::BufReader,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    time::{Duration, timeout},
};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};
const CLIENT: &str = "jabber:client";
const SASL: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const SASL2: &str = "urn:xmpp:sasl:2";
const BIND2: &str = "urn:xmpp:bind:0";
const BIND: &str = "urn:ietf:params:xml:ns:xmpp-bind";
const STREAM: &str = "http://etherx.jabber.org/streams";
const TLS: &str = "urn:ietf:params:xml:ns:xmpp-tls";
#[derive(Clone)]
pub struct Runtime {
    _data_guard: Arc<crate::data_lock::DataDirectoryGuard>,
    domain: String,
    data: PathBuf,
    hash: String,
    tls: TlsAcceptor,
    logger: Logger,
    tls_endpoint: Option<sasl::ChannelBinding>,
    config: Arc<Config>,
    hub: Hub,
    mucs: Arc<Mutex<BTreeMap<String, crate::muc::Muc>>>,
    uploads: Arc<BTreeMap<String, crate::http_service::UploadService>>,
    started: Instant,
    push: Arc<Mutex<crate::push::Push>>,
    federation: Option<crate::federation::Federation>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
}
/// Keep upload services separate: their HTTP hosts, mounts and credentials belong
/// to the component, while all listeners share one dispatcher.
#[derive(Clone)]
struct UploadRoute {
    name: String,
    config: crate::http_config::HttpConfig,
    service: crate::http_service::UploadService,
}
pub(crate) fn upload_backend(
    config: &Config,
    name: &str,
) -> Result<crate::object_store::UploadBackendConfig> {
    use crate::object_store::{S3Config, UploadBackendConfig};
    let backend = config
        .option(name, "http_file_share_backend")
        .map(|value| {
            value
                .as_str()
                .context("http_file_share_backend must be a string")
        })
        .transpose()?
        .unwrap_or("local");
    match backend {
        "local" => Ok(UploadBackendConfig::Local),
        "s3" => {
            let options = config
                .option(name, "http_file_share_s3")
                .and_then(|value| value.as_object())
                .context("http_file_share_s3 must be a table for S3 uploads")?;
            let field = |key: &str| -> Result<Option<String>> {
                if let Some(value) = options.get(&format!("{key}_env")) {
                    let variable = value.as_str().with_context(|| {
                        format!("http_file_share_s3.{key}_env must be a string")
                    })?;
                    return Ok(Some(std::env::var(variable).with_context(|| {
                        format!("environment variable for http_file_share_s3.{key} is unavailable")
                    })?));
                }
                options
                    .get(key)
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_owned)
                            .with_context(|| format!("http_file_share_s3.{key} must be a string"))
                    })
                    .transpose()
            };
            let required = |key: &str| {
                field(key)?
                    .filter(|value| !value.is_empty())
                    .with_context(|| format!("http_file_share_s3.{key} is required"))
            };
            Ok(UploadBackendConfig::S3(S3Config {
                endpoint: required("endpoint")?,
                bucket: required("bucket")?,
                region: required("region")?,
                access_key: required("access_key")?,
                secret_key: required("secret_key")?,
                session_token: field("session_token")?,
                key_prefix: field("key_prefix")?.unwrap_or_default(),
            }))
        }
        other => bail!("unsupported http_file_share_backend: {other}"),
    }
}
fn upload_mount_matches(mount: &str, path: &str) -> bool {
    mount == "/"
        || path == mount
        || path
            .strip_prefix(mount)
            .is_some_and(|rest| rest.starts_with('/'))
}
fn upload_routes(
    config: &Config,
    uploads: &BTreeMap<String, crate::http_service::UploadService>,
) -> Result<Arc<Vec<UploadRoute>>> {
    let mut routes: Vec<UploadRoute> = Vec::new();
    for (name, service) in uploads {
        let http = crate::http_config::HttpConfig::for_host(config, name)?;
        for existing in &routes {
            ensure!(
                existing.config.host != http.host
                    || !(upload_mount_matches(
                        &existing.config.file_share_path,
                        &http.file_share_path
                    ) || upload_mount_matches(
                        &http.file_share_path,
                        &existing.config.file_share_path
                    )),
                "ambiguous HTTP upload components '{}' and '{}': HTTP host '{}' has overlapping mounts '{}' and '{}'",
                existing.name,
                name,
                http.host,
                existing.config.file_share_path,
                http.file_share_path
            );
        }
        routes.push(UploadRoute {
            name: name.clone(),
            config: http,
            service: service.clone(),
        });
    }
    Ok(Arc::new(routes))
}
async fn dispatch_upload(
    routes: Arc<Vec<UploadRoute>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok());
    if let Some(route) = routes.iter().find(|route| {
        host.is_some_and(|host| route.config.accepts_host(host))
            && upload_mount_matches(&route.config.file_share_path, request.uri().path())
    }) {
        let mut response = route
            .service
            .handle_at(request, &route.config.file_share_path)
            .await;
        response
            .extensions_mut()
            .insert(crate::http_transport::HttpRoute::Upload);
        return response;
    }
    axum::http::StatusCode::NOT_FOUND.into_response()
}
struct ConnectionLog {
    logger: Logger,
    id: String,
    started: Instant,
    phase: &'static str,
}
impl ConnectionLog {
    fn new(rt: &Runtime, transport: &str, peer: &str) -> Self {
        let ctx = Self {
            logger: rt.logger.clone(),
            id: uuid::Uuid::new_v4().to_string(),
            started: Instant::now(),
            phase: "stream-open",
        };
        ctx.event(
            Level::Info,
            "connection-open",
            &[
                ("transport", transport),
                ("peer", peer),
                ("host", &rt.domain),
            ],
        );
        ctx
    }
    fn event(&self, level: Level, event: &str, fields: &[(&str, &str)]) {
        self.logger
            .event(level, "c2s", Some(&self.id), event, fields);
    }
    fn finish(&self, result: &Result<()>) {
        let elapsed = self.started.elapsed().as_millis().to_string();
        let reason = match result {
            Ok(()) => "stream-complete",
            Err(e) if e.is::<PeerStreamClosed>() => "stream-complete",
            Err(e) if e.to_string() == "connection closed" => "peer-disconnected",
            Err(e) if e.to_string() == "authentication failed" => {
                "authentication-attempts-exhausted"
            }
            Err(e) if e.downcast_ref::<tokio::time::error::Elapsed>().is_some() => "timeout",
            Err(e) if e.to_string() == "invalid stream header" => "invalid-stream-header",
            Err(e) if e.to_string() == "TLS required" => "starttls-required",
            Err(e) if e.to_string() == "binding required" => "resource-binding-required",
            Err(e) if e.to_string() == "stanza too large" => "stanza-size-limit",
            Err(e) if e.downcast_ref::<roxmltree::Error>().is_some() => "invalid-xml",
            Err(_) if self.phase == "tls-handshake" => "tls-handshake-failed",
            Err(_) => "protocol-or-transport-error",
        };
        let io_kind = result
            .as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<std::io::Error>())
            .map(|e| format!("{:?}", e.kind()))
            .unwrap_or_else(|| "none".into());
        self.event(
            if result.is_err() && !matches!(reason, "peer-disconnected" | "stream-complete") {
                Level::Warn
            } else {
                Level::Info
            },
            "connection-closed",
            &[
                ("phase", self.phase),
                ("reason", reason),
                ("duration_ms", &elapsed),
                ("io_kind", &io_kind),
            ],
        );
    }
}
fn sasl_reason(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "malformed-request" => "malformed-request",
        "extensions-not-supported" => "extensions-not-supported",
        "channel-binding-not-supported" => "channel-binding-not-supported",
        "unsupported-channel-binding-type" => "unsupported-channel-binding-type",
        "server-does-support-channel-binding" => "channel-binding-downgrade-detected",
        "channel-bindings-dont-match" => "channel-binding-mismatch",
        "invalid-username-encoding" => "invalid-username-encoding",
        "invalid-authzid" => "invalid-authzid",
        "invalid-credentials" | "invalid SCRAM credentials" => "account-hash-or-record-invalid",
        "unsupported/incomplete account record" | "invalid account record" => {
            "account-record-invalid"
        }
        "invalid-client-proof" => "invalid-client-proof",
        "nonce-mismatch" => "nonce-mismatch",
        "not-authorized" => "invalid-client-proof-or-account-unavailable",
        _ => "invalid-exchange-or-account-store-error",
    }
}
struct Cleanup {
    runtime: Runtime,
    token: String,
    graceful: bool,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        for session in self.runtime.hub.all() {
            let state = session.lock().unwrap();
            if state.connection == self.token {
                self.runtime.logger.event(
                    Level::Info,
                    "smacks",
                    Some(&self.token),
                    "session-disconnected",
                    &[
                        ("jid", &state.jid),
                        (
                            "mode",
                            if !self.graceful && state.sm && state.resume_id.is_some() {
                                "hibernating"
                            } else {
                                "removed"
                            },
                        ),
                        ("unacked", &state.pending.len().to_string()),
                    ],
                );
            }
        }
        for jid in self.runtime.hub.disconnect(&self.token, self.graceful) {
            self.runtime.disconnected(&jid);
        }
        if !self.graceful && self.runtime.enabled("cloud_notify") {
            let mut queued = Vec::new();
            for session in self.runtime.hub.all() {
                let s = session.lock().unwrap();
                if s.connection != self.token || s.sender.is_some() {
                    continue;
                }
                if let Some(identifier) = &s.push_identifier
                    && let Some(user) = self.runtime.owner(&s.jid)
                {
                    queued.push((
                        user,
                        identifier.clone(),
                        s.pending.iter().cloned().collect::<Vec<_>>(),
                    ));
                }
            }
            if !queued.is_empty()
                && let Ok(handle) = tokio::runtime::Handle::try_current()
            {
                let rt = self.runtime.clone();
                handle.spawn(async move {
                    for (user, identifier, messages) in queued {
                        let result = rt.push.lock().unwrap().notify_queue(
                            &rt.data,
                            &rt.domain,
                            &user,
                            &messages,
                            &rt.config,
                            &identifier,
                        );
                        let notifications = if let Ok(result) = result {
                            if result.reset_watchdog {
                                reset_push_watchdog(&rt, &user, &identifier);
                            }
                            result.deliveries
                        } else {
                            Vec::new()
                        };
                        for (to, payload) in notifications {
                            let _ = route_delivery(&rt, &to, &payload).await;
                        }
                    }
                });
            }
        }
    }
}
impl Runtime {
    fn enabled(&self, m: &str) -> bool {
        self.config
            .modules(&self.domain)
            .is_ok_and(|s| s.contains(m))
    }
    fn disconnected(&self, jid: &str) {
        if let Ok(d) =
            roxmltree::Document::parse("<presence xmlns='jabber:client' type='unavailable'/>")
        {
            let _ = crate::pubsub::on_presence(&self.data, &self.domain, jid, d.root_element());
        }
        // Shutdown freezes MUC membership before transport teardown. Teardown
        // must not erase temporary room checkpoints as if every user had left.
        if self.stopping.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let mut rooms = self.mucs.lock().unwrap();
        for muc in rooms.values_mut() {
            let result = muc.disconnect(jid);
            for (to, xml) in result.deliveries {
                self.hub.deliver(&to, &xml);
            }
        }
    }
    fn bind_session(
        &self,
        full: &str,
        token: &str,
        sender: mpsc::Sender<String>,
    ) -> Result<SharedSession> {
        let policy = crate::sessions::ConflictPolicy::from_config(
            self.config
                .option(&self.domain, "conflict_resolve")
                .and_then(|v| v.as_str()),
        );
        let (session, replaced) = self.hub.bind_resolving(
            full,
            token,
            sender,
            Duration::from_secs(number(
                &self.config,
                &self.domain,
                "smacks_hibernation_time",
                300,
            )),
            policy,
        )?;
        if let Some(old) = replaced {
            let (jid, previous) = {
                let state = old.lock().unwrap();
                (state.jid.clone(), state.connection.clone())
            };
            self.logger.event(
                Level::Info,
                "bind",
                Some(token),
                "resource-replaced",
                &[
                    ("jid", &jid),
                    ("previous_connection", &previous),
                    ("policy", &format!("{policy:?}")),
                ],
            );
            self.disconnected(&jid);
        }
        Ok(session)
    }
    fn owner(&self, jid: &str) -> Option<String> {
        let (user, domain) = protocol::bare(jid).split_once('@')?;
        (domain == self.domain).then(|| user.to_owned())
    }
}
pub fn settings_config(path: &Path) -> Result<(Config, String)> {
    let c = config::load(path)?;
    let hosts: Vec<_> = c
        .hosts
        .iter()
        .filter(|(_, h)| h.component.is_none())
        .collect();
    ensure!(
        hosts.len() == 1,
        "runtime requires exactly one VirtualHost (components allowed)"
    );
    let d = hosts[0].0.clone();
    ensure!(
        c.option(&d, "authentication").and_then(|v| v.as_str()) == Some("internal_hashed"),
        "authentication must be internal_hashed"
    );
    Ok((c, d))
}
pub fn account_config(path: &Path) -> Result<(PathBuf, String, String)> {
    let (c, d) = settings_config(path)?;
    let data = c
        .option(&d, "data_path")
        .and_then(|v| v.as_str())
        .context("data_path required")?;
    let hash = c
        .option(&d, "password_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("SHA-1");
    ensure!(
        matches!(hash, "SHA-1" | "SHA-256"),
        "unsupported password_hash"
    );
    Ok((data.into(), d.clone(), hash.into()))
}
fn ports(c: &Config, d: &str, key: &str) -> Vec<u16> {
    c.option(d, key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u16))
                .collect()
        })
        .unwrap_or_default()
}
fn boolean(c: &Config, d: &str, k: &str, default: bool) -> bool {
    c.option(d, k).and_then(|v| v.as_bool()).unwrap_or(default)
}
fn refresh_push_session(rt: &Runtime, session: &SharedSession) -> Result<()> {
    let (jid, client_id) = {
        let s = session.lock().unwrap();
        (s.jid.clone(), s.client_id.clone())
    };
    let identifier = if rt.enabled("cloud_notify") {
        crate::push::client_device(
            &rt.data,
            &rt.domain,
            &rt.owner(&jid).context("local account")?,
            client_id.as_deref(),
            jid.split_once('/').map(|(_, r)| r).unwrap_or(""),
        )?
    } else {
        None
    };
    let timeout = if identifier.is_some() {
        number(
            &rt.config,
            &rt.domain,
            "push_max_hibernation_timeout",
            72 * 3600,
        )
    } else {
        number(&rt.config, &rt.domain, "smacks_hibernation_time", 300)
    };
    let mut s = session.lock().unwrap();
    s.push_identifier = identifier;
    s.first_push_sent = false;
    s.timeout = Duration::from_secs(timeout);
    Ok(())
}
fn message_pushes(
    rt: &Runtime,
    user: &str,
    to: &str,
    delivered: usize,
    message: roxmltree::Node<'_, '_>,
) -> Result<Vec<(String, String)>> {
    if !rt.enabled("cloud_notify") || message.attribute("type") == Some("error") {
        return Ok(vec![]);
    }
    if delivered == 0 {
        return rt
            .push
            .lock()
            .unwrap()
            .notify(&rt.data, &rt.domain, user, message, &rt.config);
    }
    let mut identifiers = std::collections::BTreeSet::new();
    for session in rt.hub.message_targets(to) {
        let s = session.lock().unwrap();
        if s.sender.is_none()
            && let Some(id) = &s.push_identifier
        {
            identifiers.insert(id.clone());
        }
    }
    let mut notifications = Vec::new();
    for id in identifiers {
        let deliveries = rt.push.lock().unwrap().notify_for_identifier(
            &rt.data,
            &rt.domain,
            user,
            message,
            &rt.config,
            Some(&id),
        )?;
        if !deliveries.is_empty() && crate::push::resets_watchdog(message, &rt.config, &rt.domain) {
            reset_push_watchdog(rt, user, &id);
        }
        notifications.extend(deliveries);
    }
    Ok(notifications)
}
fn reset_push_watchdog(rt: &Runtime, user: &str, identifier: &str) {
    let owner = format!("{user}@{}", rt.domain);
    let timeout = Duration::from_secs(number(
        &rt.config,
        &rt.domain,
        "smacks_hibernation_time",
        300,
    ));
    for session in rt.hub.all() {
        let mut s = session.lock().unwrap();
        if s.owner == owner && s.push_identifier.as_deref() == Some(identifier) {
            s.first_important_push(timeout);
        }
    }
}
fn remove_push_sessions(rt: &Runtime) {
    let removed = rt.push.lock().unwrap().take_removed();
    if removed.is_empty() {
        return;
    }
    let timeout = Duration::from_secs(number(
        &rt.config,
        &rt.domain,
        "smacks_hibernation_time",
        300,
    ));
    for session in rt.hub.all() {
        let mut s = session.lock().unwrap();
        if removed.iter().any(|(user, id)| {
            s.owner == format!("{user}@{}", rt.domain) && s.push_identifier.as_deref() == Some(id)
        }) {
            s.push_identifier = None;
            s.timeout = timeout;
            s.first_push_sent = false;
            if s.expires.is_some() {
                s.expires = Some(Instant::now() + timeout);
            }
        }
    }
}
fn http_interfaces(c: &Config, domain: &str, secure: bool) -> Result<Vec<std::net::IpAddr>> {
    let key = if secure {
        "https_interfaces"
    } else {
        "http_interfaces"
    };
    let configured = c
        .option(domain, key)
        .or_else(|| c.option(domain, "interfaces"));
    let mut addresses = std::collections::BTreeSet::new();
    let mut add = |value: &serde_json::Value| -> Result<()> {
        let value = value
            .as_str()
            .context("HTTP interface must be an IP address or *")?;
        if value == "*" {
            addresses.insert(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            addresses.insert(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
        } else {
            addresses.insert(
                value
                    .parse::<std::net::IpAddr>()
                    .context("invalid HTTP interface IP")?,
            );
        }
        Ok(())
    };
    match configured {
        Some(serde_json::Value::Array(values)) => {
            for value in values {
                add(value)?;
            }
        }
        Some(value) => add(value)?,
        None => add(&serde_json::Value::String("*".into()))?,
    }
    Ok(addresses.into_iter().collect())
}

fn number(c: &Config, d: &str, k: &str, default: u64) -> u64 {
    c.option(d, k).and_then(|v| v.as_u64()).unwrap_or(default)
}
pub async fn serve(path: &Path) -> Result<()> {
    let (c, domain) = settings_config(path)?;
    let default_debug_log = serde_json::Value::String("debug".into());
    let logger = Logger::from_config_with_format(
        c.option(&domain, "log")
            .or_else(|| boolean(&c, &domain, "debug", false).then_some(&default_debug_log)),
        c.option(&domain, "log_format").and_then(|v| v.as_str()),
    )?;
    logger.event(
        Level::Info,
        "server",
        None,
        "starting",
        &[("version", env!("CARGO_PKG_VERSION")), ("host", &domain)],
    );
    let implemented = [
        "tls",
        "saslauth",
        "sasl2",
        "bind2",
        "sasl2_bind2",
        "sasl_ssdp",
        "disco",
        "ping",
        "version",
        "roster",
        "private",
        "vcard_legacy",
        "blocklist",
        "mam",
        "pep",
        "pep_simple",
        "bookmarks",
        "smacks",
        "csi_simple",
        "carbons",
        "time",
        "uptime",
        "turn_external",
        "seclabels",
        "register",
        "admin_shell",
        "websocket",
        "bosh",
        "http_altconnect",
        "cloud_notify",
        "s2s",
        "s2s_auth_certs",
    ];
    let missing: Vec<_> = c
        .modules(&domain)?
        .into_iter()
        .filter(|m| !implemented.contains(&m.as_str()))
        .collect();
    ensure!(
        missing.is_empty(),
        "modules not integrated: {}",
        missing.join(", ")
    );

    let (data, _, hash) = account_config(path)?;
    let data_guard = Arc::new(crate::data_lock::DataDirectoryGuard::acquire(&data)?);
    crate::upload_migration::ensure_no_pending(&data)?;
    let ssl = c.option(&domain, "ssl").context("ssl required")?;
    let cert = ssl
        .get("certificate")
        .and_then(|v| v.as_str())
        .context("ssl.certificate required")?;
    let key = ssl
        .get("key")
        .and_then(|v| v.as_str())
        .context("ssl.key required")?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(fs::File::open(cert)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(key)?))?
        .context("private key missing")?;
    let tls = TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.clone_key())?,
    ));
    let federation = if c.modules(&domain)?.contains("s2s") {
        let mut f = crate::federation::Federation::new(
            domain.clone(),
            certs.clone(),
            key.clone_key(),
            crate::federation::Federation::native_roots()?,
        )?;
        for name in c.hosts.keys() {
            f.add_local_domain(name.clone())?;
        }
        Some(f)
    } else {
        None
    };
    crate::account_modules::set_legacy_pep_limit(
        &data,
        &domain,
        number(&c, &domain, "pep_max_items", 256) as usize,
    )?;
    let mut mucs = BTreeMap::new();
    let mut uploads = BTreeMap::new();
    for (name, host) in &c.hosts {
        match host.component.as_deref() {
            Some("muc") => {
                let mut muc = crate::muc::Muc::new(data.clone(), name.clone());
                let mut options = c.global.clone();
                options.extend(host.options.clone());
                muc.set_component_options(
                    serde_json::Value::Object(options),
                    c.modules(name)?.contains("muc_mam"),
                );
                muc.set_local_domain(domain.clone());
                muc.set_tombstones(boolean(&c, name, "muc_tombstones", true));
                muc.set_archive_retention(period(
                    c.option(name, "muc_log_expires_after")
                        .or_else(|| c.option(name, "mam_muc_archive_expires_after")),
                    Some(604800.0),
                ));
                muc.prepare_recovery()?;
                mucs.insert(name.clone(), muc);
            }
            Some("http_file_share") => {
                let https = ports(&c, &domain, "https_ports");
                let http = ports(&c, &domain, "http_ports");
                let http_config = crate::http_config::HttpConfig::for_host(&c, name)?;
                let (secure_url, port) = https
                    .first()
                    .map(|p| (true, *p))
                    .unwrap_or_else(|| (false, *http.first().unwrap_or(&5280)));
                let base = http_config.external_url("file_share", secure_url, port)?;
                let base = c
                    .option(name, "http_file_share_base_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim_end_matches('/').to_owned())
                    .unwrap_or(base);
                let service = crate::http_service::UploadService::new_with_backend(
                    crate::http_service::UploadConfig {
                        root: data.clone(),
                        host: name.clone(),
                        base_url: base,
                        size_limit: number(
                            &c,
                            name,
                            "http_file_share_size_limit",
                            10 * 1024 * 1024,
                        ),
                        daily_quota: number(
                            &c,
                            name,
                            "http_file_share_daily_quota",
                            number(&c, name, "http_file_share_size_limit", 10 * 1024 * 1024)
                                .saturating_mul(10),
                        ),
                        global_quota: number(&c, name, "http_file_share_global_quota", u64::MAX),
                        expires_after: period(
                            c.option(name, "http_file_share_expires_after"),
                            Some(7.0 * 86400.0),
                        )
                        .map(|n| n.max(0.0) as u64),
                        allowed_types: c
                            .option(name, "http_file_share_allowed_file_types")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(str::to_owned))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        secret: c
                            .option(name, "http_file_share_secret")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned),
                    },
                    upload_backend(&c, name)?,
                )?;
                service.recover_backend().await?;
                for slot in service.quarantined_slots() {
                    logger.event(
                        Level::Warn,
                        "upload",
                        None,
                        "completion-quarantined",
                        &[
                            ("component", name),
                            ("slot", &slot),
                            ("reason", "remote-completion-outcome-uncertain"),
                        ],
                    );
                }
                uploads.insert(name.clone(), service);
            }
            Some("pubsub") | None => {}
            Some(other) => bail!("component not integrated: {other}"),
        }
    }
    let upload_routes = upload_routes(&c, &uploads)?;
    let runtime = Runtime {
        _data_guard: data_guard,
        domain: domain.clone(),
        data,
        hash,
        tls: tls.clone(),
        logger: logger.clone(),
        tls_endpoint: certs.first().and_then(|cert| {
            match crate::tls_binding::server_end_point(cert.as_ref()) {
                Ok(data) => Some(sasl::ChannelBinding {
                    name: "tls-server-end-point".into(),
                    data,
                }),
                Err(_) => {
                    logger.event(
                        Level::Warn,
                        "tls",
                        None,
                        "endpoint-binding-unavailable",
                        &[("reason", "unsupported-certificate-signature-algorithm")],
                    );
                    None
                }
            }
        }),
        config: Arc::new(c.clone()),
        hub: Hub::default(),
        mucs: Arc::new(Mutex::new(mucs)),
        uploads: Arc::new(uploads),
        started: Instant::now(),
        push: Default::default(),
        stopping: Default::default(),
        federation,
    };
    let interfaces = c
        .option(&domain, "interfaces")
        .and_then(|v| v.as_array())
        .context("interfaces required")?;
    let mut tasks = tokio::task::JoinSet::new();
    let semaphore = Arc::new(Semaphore::new(4096));
    for interface in interfaces {
        let ip: std::net::IpAddr = interface.as_str().context("IP expected")?.parse()?;
        for port in ports(&c, &domain, "c2s_ports") {
            let listener = bind_listener(std::net::SocketAddr::new(ip, port))?;
            logger.event(
                Level::Info,
                "c2s",
                None,
                "listener-ready",
                &[
                    ("address", &listener.local_addr()?.to_string()),
                    ("transport", "tcp-starttls"),
                ],
            );
            let rt = runtime.clone();
            let slots = semaphore.clone();
            tasks.spawn(async move {
                loop {
                    let (socket, peer) = listener.accept().await?;
                    if let Ok(permit) = slots.clone().try_acquire_owned() {
                        let rt = rt.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let _ = connection(socket, rt).await;
                        });
                    } else {
                        rt.logger.event(
                            Level::Warn,
                            "c2s",
                            None,
                            "connection-rejected",
                            &[("peer", &peer.to_string()), ("reason", "connection-limit")],
                        );
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            });
        }
    }
    if runtime.enabled("admin_shell") {
        let path = admin_path(&c, &domain, &runtime.data);
        let snapshot = {
            let rt = runtime.clone();
            Arc::new(move || crate::admin::AdminSnapshot {
                uptime: rt.started.elapsed(),
                sessions: rt
                    .hub
                    .all()
                    .into_iter()
                    .map(|s| s.lock().unwrap().jid.clone())
                    .collect(),
            })
        };
        let disconnect: crate::admin::UserMutation = {
            let rt = runtime.clone();
            Arc::new(move |jid: &str| -> Result<()> {
                let old = rt
                    .hub
                    .all()
                    .iter()
                    .filter_map(|s| {
                        let s = s.lock().unwrap();
                        (s.owner == jid).then(|| s.jid.clone())
                    })
                    .collect::<Vec<_>>();
                rt.hub.kick_owner(jid);
                for j in old {
                    rt.disconnected(&j);
                }
                Ok(())
            })
        };
        let delete: crate::admin::UserMutation = {
            let rt = runtime.clone();
            let disconnect = disconnect.clone();
            Arc::new(move |jid: &str| -> Result<()> {
                let (u, d) = jid.split_once('@').context("bare JID required")?;
                crate::storage::update(&rt.data, d, Some(u), "accounts", |a| {
                    a.set("disabled", crate::storage::LuaValue::Bool(true));
                    Ok(())
                })?;
                disconnect(jid)?;
                crate::account_modules::remove_account(&rt.data, d, u)
            })
        };
        let hosts = BTreeMap::from([(domain.clone(), runtime.hash.clone())]);
        let modules = c
            .hosts
            .keys()
            .map(|d| Ok((d.clone(), c.modules(d)?.into_iter().collect())))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let server = crate::admin::AdminServer::bind(
            &path,
            crate::admin::AdminBackend {
                data: runtime.data.clone(),
                hosts,
                modules,
                snapshot,
                delete_user: Some(delete),
                disconnect_user: Some(disconnect),
            },
        )?;
        tasks.spawn(async move { server.serve().await });
    }
    let (federated_tx, mut federated_rx) =
        mpsc::channel::<crate::federation::FederatedStanza>(1024);
    if let Some(federation) = &runtime.federation {
        for interface in interfaces {
            let ip: std::net::IpAddr = interface.as_str().context("interface")?.parse()?;
            for port in ports(&c, &domain, "s2s_ports") {
                let listener = bind_listener(std::net::SocketAddr::new(ip, port))?;
                logger.event(
                    Level::Info,
                    "s2s",
                    None,
                    "listener-ready",
                    &[("address", &listener.local_addr()?.to_string())],
                );
                let fed = federation.clone();
                let tx = federated_tx.clone();
                let log = logger.clone();
                tasks.spawn(async move {
                    loop {
                        let (socket, peer) = listener.accept().await?;
                        let fed = fed.clone();
                        let tx = tx.clone();
                        let log = log.clone();
                        tokio::spawn(async move {
                            let id = uuid::Uuid::new_v4().to_string();
                            log.event(
                                Level::Info,
                                "s2s",
                                Some(&id),
                                "connection-open",
                                &[("peer", &peer.to_string())],
                            );
                            let result = fed.accept(socket, tx).await;
                            log.event(
                                if result.is_ok() {
                                    Level::Info
                                } else {
                                    Level::Warn
                                },
                                "s2s",
                                Some(&id),
                                "connection-closed",
                                &[(
                                    "reason",
                                    if result.is_ok() {
                                        "stream-complete"
                                    } else {
                                        "federation-transport-or-auth-error"
                                    },
                                )],
                            );
                        });
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), anyhow::Error>(())
                });
            }
        }
    }
    for (key, secure) in [("http_ports", false), ("https_ports", true)] {
        for port in ports(&c, &domain, key) {
            let handler: crate::http_transport::ContextConnectionHandler = {
                let rt = runtime.clone();
                Arc::new(move |stream, context| {
                    let rt = rt.clone();
                    Box::pin(web_connection_context(stream, rt, context))
                })
            };
            let http_config = crate::http_config::HttpConfig::for_host(&c, &domain)?;
            let routes = upload_routes.clone();
            let fallback = axum::Router::new().fallback(move |request: axum::extract::Request| {
                let routes = routes.clone();
                async move { dispatch_upload(routes, request).await }
            });
            let app = crate::http_transport::configured_router_with_fallback(
                handler,
                http_config,
                runtime.enabled("websocket"),
                runtime.enabled("bosh"),
                secure,
                fallback,
            )?;
            let app = if runtime.enabled("http_altconnect") {
                let mut preferred = None;
                for (key, secure) in [("https_ports", true), ("http_ports", false)] {
                    if !http_interfaces(&c, &domain, secure)?.is_empty()
                        && let Some(port) = ports(&c, &domain, key).first()
                    {
                        preferred = Some((secure, *port));
                        break;
                    }
                }
                let (advertised_secure, advertised_port) = preferred.unwrap_or((secure, port));
                crate::http_altconnect::with_altconnect(
                    app,
                    &c,
                    &domain,
                    advertised_secure,
                    advertised_port,
                )?
            } else {
                app
            };
            for ip in http_interfaces(&c, &domain, secure)? {
                let listener = bind_listener(std::net::SocketAddr::new(ip, port))?;
                logger.event(
                    Level::Info,
                    "http",
                    None,
                    "listener-ready",
                    &[
                        ("address", &listener.local_addr()?.to_string()),
                        ("transport", if secure { "https" } else { "http" }),
                        (
                            "websocket",
                            if runtime.enabled("websocket") {
                                "enabled"
                            } else {
                                "disabled"
                            },
                        ),
                        (
                            "bosh",
                            if runtime.enabled("bosh") {
                                "enabled"
                            } else {
                                "disabled"
                            },
                        ),
                    ],
                );
                let tls = secure.then(|| tls.clone());
                let app = app.clone();
                let log = logger.clone();
                let proxy = crate::http_proxy::ProxyConfig::from_options(&c.global)?;
                tasks.spawn(async move {
                    crate::http_service::serve_router_configured(
                        listener,
                        tls,
                        app,
                        Some(log),
                        proxy,
                    )
                    .await
                });
            }
        }
    }
    ensure!(!tasks.is_empty(), "no listeners configured");
    logger.event(
        Level::Info,
        "server",
        None,
        "ready",
        &[
            ("host", &domain),
            ("version", env!("CARGO_PKG_VERSION")),
            ("storage", &runtime.data.display().to_string()),
            ("account_hash", &runtime.hash),
        ],
    );
    let mut maintenance = tokio::time::interval(Duration::from_secs(300));
    let mut maintenance_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            _ = hangup.recv() => {
                match logger.reopen() {
                    Ok(()) => logger.event(Level::Info, "logging", None, "logs-reopened", &[]),
                    Err(_) => logger.event(Level::Error, "logging", None, "log-reopen-failed", &[("reason", "cannot-open-log-destination")]),
                }
            },
            _ = maintenance.tick() => {
                if maintenance_task.as_ref().is_none_or(|t| t.is_finished()) {
                    let rt = runtime.clone();
                    let log = logger.clone();
                    maintenance_task = Some(tokio::spawn(async move {
                        if !matches!(tokio::task::spawn_blocking(move || maintenance_run(&rt)).await, Ok(Ok(()))) {
                            log.event(Level::Error, "maintenance", None, "maintenance-failed", &[("reason", "storage-or-worker-error")]);
                        }
                    }));
                }
            },
            _ = tick.tick() => {
                for jid in runtime.hub.expired() {
                    logger.event(Level::Info, "smacks", None, "session-expired", &[("jid", &jid)]);
                    runtime.disconnected(&jid);
                }
            },
            stanza = federated_rx.recv() => {
                if let Some(stanza) = stanza {
                    let rt = runtime.clone();
                    let log = logger.clone();
                    tokio::spawn(async move {
                        if incoming_federated(rt, stanza).await.is_err() {
                            log.event(Level::Warn, "s2s", None, "inbound-routing-failed", &[("reason", "routing-or-storage-error")]);
                        }
                    });
                }
            },
            result = tasks.join_next() => {
                match result { Some(r) => r??, None => break }
            }
        }
    }
    logger.event(Level::Info, "server", None, "shutdown-requested", &[]);
    runtime
        .stopping
        .store(true, std::sync::atomic::Ordering::Release);
    for (domain, muc) in runtime.mucs.lock().unwrap().iter_mut() {
        muc.checkpoint_live()?;
        logger.event(
            Level::Info,
            "muc",
            None,
            "occupant-checkpoint-saved",
            &[("component", domain)],
        );
    }
    tasks.abort_all();
    Ok(())
}
fn bind_listener(addr: std::net::SocketAddr) -> Result<TcpListener> {
    let socket = socket2::Socket::new(
        if addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(TcpListener::from_std(socket.into())?)
}
async fn send<S: AsyncWrite + Unpin>(s: &mut S, xml: &str) -> Result<()> {
    timeout(Duration::from_secs(15), s.write_all(xml.as_bytes())).await??;
    Ok(())
}
async fn csi_send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: Option<&SharedSession>,
    xml: &str,
) -> Result<()> {
    let output = if let Some(session) = session {
        let mut s = session.lock().unwrap();
        let owner = s.owner.clone();
        s.csi.output(xml.into(), &owner, Instant::now())
    } else {
        vec![xml.into()]
    };
    for xml in output {
        send(stream, &xml).await?;
    }
    Ok(())
}
async fn csi_activity<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: Option<&SharedSession>,
) -> Result<()> {
    let output = session
        .map(|s| s.lock().unwrap().csi.activity(Instant::now()))
        .unwrap_or_default();
    for xml in output {
        send(stream, &xml).await?;
    }
    Ok(())
}
async fn emit<S: AsyncWrite + Unpin>(
    s: &mut S,
    session: Option<&SharedSession>,
    xml: &str,
) -> Result<()> {
    if let Some(session) = session {
        let mut session = session.lock().unwrap();
        if session.sm {
            ensure!(session.pending.len() < 4096, "unacknowledged stanza limit");
            session.sent = session.sent.wrapping_add(1);
            session.pending.push_back(xml.into());
        }
    }
    csi_send(s, session, xml).await?;
    if session.is_some_and(|s| s.lock().unwrap().request_ack()) {
        csi_send(s, session, "<r xmlns='urn:xmpp:sm:3'/>").await?;
    }
    Ok(())
}
fn wrap(xml: &str) -> String {
    format!("<root xmlns='{CLIENT}' xmlns:stream='{STREAM}'>{xml}</root>")
}
#[derive(Debug)]
struct PeerStreamClosed;
impl std::fmt::Display for PeerStreamClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("peer closed XMPP stream")
    }
}
impl std::error::Error for PeerStreamClosed {}
async fn frame<S: AsyncRead + AsyncWrite + Unpin>(f: &mut Framer, s: &mut S) -> Result<String> {
    let text = timeout(Duration::from_secs(60), f.next(s)).await??;
    if f.is_stream_end(&text) {
        send(s, "</stream:stream>").await?;
        return Err(PeerStreamClosed.into());
    }
    Ok(text)
}
async fn open<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    f: &mut Framer,
    domain: &str,
    features: &str,
) -> Result<()> {
    let mut text = frame(f, s).await?;
    if text.starts_with("<?xml ") {
        text = frame(f, s).await?;
    }
    let header = crate::wire::StreamHeader::parse(&text)?;
    ensure!(
        header.default_namespace() == Some(CLIENT)
            && header.to.as_deref() == Some(domain)
            && header.version.as_deref() == Some("1.0"),
        "invalid stream header"
    );
    send(s,&format!("<?xml version='1.0'?><stream:stream xmlns='{CLIENT}' xmlns:stream='{STREAM}' from='{}' id='{}' version='1.0'><stream:features>{features}</stream:features>",escape(domain),uuid::Uuid::new_v4())).await
}
async fn connection(tcp: TcpStream, rt: Runtime) -> Result<()> {
    let peer = tcp
        .peer_addr()
        .map(|p| p.to_string())
        .unwrap_or_else(|_| "unknown".into());
    let mut ctx = ConnectionLog::new(&rt, "tcp", &peer);
    let result = connection_inner(tcp, rt, &mut ctx).await;
    ctx.finish(&result);
    result
}
async fn connection_inner(mut tcp: TcpStream, rt: Runtime, ctx: &mut ConnectionLog) -> Result<()> {
    tcp.set_nodelay(true)?;
    let mut f = Framer::default();
    open(
        &mut tcp,
        &mut f,
        &rt.domain,
        &format!("<starttls xmlns='{TLS}'><required/></starttls>"),
    )
    .await?;
    let text = frame(&mut f, &mut tcp).await?;
    {
        let w = f.wrap(&text);
        let d = roxmltree::Document::parse(&w)?;
        let n = d.root_element().first_element_child().context("starttls")?;
        ensure!(
            n.tag_name().namespace() == Some(TLS) && n.tag_name().name() == "starttls",
            "TLS required"
        );
    }
    ensure!(f.buffer.is_empty(), "pipelining before TLS");
    send(&mut tcp, &format!("<proceed xmlns='{TLS}'/>")).await?;
    ctx.phase = "tls-handshake";
    ctx.event(Level::Debug, "tls-handshake-start", &[]);
    let mut stream = timeout(Duration::from_secs(15), rt.tls.accept(tcp)).await??;
    let version = format!("{:?}", stream.get_ref().1.protocol_version());
    let cipher = format!(
        "{:?}",
        stream
            .get_ref()
            .1
            .negotiated_cipher_suite()
            .map(|s| s.suite())
    );
    ctx.event(
        Level::Info,
        "tls-established",
        &[("version", &version), ("cipher", &cipher)],
    );
    let mut cb: Vec<_> = rt.tls_endpoint.iter().cloned().collect();
    // Exporter is selected by Android clients on TLS 1.3. On TLS 1.2,
    // certificate endpoint binding supplies their interoperable fallback.
    if stream.get_ref().1.protocol_version() == Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
        && let Ok(data) = stream.get_ref().1.export_keying_material(
            vec![0u8; 32],
            b"EXPORTER-Channel-Binding",
            Some(b""),
        )
    {
        cb.push(sasl::ChannelBinding {
            name: "tls-exporter".into(),
            data,
        });
    }
    authenticated_transport(&mut stream, rt, cb, ctx).await
}
struct ResumeRequest {
    id: String,
    h: u32,
}
fn inline_resume_request(
    n: roxmltree::Node<'_, '_>,
    rt: &Runtime,
) -> Result<Option<ResumeRequest>> {
    // A cached SASL2 Quickstart may carry optional extensions which this
    // configuration no longer advertises. Leave authentication independent.
    if !rt.enabled("smacks") {
        return Ok(None);
    }
    let resumes: Vec<_> = n
        .children()
        .filter(|c| c.has_tag_name(("urn:xmpp:sm:3", "resume")))
        .collect();
    ensure!(resumes.len() <= 1, "duplicate resume request");
    let Some(resume) = resumes.first() else {
        return Ok(None);
    };
    ensure!(rt.enabled("smacks"), "SM is disabled");
    ensure!(
        !resume.children().any(|c| c.is_element()),
        "nested resume option"
    );
    ensure!(
        resume
            .attributes()
            .all(|a| a.namespace().is_none() && matches!(a.name(), "previd" | "h")),
        "invalid resume attribute"
    );
    let id = resume
        .attribute("previd")
        .filter(|id| !id.is_empty())
        .context("missing resume id")?
        .to_owned();
    let h = resume
        .attribute("h")
        .context("missing resume counter")?
        .parse::<u32>()?;
    Ok(Some(ResumeRequest { id, h }))
}
#[derive(Default)]
struct Bind2Request {
    resource: String,
    carbons: bool,
    inactive: bool,
    sm: Option<bool>,
}
fn bind2_request(n: roxmltree::Node<'_, '_>, rt: &Runtime) -> Result<Option<Bind2Request>> {
    if !(rt.enabled("sasl2_bind2") || rt.enabled("bind2")) {
        return Ok(None);
    }
    let binds: Vec<_> = n
        .children()
        .filter(|c| c.has_tag_name((BIND2, "bind")))
        .collect();
    ensure!(binds.len() <= 1, "duplicate bind request");
    let Some(bind) = binds.first() else {
        return Ok(None);
    };
    ensure!(
        rt.enabled("sasl2_bind2") || rt.enabled("bind2"),
        "bind2 is disabled"
    );
    ensure!(bind.attributes().len() == 0, "invalid bind attributes");
    let mut request = Bind2Request::default();
    let mut tag = None;
    let mut csi = false;
    for child in bind.children().filter(|c| c.is_element()) {
        ensure!(
            !child.children().any(|c| c.is_element()),
            "nested bind option"
        );
        match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(BIND2), "tag") => {
                ensure!(
                    tag.is_none() && child.attributes().len() == 0,
                    "duplicate or invalid tag"
                );
                let prepared = stringprep::resourceprep(child.text().unwrap_or(""))
                    .map_err(|_| anyhow::anyhow!("invalid bind tag"))?;
                ensure!(
                    !prepared.is_empty() && prepared.len() <= 986,
                    "invalid bind tag length"
                );
                tag = Some(prepared.into_owned());
            }
            (Some("urn:xmpp:carbons:2"), "enable") if rt.enabled("carbons") => {
                ensure!(
                    !request.carbons && child.attributes().len() == 0,
                    "invalid carbons option"
                );
                request.carbons = true;
            }
            (Some("urn:xmpp:csi:0"), "active" | "inactive") if rt.enabled("csi_simple") => {
                ensure!(!csi && child.attributes().len() == 0, "invalid CSI option");
                csi = true;
                request.inactive = child.tag_name().name() == "inactive";
            }
            (Some("urn:xmpp:sm:3"), "enable") if rt.enabled("smacks") => {
                ensure!(request.sm.is_none(), "duplicate SM option");
                ensure!(
                    child
                        .attributes()
                        .all(|a| a.name() == "resume" && a.namespace().is_none()),
                    "invalid SM attribute"
                );
                request.sm = Some(match child.attribute("resume") {
                    None | Some("false" | "0") => false,
                    Some("true" | "1") => true,
                    _ => bail!("invalid SM resume"),
                });
            }
            _ => bail!("unsupported bind option"),
        }
    }
    // UUID v4 supplies independent entropy: never expose the stable user-agent id.
    let random = uuid::Uuid::new_v4().to_string();
    request.resource = tag.map(|tag| format!("{tag}/{random}")).unwrap_or(random);
    Ok(Some(request))
}
async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    f: &mut Framer,
    rt: &Runtime,
    cb: Vec<sasl::ChannelBinding>,
    ctx: &mut ConnectionLog,
) -> Result<(
    String,
    bool,
    Option<String>,
    Option<Bind2Request>,
    Option<ResumeRequest>,
    String,
)> {
    let mut cb = cb;
    let mut mechanisms = vec!["PLAIN".to_owned(), format!("SCRAM-{}", rt.hash)];
    if !cb.is_empty() {
        mechanisms.push(format!("SCRAM-{}-PLUS", rt.hash));
    }
    if let Some(disabled) = rt
        .config
        .option(&rt.domain, "disable_sasl_mechanisms")
        .and_then(|v| v.as_array())
    {
        mechanisms.retain(|m| !disabled.iter().any(|d| d.as_str() == Some(m)));
    }
    // XEP-0440 forbids announcing binding types without a usable PLUS
    // mechanism. Disabled mechanisms must also disable downgrade detection.
    if !mechanisms.iter().any(|m| m.ends_with("-PLUS")) {
        cb.clear();
    }
    let list = mechanisms
        .iter()
        .map(|m| format!("<mechanism>{m}</mechanism>"))
        .collect::<String>();
    let mut features = format!("<mechanisms xmlns='{SASL}'>{list}</mechanisms>");
    if rt.enabled("sasl2") {
        let mut inline = if rt.enabled("sasl2_bind2") || rt.enabled("bind2") {
            let extensions = [
                ("carbons", "urn:xmpp:carbons:2"),
                ("csi_simple", "urn:xmpp:csi:0"),
                ("smacks", "urn:xmpp:sm:3"),
            ]
            .iter()
            .filter(|(module, _)| rt.enabled(module))
            .map(|(_, ns)| format!("<feature var='{ns}'/>"))
            .collect::<String>();
            format!("<bind xmlns='{BIND2}'><inline>{extensions}</inline></bind>")
        } else {
            String::new()
        };
        if rt.enabled("smacks") {
            inline.push_str("<sm xmlns='urn:xmpp:sm:3'/>");
        }
        features.push_str(&format!(
            "<authentication xmlns='{SASL2}'>{list}<inline>{inline}</inline></authentication>"
        ));
    }
    if rt.enabled("register") && boolean(&rt.config, &rt.domain, "allow_registration", false) {
        features.push_str("<register xmlns='http://jabber.org/features/iq-register'/>");
    }
    if !cb.is_empty() {
        features.push_str("<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'>");
        for binding in &cb {
            features.push_str(&format!(
                "<channel-binding type='{}'/>",
                escape(&binding.name)
            ));
        }
        features.push_str("</sasl-channel-binding>");
    }
    ctx.phase = "sasl-initial";
    let offered = mechanisms.join(",");
    let bindings = cb
        .iter()
        .map(|c| c.name.as_str())
        .collect::<Vec<_>>()
        .join(",");
    ctx.event(
        Level::Info,
        "sasl-features",
        &[
            ("mechanisms", &offered),
            ("channel_bindings", &bindings),
            ("account_hash", &rt.hash),
            (
                "ssdp",
                if rt.enabled("sasl_ssdp") {
                    "enabled"
                } else {
                    "disabled"
                },
            ),
        ],
    );
    open(stream, f, &rt.domain, &features).await?;
    let mut pending_auth = None;
    for attempt in 1..=3 {
        ctx.phase = "sasl-initial";
        let text = match pending_auth.take() {
            Some(text) => text,
            None => frame(f, stream).await?,
        };
        let w = f.wrap(&text);
        let d = roxmltree::Document::parse(&w)?;
        let n = d.root_element().first_element_child().context("auth")?;
        if n.tag_name().namespace() == Some(CLIENT)
            && n.tag_name().name() == "iq"
            && let Some(q) = n
                .first_element_child()
                .filter(|q| q.tag_name().namespace() == Some("jabber:iq:register"))
        {
            if rt.enabled("register")
                && boolean(&rt.config, &rt.domain, "allow_registration", false)
            {
                if n.attribute("type") == Some("get") {
                    send(stream,&protocol::iq_result(n,"<query xmlns='jabber:iq:register'><instructions>Choose username and password</instructions><username/><password/></query>")).await?;
                    continue;
                }
                let user = q
                    .children()
                    .find(|c| c.is_element() && c.tag_name().name() == "username")
                    .and_then(|c| c.text());
                let password = q
                    .children()
                    .find(|c| c.is_element() && c.tag_name().name() == "password")
                    .and_then(|c| c.text());
                let result = if let (Some(u), Some(p)) = (user, password) {
                    auth::create(&rt.data, &rt.domain, u, p, &rt.hash)
                } else {
                    Err(anyhow::anyhow!("missing fields"))
                };
                let reply = if result.is_ok() {
                    protocol::iq_result(n, "")
                } else {
                    protocol::iq_error(n, "conflict")
                };
                send(stream, &reply).await?;
                continue;
            }
            send(stream, &protocol::iq_error(n, "forbidden")).await?;
            continue;
        }
        let sasl2 = n.tag_name().namespace() == Some(SASL2)
            && n.tag_name().name() == "authenticate"
            && rt.enabled("sasl2");
        let client_id = if sasl2 {
            n.children()
                .find(|c| c.has_tag_name((SASL2, "user-agent")))
                .and_then(|c| c.attribute("id"))
                .filter(|id| !id.is_empty() && id.len() <= 1024)
                .map(str::to_owned)
        } else {
            None
        };
        let ns = if sasl2 { SASL2 } else { SASL };
        if !(sasl2 || (n.tag_name().namespace() == Some(SASL) && n.tag_name().name() == "auth")) {
            send(
                stream,
                &format!("<failure xmlns='{ns}'><invalid-mechanism xmlns='{SASL}'/></failure>"),
            )
            .await?;
            continue;
        }
        let mechanism = n.attribute("mechanism").unwrap_or("");
        let mechanism_label = mechanism.chars().take(64).collect::<String>();
        ctx.event(
            Level::Info,
            "sasl-attempt",
            &[
                ("attempt", &attempt.to_string()),
                ("mechanism", &mechanism_label),
                ("protocol", if sasl2 { "sasl2" } else { "sasl1" }),
            ],
        );
        if sasl2 {
            let cached_bind = n.children().any(|c| c.has_tag_name((BIND2, "bind")));
            let cached_resume = n
                .children()
                .any(|c| c.has_tag_name(("urn:xmpp:sm:3", "resume")));
            let binding_enabled = rt.enabled("sasl2_bind2") || rt.enabled("bind2");
            ctx.event(
                Level::Debug,
                "sasl-inline-options",
                &[
                    ("bind_requested", if cached_bind { "true" } else { "false" }),
                    (
                        "bind_available",
                        if binding_enabled { "true" } else { "false" },
                    ),
                    (
                        "resume_requested",
                        if cached_resume { "true" } else { "false" },
                    ),
                    (
                        "sm_available",
                        if rt.enabled("smacks") {
                            "true"
                        } else {
                            "false"
                        },
                    ),
                ],
            );
            for (requested, available, reason) in [
                (cached_bind, binding_enabled, "bind2-disabled"),
                (cached_resume, rt.enabled("smacks"), "sm-disabled"),
            ] {
                if requested && !available {
                    ctx.event(
                        Level::Info,
                        "inline-request-ignored",
                        &[
                            ("reason", reason),
                            ("fallback", "post-auth-stream-features"),
                        ],
                    );
                }
            }
        }
        let (bind2, resume) = if sasl2 {
            match bind2_request(n, rt).and_then(|bind| Ok((bind, inline_resume_request(n, rt)?))) {
                Ok(request) => request,
                Err(e) => {
                    let detail = match e.to_string().as_str() {
                        "unsupported bind option" => "unsupported-bind-option",
                        "bind2 is disabled" => "bind2-disabled",
                        "duplicate bind request" => "duplicate-bind-request",
                        "duplicate resume request" => "duplicate-resume-request",
                        "SM is disabled" => "sm-disabled",
                        "invalid SM resume" => "invalid-sm-resume",
                        "invalid SM attribute" => "invalid-sm-attribute",
                        "invalid bind attributes" => "invalid-bind-attributes",
                        "duplicate or invalid tag" => "duplicate-or-invalid-bind-tag",
                        "invalid bind tag" | "invalid bind tag length" => "invalid-bind-tag",
                        "nested bind option" => "nested-bind-option",
                        "invalid carbons option" => "invalid-carbons-option",
                        "invalid CSI option" => "invalid-csi-option",
                        "duplicate SM option" => "duplicate-sm-option",
                        "invalid resume attribute" => "invalid-resume-attribute",
                        "missing resume id" => "missing-resume-id",
                        "missing resume counter" => "missing-resume-counter",
                        _ => "invalid-inline-fields",
                    };
                    ctx.event(
                        Level::Warn,
                        "sasl-rejected",
                        &[("reason", "inline-request-malformed"), ("detail", detail)],
                    );
                    send(
                        stream,
                        &format!(
                            "<failure xmlns='{SASL2}'><malformed-request xmlns='{SASL}'/></failure>"
                        ),
                    )
                    .await?;
                    continue;
                }
            }
        } else {
            (None, None)
        };
        if !mechanisms.iter().any(|m| m == mechanism) {
            ctx.event(
                Level::Warn,
                "sasl-rejected",
                &[
                    ("reason", "mechanism-not-offered"),
                    ("mechanism", &mechanism_label),
                ],
            );
            send(
                stream,
                &format!("<failure xmlns='{ns}'><invalid-mechanism xmlns='{SASL}'/></failure>"),
            )
            .await?;
            continue;
        }
        let initial = if sasl2 {
            n.children()
                .find(|c| c.has_tag_name((SASL2, "initial-response")))
                .and_then(|c| c.text())
                .unwrap_or("")
        } else {
            n.text().unwrap_or("")
        };
        let raw = match STANDARD.decode(initial) {
            Ok(v) => v,
            Err(_) => {
                ctx.event(
                    Level::Warn,
                    "sasl-rejected",
                    &[("reason", "incorrect-encoding"), ("mechanism", mechanism)],
                );
                send(
                    stream,
                    &format!(
                        "<failure xmlns='{ns}'><incorrect-encoding xmlns='{SASL}'/></failure>"
                    ),
                )
                .await?;
                continue;
            }
        };
        let mut username = None;
        let mut final_data = String::new();
        if mechanism == "PLAIN" {
            let fields: Vec<_> = raw.split(|&b| b == 0).collect();
            if fields.len() == 3
                && let (Ok(authz), Ok(user), Ok(pass)) = (
                    std::str::from_utf8(fields[0]),
                    std::str::from_utf8(fields[1]),
                    std::str::from_utf8(fields[2]),
                )
                && let Ok(user) = auth::prepared_auth_username(user)
            {
                let authz_matches = authz.is_empty()
                    || authz.split_once('@').is_some_and(|(name, host)| {
                        auth::prepared_auth_username(name).is_ok_and(|name| name == user)
                            && stringprep::nameprep(host).is_ok_and(|host| host == rt.domain)
                    });
                ctx.event(Level::Info, "auth-identity", &[("user", &user)]);
                if authz_matches {
                    let (root, domain, hash, u, p) = (
                        rt.data.clone(),
                        rt.domain.clone(),
                        rt.hash.clone(),
                        user.clone(),
                        pass.to_owned(),
                    );
                    let valid = tokio::task::spawn_blocking(move || {
                        auth::verify(&root, &domain, &u, &p, &hash)
                    })
                    .await?;
                    match valid {
                        Ok(true) => username = Some(user),
                        Ok(false) => {}
                        Err(e) => ctx.event(
                            Level::Warn,
                            "account-lookup",
                            &[("user", &user), ("reason", sasl_reason(&e))],
                        ),
                    }
                } else {
                    ctx.event(
                        Level::Warn,
                        "sasl-rejected",
                        &[("reason", "invalid-authzid"), ("mechanism", mechanism)],
                    );
                }
            }
        } else {
            let opts = sasl::Options {
                // Match the type requested in GS2; SSDP still covers every
                // advertised type. Non-PLUS retains support for downgrade checks.
                channel_binding: if mechanism.ends_with("-PLUS") {
                    std::str::from_utf8(&raw)
                        .ok()
                        .and_then(|s| s.split(',').next())
                        .and_then(|s| s.strip_prefix("p="))
                        .and_then(|name| cb.iter().find(|c| c.name == name))
                        .cloned()
                } else {
                    cb.first().cloned()
                },
                ssdp_mechanisms: rt.enabled("sasl_ssdp").then(|| mechanisms.clone()),
                ssdp_channel_bindings: (rt.enabled("sasl_ssdp") && !cb.is_empty())
                    .then(|| cb.iter().map(|c| c.name.clone()).collect()),
            };
            let result = sasl::Scram::start(
                mechanism,
                &raw,
                &rt.domain,
                |u, h| {
                    let result = auth::load_scram(&rt.data, &rt.domain, u, h);
                    match &result {
                        Ok(Some(c)) => ctx.event(
                            Level::Debug,
                            "account-lookup",
                            &[
                                ("user", u),
                                ("hash", h),
                                ("account_state", "usable"),
                                ("iterations", &c.iterations.to_string()),
                                ("salt_bytes", &c.salt.len().to_string()),
                            ],
                        ),
                        Ok(None) => ctx.event(
                            Level::Warn,
                            "account-lookup",
                            &[
                                ("user", u),
                                ("hash", h),
                                ("account_state", "missing-or-disabled"),
                            ],
                        ),
                        Err(e) => ctx.event(
                            Level::Warn,
                            "account-lookup",
                            &[("user", u), ("hash", h), ("reason", sasl_reason(e))],
                        ),
                    }
                    result
                },
                opts,
            );
            match result {
                Ok((state, challenge)) => {
                    ctx.phase = "sasl-client-final";
                    ctx.event(Level::Info, "sasl-challenge", &[("mechanism", mechanism)]);
                    send(
                        stream,
                        &format!(
                            "<challenge xmlns='{ns}'>{}</challenge>",
                            STANDARD.encode(challenge)
                        ),
                    )
                    .await?;
                    let reply = frame(f, stream).await?;
                    let w = f.wrap(&reply);
                    let d = roxmltree::Document::parse(&w)?;
                    let response = d.root_element().first_element_child();
                    if response.is_some_and(|n| n.has_tag_name((ns, "abort"))) {
                        ctx.event(
                            Level::Warn,
                            "sasl-rejected",
                            &[
                                ("reason", "client-aborted-after-challenge"),
                                ("mechanism", mechanism),
                            ],
                        );
                        send(
                            stream,
                            &format!("<failure xmlns='{ns}'><aborted xmlns='{SASL}'/></failure>"),
                        )
                        .await?;
                        continue;
                    } else if response.is_some_and(|n| {
                        n.has_tag_name((SASL, "auth"))
                            || (rt.enabled("sasl2") && n.has_tag_name((SASL2, "authenticate")))
                    }) {
                        ctx.event(
                            Level::Info,
                            "sasl-restarted",
                            &[("previous_mechanism", mechanism)],
                        );
                        pending_auth = Some(reply);
                        continue;
                    } else if let Some(n) = response.filter(|n| n.has_tag_name((ns, "response"))) {
                        match STANDARD.decode(n.text().unwrap_or("")) {
                            Ok(bytes) => match state.finish(&bytes) {
                                Ok(success) => {
                                    username = Some(success.username);
                                    final_data = success.server_final;
                                }
                                Err(e) => ctx.event(
                                    Level::Warn,
                                    "sasl-rejected",
                                    &[("reason", sasl_reason(&e)), ("mechanism", mechanism)],
                                ),
                            },
                            Err(_) => ctx.event(
                                Level::Warn,
                                "sasl-rejected",
                                &[("reason", "incorrect-encoding"), ("mechanism", mechanism)],
                            ),
                        }
                    } else {
                        ctx.event(
                            Level::Warn,
                            "sasl-rejected",
                            &[
                                ("reason", "unexpected-client-final-element"),
                                ("mechanism", mechanism),
                            ],
                        );
                    }
                }
                Err(e) => ctx.event(
                    Level::Warn,
                    "sasl-rejected",
                    &[("reason", sasl_reason(&e)), ("mechanism", mechanism)],
                ),
            }
        }
        if let Some(user) = username {
            ctx.phase = "sasl-success";
            ctx.event(
                Level::Info,
                "auth-success",
                &[
                    ("user", &user),
                    ("mechanism", mechanism),
                    ("protocol", if sasl2 { "sasl2" } else { "sasl1" }),
                ],
            );
            let extra = if final_data.is_empty() {
                String::new()
            } else {
                STANDARD.encode(final_data)
            };
            let success = if sasl2 {
                format!(
                    "<success xmlns='{SASL2}'><additional-data>{extra}</additional-data><authorization-identifier>{}@{}</authorization-identifier></success>",
                    escape(&user),
                    escape(&rt.domain)
                )
            } else if extra.is_empty() {
                format!("<success xmlns='{SASL}'/>")
            } else {
                format!("<success xmlns='{SASL}'>{extra}</success>")
            };
            return Ok((user, sasl2, client_id, bind2, resume, success));
        }
        if mechanism == "PLAIN" {
            ctx.event(
                Level::Warn,
                "sasl-rejected",
                &[
                    ("reason", "invalid-plain-credentials-or-authzid"),
                    ("mechanism", mechanism),
                ],
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        send(
            stream,
            &format!("<failure xmlns='{ns}'><not-authorized xmlns='{SASL}'/></failure>"),
        )
        .await?;
    }
    bail!("authentication failed")
}
pub async fn web_connection(stream: tokio::io::DuplexStream, rt: Runtime) {
    web_connection_context(stream, rt, None).await;
}
async fn web_connection_context(
    mut stream: tokio::io::DuplexStream,
    rt: Runtime,
    context: Option<crate::http_proxy::RequestContext>,
) {
    let peer = context
        .as_ref()
        .map(|c| c.peer_ip.to_string())
        .unwrap_or_else(|| "not-forwarded".into());
    let mut ctx = ConnectionLog::new(&rt, "http-adapter", &peer);
    if let Some(context) = context {
        ctx.event(
            Level::Info,
            "http-connection-context",
            &[
                ("socket_peer", &context.socket_peer.to_string()),
                ("secure", if context.secure { "true" } else { "false" }),
            ],
        );
    }
    let result = authenticated_transport(&mut stream, rt, Vec::new(), &mut ctx).await;
    ctx.finish(&result);
}

async fn apply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: Option<&SharedSession>,
    rt: &Runtime,
    result: ModuleResult,
) -> Result<()> {
    for xml in result.replies {
        emit(stream, session, &xml).await?;
    }
    for (to, xml) in result.deliveries {
        if let Ok(doc) = roxmltree::Document::parse(&xml)
            && let Some(fields) = crate::pep_diagnostics::event_fields(doc.root_element())
        {
            let fields: Vec<_> = fields
                .iter()
                .map(|(key, value)| (*key, value.as_str()))
                .collect();
            rt.logger
                .event(Level::Info, "pep", None, "notification-generated", &fields);
        }
        route_delivery(rt, &to, &xml).await?;
    }
    Ok(())
}
fn upload_allowed(
    data: &Path,
    config: &Config,
    local_domain: &str,
    component: &str,
    jid: &str,
) -> Result<bool> {
    let bare = protocol::bare(jid);
    let domain = bare.rsplit_once('@').map(|(_, d)| d).unwrap_or(bare);
    if domain == local_domain
        && let Some((user, _)) = bare.split_once('@')
        && crate::storage::load(data, local_domain, Some(user), "accounts")?
            .is_some_and(|a| a.get("disabled") != Some(&crate::storage::LuaValue::Bool(true)))
    {
        return Ok(true);
    }
    Ok(config
        .option(component, "http_file_share_access")
        .and_then(|v| v.as_array())
        .is_some_and(|values| {
            values
                .iter()
                .any(|v| v.as_str().is_some_and(|v| v == bare || v == domain))
        }))
}

// Summarize only protocol metadata. Never log payloads, item IDs, node suffixes,
// IQ IDs or arbitrary XML attribute values (OMEMO bundles and avatar data are private).
fn pep_iq_metadata(
    iq: roxmltree::Node<'_, '_>,
    result: &ModuleResult,
    domain: &str,
    jid: &str,
) -> Option<Vec<(&'static str, String)>> {
    let payload = iq.first_element_child()?;
    let ns = payload.tag_name().namespace().unwrap_or("");
    let discovery = ns == "http://jabber.org/protocol/disco#info";
    if !discovery
        && !matches!(
            ns,
            "http://jabber.org/protocol/pubsub" | "http://jabber.org/protocol/pubsub#owner"
        )
    {
        return None;
    }
    let action = if discovery {
        "disco-info"
    } else {
        match payload.first_element_child().map(|n| n.tag_name().name()) {
            Some("publish") => "publish",
            Some("items") => "items",
            Some("configure") => "configure",
            Some("create") => "create",
            Some("subscribe") => "subscribe",
            Some("unsubscribe") => "unsubscribe",
            Some("retract") => "retract",
            Some("purge") => "purge",
            Some("delete") => "delete",
            Some("affiliations") => "affiliations",
            Some("subscriptions") => "subscriptions",
            Some("default") => "default",
            _ => "other",
        }
    };
    let node = if discovery {
        payload.attribute("node")
    } else {
        payload
            .first_element_child()
            .and_then(|n| n.attribute("node"))
    };
    let node_kind = match node {
        None => "none",
        Some("urn:xmpp:avatar:metadata") => "avatar-metadata",
        Some("urn:xmpp:avatar:data") => "avatar-data",
        Some("eu.siacs.conversations.axolotl.devicelist" | "urn:xmpp:omemo:2:devices") => {
            "omemo-devices"
        }
        Some(v)
            if v.starts_with("eu.siacs.conversations.axolotl.bundles:")
                || v.starts_with("urn:xmpp:omemo:2:bundles") =>
        {
            "omemo-bundle"
        }
        Some("urn:xmpp:bookmarks:1") => "bookmarks",
        Some(_) => "custom",
    };
    let target_scope = match iq.attribute("to") {
        None => "implicit",
        Some(t) if t == domain => "server",
        Some(t) if t.contains('/') => "resource",
        Some(t) if t == protocol::bare(jid) => "self-account",
        Some(t) if t.contains('@') => "other-account",
        Some(_) => "host-or-component",
    };
    let mut device_fields = Vec::new();
    let mut item_count = 0;
    let mut first_payload = "none";
    let mut first_devices = 0;
    let mut status = "no-reply";
    let mut condition = "none";
    let mut pep = false;
    let mut persistent = false;
    let mut options = false;
    let mut precondition = false;
    for xml in &result.replies {
        if let Ok(doc) = roxmltree::Document::parse(xml) {
            let reply = doc.root_element();
            status = match reply.attribute("type") {
                Some("result") => "result",
                Some("error") => "error",
                _ => "other",
            };
            if action == "items"
                && reply.attribute("type") == Some("result")
                && let Some(items) = reply
                    .children()
                    .find(|n| n.has_tag_name(("http://jabber.org/protocol/pubsub", "pubsub")))
                    .and_then(|n| {
                        n.children().find(|n| {
                            n.has_tag_name(("http://jabber.org/protocol/pubsub", "items"))
                        })
                    })
            {
                device_fields = crate::pep_diagnostics::item_fields(items);
                item_count = items
                    .children()
                    .filter(|n| n.has_tag_name(("http://jabber.org/protocol/pubsub", "item")))
                    .count();
                if let Some(payload) = items
                    .children()
                    .find(|n| n.has_tag_name(("http://jabber.org/protocol/pubsub", "item")))
                    .and_then(|n| n.first_element_child())
                {
                    first_payload =
                        match (payload.tag_name().namespace(), payload.tag_name().name()) {
                            (Some("eu.siacs.conversations.axolotl"), "list")
                            | (Some("urn:xmpp:omemo:2"), "devices") => "omemo-devices",
                            (
                                Some("eu.siacs.conversations.axolotl" | "urn:xmpp:omemo:2"),
                                "bundle",
                            ) => "omemo-bundle",
                            (Some("urn:xmpp:avatar:metadata"), "metadata") => "avatar-metadata",
                            (Some("urn:xmpp:avatar:data"), "data") => "avatar-data",
                            (Some("http://jabber.org/protocol/pubsub"), "item") => "nested-item",
                            _ => "other",
                        };
                    if first_payload == "omemo-devices" {
                        first_devices = payload
                            .children()
                            .filter(|n| {
                                n.tag_name().name() == "device"
                                    && n.tag_name().namespace() == payload.tag_name().namespace()
                            })
                            .count();
                    }
                }
            }
            for n in reply
                .children()
                .filter(|n| {
                    n.has_tag_name((CLIENT, "error"))
                        || n.has_tag_name(("http://jabber.org/protocol/disco#info", "query"))
                })
                .flat_map(|n| n.descendants())
                .filter(|n| n.is_element())
            {
                precondition |= n.has_tag_name((
                    "http://jabber.org/protocol/pubsub#errors",
                    "precondition-not-met",
                ));
                if n.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas") {
                    condition = match n.tag_name().name() {
                        "bad-request" => "bad-request",
                        "forbidden" => "forbidden",
                        "item-not-found" => "item-not-found",
                        "conflict" => "conflict",
                        "not-acceptable" => "not-acceptable",
                        "not-allowed" => "not-allowed",
                        "service-unavailable" => "service-unavailable",
                        "internal-server-error" => "internal-server-error",
                        "feature-not-implemented" => "feature-not-implemented",
                        "resource-constraint" => "resource-constraint",
                        _ => "other",
                    };
                }
                pep |= n.has_tag_name(("http://jabber.org/protocol/disco#info", "identity"))
                    && n.attribute("category") == Some("pubsub")
                    && n.attribute("type") == Some("pep");
                if n.has_tag_name(("http://jabber.org/protocol/disco#info", "feature")) {
                    persistent |= n.attribute("var")
                        == Some("http://jabber.org/protocol/pubsub#persistent-items");
                    options |= n.attribute("var")
                        == Some("http://jabber.org/protocol/pubsub#publish-options");
                }
            }
        }
    }
    let mut fields = vec![
        ("action", action.to_owned()),
        ("target_scope", target_scope.to_owned()),
        ("node_kind", node_kind.to_owned()),
        ("status", status.to_owned()),
        ("condition", condition.to_owned()),
        ("precondition_not_met", precondition.to_string()),
        ("deliveries", result.deliveries.len().to_string()),
    ];
    if action == "items" && status == "result" {
        fields.extend([
            ("items_count", item_count.to_string()),
            ("first_content_kind", first_payload.to_owned()),
            ("first_device_count", first_devices.to_string()),
        ]);
    }
    fields.extend(device_fields);
    if discovery {
        fields.extend([
            ("pep_identity", pep.to_string()),
            ("persistent_items", persistent.to_string()),
            ("publish_options", options.to_string()),
        ]);
    }
    Some(fields)
}

fn dispatch_iq(
    rt: &Runtime,
    jid: &str,
    iq: roxmltree::Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    let Some(q) = iq.first_element_child() else {
        return Ok(None);
    };
    let ns = q.tag_name().namespace().unwrap_or("");
    let name = q.tag_name().name();
    let typ = iq.attribute("type").unwrap_or("");
    let target = iq.attribute("to").unwrap_or(&rt.domain);
    let target_bare = protocol::bare(target);
    {
        let mut rooms = rt.mucs.lock().unwrap();
        for muc in rooms.values_mut() {
            if let Some(result) = muc.handle(jid, iq)? {
                return Ok(Some(result));
            }
        }
    }
    if let Some(upload) = rt.uploads.get(target_bare) {
        let payload = if typ == "get" && ns == "urn:xmpp:http:upload:0" && name == "request" {
            if !upload_allowed(&rt.data, &rt.config, &rt.domain, target_bare, jid)? {
                return Ok(Some(ModuleResult::reply(protocol::iq_error(
                    iq,
                    "forbidden",
                ))));
            }
            if q.attribute("size")
                .and_then(|s| s.parse::<u64>().ok())
                .is_none()
                || q.attribute("filename").is_none_or(str::is_empty)
            {
                return Ok(Some(ModuleResult::reply(protocol::iq_error(
                    iq,
                    "bad-request",
                ))));
            }
            match upload.request_slot(
                protocol::bare(jid),
                q.attribute("filename").unwrap_or(""),
                q.attribute("size").unwrap_or("0").parse().unwrap_or(0),
                q.attribute("content-type")
                    .unwrap_or("application/octet-stream"),
            ) {
                Ok(slot) => slot.xml(),
                Err(_) => {
                    return Ok(Some(ModuleResult::reply(protocol::iq_error(
                        iq,
                        "not-acceptable",
                    ))));
                }
            }
        } else if typ == "get" && ns == "http://jabber.org/protocol/disco#info" {
            format!("<query xmlns='{ns}'>{}</query>", upload.disco_info())
        } else {
            return Ok(None);
        };
        return Ok(Some(ModuleResult::reply(protocol::iq_result(iq, &payload))));
    }
    if rt
        .config
        .hosts
        .get(target_bare)
        .and_then(|h| h.component.as_deref())
        == Some("pubsub")
    {
        let admins: Vec<String> = rt
            .config
            .global
            .get("admins")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        return crate::pubsub::handle_component_with_options(
            &rt.data,
            target_bare,
            jid,
            &admins,
            iq,
            &crate::pubsub::Options {
                max_items: number(&rt.config, target_bare, "pubsub_max_items", 256) as usize,
                restrict_node_creation: boolean(
                    &rt.config,
                    target_bare,
                    "restrict_node_creation",
                    true,
                ),
                autocreate_on_publish: false,
            },
        );
    }
    if rt.enabled("pep")
        && let Some(mut reply) = crate::pubsub::handle_with_options(
            &rt.data,
            &rt.domain,
            jid,
            iq,
            &crate::pubsub::Options {
                max_items: number(&rt.config, &rt.domain, "pep_max_items", 256) as usize,
                restrict_node_creation: false,
                autocreate_on_publish: true,
            },
        )?
    {
        if typ == "get"
            && ns == "http://jabber.org/protocol/disco#info"
            && q.attribute("node").is_none()
            && target == target_bare
            && target_bare == protocol::bare(jid)
        {
            for xml in &mut reply.replies {
                if let Some(at) = xml.rfind("</query>") {
                    xml.insert_str(at, &account_features(rt));
                }
            }
        }
        return Ok(Some(reply));
    }
    if rt.enabled("roster")
        && let Some(result) = crate::preauth::handle_iq(&rt.data, &rt.domain, jid, iq)?
    {
        return Ok(Some(result));
    }
    // Bare-account discovery must work independently of the PEP module.
    if typ == "get"
        && name == "query"
        && ns == "http://jabber.org/protocol/disco#info"
        && target == target_bare
        && rt.owner(target).is_some()
    {
        let user = rt.owner(target).unwrap();
        if q.attribute("node").is_some()
            || crate::storage::load(&rt.data, &rt.domain, Some(&user), "accounts")?.is_none()
        {
            return Ok(Some(ModuleResult::reply(protocol::iq_error(
                iq,
                "item-not-found",
            ))));
        }
        let own_features = if target_bare == protocol::bare(jid) {
            account_features(rt)
        } else {
            String::new()
        };
        let payload = format!(
            "<query xmlns='{ns}'><identity category='account' type='registered'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/>{own_features}</query>"
        );
        return Ok(Some(ModuleResult::reply(protocol::iq_result(iq, &payload))));
    }
    if (rt.enabled("vcard_legacy") || rt.enabled("bookmarks"))
        && let Some(result) = crate::account_modules::handle_legacy(&rt.data, &rt.domain, jid, iq)?
    {
        return Ok(Some(result));
    }
    let own = target == rt.domain || target == jid || target_bare == protocol::bare(jid);
    // vCards may be publicly requested; account handler enforces its per-namespace access rules.
    if [
        "jabber:iq:roster",
        "jabber:iq:private",
        "vcard-temp",
        "urn:xmpp:blocking",
    ]
    .contains(&ns)
    {
        let module = match ns {
            "jabber:iq:roster" => "roster",
            "jabber:iq:private" => "private",
            "vcard-temp" => "vcard_legacy",
            _ => "blocklist",
        };
        if rt.enabled(module) {
            return crate::account_modules::handle(&rt.data, &rt.domain, jid, iq);
        }
    }
    if ns == "urn:xmpp:mam:2" && rt.enabled("mam") {
        return crate::mam::handle_with_options(
            &rt.data,
            &rt.domain,
            jid,
            iq,
            archive_policy(rt),
            boolean(&rt.config, &rt.domain, "mam_smart_enable", false),
        );
    }
    if !own {
        return Ok(None);
    }
    if rt.enabled("cloud_notify") {
        let session = rt.hub.get(jid);
        let client_id = session
            .as_ref()
            .and_then(|s| s.lock().unwrap().client_id.clone());
        let result = rt.push.lock().unwrap().handle_with_client(
            &rt.data,
            &rt.domain,
            jid,
            iq,
            number(&rt.config, &rt.domain, "push_max_devices", 5) as usize,
            client_id.as_deref(),
        )?;
        if result.is_some() {
            if let Some(session) = session {
                refresh_push_session(rt, &session)?;
            }
            return Ok(result);
        }
    }
    if let Some(reply) = crate::extras::handle(&rt.config, &rt.domain, iq, rt.started)? {
        return Ok(Some(reply));
    }
    if ns == "jabber:iq:register" && rt.enabled("register") {
        let user = rt.owner(jid).context("local account")?;
        if typ == "get" {
            return Ok(Some(ModuleResult::reply(protocol::iq_result(
                iq,
                &format!(
                    "<query xmlns='{ns}'><registered/><username>{}</username><password/></query>",
                    escape(&user)
                ),
            ))));
        }
        if typ == "set" {
            let target_user = q
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "username")
                .and_then(|n| n.text())
                .unwrap_or(&user);
            if target_user != user {
                return Ok(Some(ModuleResult::reply(protocol::iq_error(
                    iq,
                    "forbidden",
                ))));
            }
            if q.children()
                .any(|n| n.is_element() && n.tag_name().name() == "remove")
            {
                crate::storage::update(&rt.data, &rt.domain, Some(&user), "accounts", |a| {
                    a.set("disabled", crate::storage::LuaValue::Bool(true));
                    Ok(())
                })?;
                let resources = rt
                    .hub
                    .all()
                    .iter()
                    .filter_map(|s| {
                        let s = s.lock().unwrap();
                        (s.owner == protocol::bare(jid)).then(|| s.jid.clone())
                    })
                    .collect::<Vec<_>>();
                rt.hub.kick_owner(protocol::bare(jid));
                for j in resources {
                    rt.disconnected(&j);
                }
                crate::account_modules::remove_account(&rt.data, &rt.domain, &user)?;
                return Ok(Some(ModuleResult::reply(protocol::iq_result(iq, ""))));
            }
            let password = q
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "password")
                .and_then(|n| n.text());
            if let Some(password) = password {
                auth::set_password(&rt.data, &rt.domain, &user, password, &rt.hash)?;
                return Ok(Some(ModuleResult::reply(protocol::iq_result(iq, ""))));
            }
            return Ok(Some(ModuleResult::reply(protocol::iq_error(
                iq,
                "feature-not-implemented",
            ))));
        }
    }
    if typ == "get"
        && name == "query"
        && ns.starts_with("http://jabber.org/protocol/disco#")
        && let Some(node) = q.attribute("node")
    {
        let commands = "http://jabber.org/protocol/commands";
        let invite = crate::preauth::INVITE_COMMAND;
        let local_actor = rt.owner(jid).is_some();
        let payload = if rt.enabled("roster")
            && local_actor
            && target == rt.domain
            && node == commands
            && ns.ends_with("#items")
        {
            Some(format!(
                "<query xmlns='{ns}' node='{commands}'><item jid='{}' node='{invite}' name='Invite contact'/></query>",
                escape(&rt.domain)
            ))
        } else if rt.enabled("roster")
            && local_actor
            && target == rt.domain
            && node == invite
            && ns.ends_with("#info")
        {
            Some(format!(
                "<query xmlns='{ns}' node='{invite}'><identity category='automation' type='command-node' name='Invite contact'/><feature var='{commands}'/><feature var='jabber:x:data'/></query>"
            ))
        } else if rt.enabled("roster")
            && local_actor
            && target == rt.domain
            && node == commands
            && ns.ends_with("#info")
        {
            Some(format!(
                "<query xmlns='{ns}' node='{commands}'><identity category='automation' type='command-list'/><feature var='{commands}'/></query>"
            ))
        } else {
            None
        };
        return Ok(Some(ModuleResult::reply(match payload {
            Some(payload) => protocol::iq_result(iq, &payload),
            None => protocol::iq_error(iq, "item-not-found"),
        })));
    }
    let payload = match (typ, name, ns) {
        ("get", "ping", "urn:xmpp:ping") => Some(String::new()),
        ("set", "session", "urn:ietf:params:xml:ns:xmpp-session") => Some(String::new()),
        ("get", "query", "jabber:iq:version") => Some(format!(
            "<query xmlns='jabber:iq:version'><name>Rust XMPP</name><version>{}</version></query>",
            env!("CARGO_PKG_VERSION")
        )),
        ("get", "query", "http://jabber.org/protocol/disco#items") => {
            let mut x = format!("<query xmlns='{ns}'>");
            for (d, h) in &rt.config.hosts {
                if h.component.is_some() {
                    x.push_str(&format!("<item jid='{}'/>", escape(d)));
                }
            }
            x.push_str("</query>");
            Some(x)
        }
        ("get", "query", "http://jabber.org/protocol/disco#info") => {
            let mut x = format!(
                "<query xmlns='{ns}'><identity category='server' type='im' name='Rust XMPP'/>"
            );
            for feature in [
                "http://jabber.org/protocol/disco#info",
                "http://jabber.org/protocol/disco#items",
                "urn:xmpp:ping",
                "jabber:iq:version",
            ] {
                x.push_str(&format!("<feature var='{feature}'/>"));
            }
            for (module, feature) in [
                ("roster", "jabber:iq:roster"),
                ("private", "jabber:iq:private"),
                ("vcard_legacy", "vcard-temp"),
                ("mam", "urn:xmpp:mam:2"),
                ("blocklist", "urn:xmpp:blocking"),
                ("carbons", "urn:xmpp:carbons:2"),
                ("time", "urn:xmpp:time"),
                ("uptime", "jabber:iq:last"),
                ("turn_external", "urn:xmpp:extdisco:2"),
                ("register", "jabber:iq:register"),
                ("seclabels", "urn:xmpp:sec-label:0"),
                ("seclabels", "urn:xmpp:sec-label:catalog:2"),
                ("seclabels", "urn:xmpp:sec-label:catalog:0"),
            ] {
                if rt.enabled(module) {
                    x.push_str(&format!("<feature var='{feature}'/>"));
                }
            }
            if rt.enabled("roster") {
                x.push_str("<feature var='http://jabber.org/protocol/commands'/>");
            }
            x.push_str("</query>");
            Some(x)
        }
        _ => None,
    };
    Ok(payload.map(|p| ModuleResult::reply(protocol::iq_result(iq, &p))))
}
fn account_features(rt: &Runtime) -> String {
    let mut features = String::new();
    for (module, namespace) in [
        ("roster", "jabber:iq:roster"),
        ("private", "jabber:iq:private"),
        ("vcard_legacy", "vcard-temp"),
        ("mam", "urn:xmpp:mam:2"),
        ("mam", "urn:xmpp:mam:2#extended"),
        ("blocklist", "urn:xmpp:blocking"),
        ("carbons", "urn:xmpp:carbons:2"),
        ("cloud_notify", "urn:xmpp:push:0"),
        ("register", "jabber:iq:register"),
        ("seclabels", "urn:xmpp:sec-label:0"),
        ("seclabels", "urn:xmpp:sec-label:catalog:2"),
    ] {
        if rt.enabled(module) {
            features.push_str(&format!("<feature var='{namespace}'/>"));
        }
    }
    if rt.enabled("pep") && rt.enabled("bookmarks") {
        for namespace in [
            "urn:xmpp:bookmarks:1#compat",
            "urn:xmpp:bookmarks:1#compat-pep",
            "urn:xmpp:bookmarks-conversion:0",
        ] {
            features.push_str(&format!("<feature var='{namespace}'/>"));
        }
    }
    if rt.enabled("pep") && rt.enabled("vcard_legacy") {
        features.push_str("<feature var='urn:xmpp:pep-vcard-conversion:0'/>");
    }
    features
}
fn archive_policy(rt: &Runtime) -> &str {
    match rt.config.option(&rt.domain, "default_archive_policy") {
        Some(serde_json::Value::Bool(false)) => "never",
        Some(serde_json::Value::String(s)) if s == "roster" => "roster",
        Some(serde_json::Value::String(s)) if s == "never" => "never",
        _ => "always",
    }
}
fn routed(n: roxmltree::Node<'_, '_>, from: &str, to: &str) -> String {
    protocol::address(n, from, to)
}
struct ActivityReader<'a, S> {
    inner: &'a mut S,
    activity: Arc<tokio::sync::Notify>,
}
impl<S: AsyncRead + Unpin> AsyncRead for ActivityReader<'_, S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.activity.notify_one();
        }
        result
    }
}
fn configure_bound_session(
    rt: &Runtime,
    s: &SharedSession,
    client_id: Option<String>,
    csi_inactive: bool,
) {
    s.lock().unwrap().ack_limit =
        number(&rt.config, &rt.domain, "smacks_max_unacked", 100) as usize;
    s.lock().unwrap().client_id = client_id.clone();
    if rt.enabled("csi_simple") {
        let limit = number(&rt.config, &rt.domain, "csi_queue_size", 256) as usize;
        let delay = period(
            rt.config.option(&rt.domain, "csi_resume_inactive_delay"),
            Some(5.0),
        )
        .unwrap_or(5.0)
        .max(0.0);
        let payloads = rt
            .config
            .option(&rt.domain, "csi_important_payloads")
            .and_then(|v| v.as_array())
            .map(|v| {
                v.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        s.lock()
            .unwrap()
            .csi
            .configure(limit, Duration::from_secs_f64(delay), payloads);
    }
    s.lock().unwrap().csi.set_inactive(csi_inactive);
}
fn bind2_client_uuid(id: &str) -> Option<uuid::Uuid> {
    uuid::Uuid::parse_str(id)
        .ok()
        .filter(|id| id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122)
}
fn retire_bind2_client_sessions(
    rt: &Runtime,
    owner: &str,
    full: &str,
    token: &str,
    client_id: Option<&str>,
) {
    let Some(id) = client_id.and_then(bind2_client_uuid) else {
        return;
    };
    for previous in rt.hub.all() {
        let connection = {
            let mut previous = previous.lock().unwrap();
            if previous.owner != owner
                || previous.jid == full
                || previous.connection == token
                || previous.client_id.as_deref().and_then(bind2_client_uuid) != Some(id)
            {
                continue;
            }
            previous.closed = true;
            previous.sender = None;
            previous.cancel.notify_one();
            previous.connection.clone()
        };
        // The old connection's eventual Cleanup sees no sessions; the new token is excluded.
        for jid in rt.hub.disconnect(&connection, true) {
            rt.disconnected(&jid);
        }
    }
}
async fn close_retired_transport<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: Option<&SharedSession>,
    token: &str,
) -> Result<bool> {
    let reason = session.and_then(|s| {
        let state = s.lock().unwrap();
        if state.connection != token {
            Some(Some("conflict".to_owned()))
        } else if state.closed {
            Some(state.close_condition.clone())
        } else {
            None
        }
    });
    if let Some(condition) = reason {
        if let Some(condition) = condition {
            send(stream, &format!("<stream:error><{} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", escape(&condition))).await?;
        }
        send(stream, "</stream:stream>").await?;
        return Ok(true);
    }
    Ok(false)
}
async fn authenticated_transport<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    rt: Runtime,
    cb: Vec<sasl::ChannelBinding>,
    ctx: &mut ConnectionLog,
) -> Result<()> {
    let mut f = Framer::default();
    let (user, sasl2, client_id, bind2, resume, mut success) =
        match authenticate(stream, &mut f, &rt, cb, ctx).await {
            Err(e) if e.is::<PeerStreamClosed>() => return Ok(()),
            result => result?,
        };
    let owner = format!("{user}@{}", rt.domain);
    ctx.phase = "binding";
    let token = ctx.id.clone();
    let mut cleanup = Cleanup {
        runtime: rt.clone(),
        token: token.clone(),
        // A failure before success must remove even a resumable provisional session.
        graceful: true,
    };
    let (tx, mut rx) = mpsc::channel::<String>(256);
    let mut session: Option<SharedSession> = None;
    let mut jid = None::<String>;
    let mut csi_inactive = false;
    let mut replay = Vec::new();
    let mut resumed_inline = false;
    if let Some(request) = resume {
        match rt
            .hub
            .resume(&owner, &request.id, request.h, &token, tx.clone())
        {
            Ok((resumed, mut pending)) => {
                let full = resumed.lock().unwrap().jid.clone();
                // Only the SM response belongs inside SASL2 success. Pending stanzas
                // follow the completed negotiation, as in mod_sasl2_sm's finish hook.
                let response = pending.remove(0);
                success = success.replace("</success>", &format!("{response}</success>"));
                success = success.replace(
                    &format!("{}</authorization-identifier>", escape(&owner)),
                    &format!("{}</authorization-identifier>", escape(&full)),
                );
                replay = pending;
                jid = Some(full);
                session = Some(resumed);
                resumed_inline = true;
                ctx.phase = "session";
                ctx.event(Level::Info, "session-resumed", &[("mode", "sasl2-inline")]);
                // Failed writes after takeover must leave this SM session resumable.
                cleanup.graceful = false;
            }
            Err(_) => {
                success = success.replace("</success>", "<failed xmlns='urn:xmpp:sm:3'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed></success>");
            }
        }
    }
    if let Some(request) = bind2.filter(|_| !resumed_inline) {
        let current = crate::storage::load(&rt.data, &rt.domain, Some(&user), "accounts")?;
        ensure!(
            current
                .as_ref()
                .is_some_and(|a| a.get("disabled") != Some(&crate::storage::LuaValue::Bool(true))),
            "account unavailable"
        );
        let full = format!("{owner}/{}", request.resource);
        let s = rt.bind_session(&full, &token, tx.clone())?;
        let full = s.lock().unwrap().jid.clone();
        ctx.event(
            Level::Info,
            "resource-bound",
            &[("jid", &full), ("mode", "bind2")],
        );
        configure_bound_session(&rt, &s, client_id.clone(), request.inactive);
        csi_inactive = request.inactive;
        let mut bound = String::new();
        {
            let mut session = s.lock().unwrap();
            session.carbons = request.carbons;
            if request.carbons {
                bound.push_str("<enabled xmlns='urn:xmpp:carbons:2'/>");
            }
            if let Some(resume) = request.sm {
                bound.push_str(&session.enable(resume)?);
            }
        }
        if rt.enabled("mam") {
            let mut first = None;
            let mut last = None;
            crate::archive::scan_store(&rt.data, &rt.domain, Some(&user), "archive", |entry| {
                if first.is_none() {
                    first = Some((entry.id.clone(), entry.when));
                }
                last = Some((entry.id, entry.when));
                Ok(())
            })?;
            bound.push_str("<metadata xmlns='urn:xmpp:mam:2'>");
            for (element, edge) in [("start", first), ("end", last)] {
                if let Some((id, when)) = edge {
                    bound.push_str(&format!(
                        "<{element} id='{}' timestamp='{}'/>",
                        escape(&id),
                        crate::archive::timestamp(when)?
                    ));
                }
            }
            bound.push_str("</metadata>");
        }
        // Bind2 clients synchronise the archive rather than receive offline replay.
        let pending = crate::account_modules::offline_pending(&rt.data, &rt.domain, &user)?;
        let ids: Vec<_> = pending.into_iter().map(|(id, _)| id).collect();
        if !ids.is_empty() {
            crate::archive::delete_ids(&rt.data, &rt.domain, Some(&user), "offline", &ids)?;
        }
        refresh_push_session(&rt, &s)?;
        success = success.replace(
            &format!("{}</authorization-identifier>", escape(&owner)),
            &format!("{}</authorization-identifier>", escape(&full)),
        );
        success = success.replace(
            "</success>",
            &format!("<bound xmlns='{BIND2}'>{bound}</bound></success>"),
        );
        jid = Some(full);
        session = Some(s);
    }
    send(stream, &success).await?;
    ctx.event(Level::Debug, "sasl-success-sent", &[]);
    if session.is_some() {
        ctx.phase = "session";
    }
    cleanup.graceful = false;
    if let Some(full) = &jid
        && !resumed_inline
    {
        retire_bind2_client_sessions(&rt, &owner, full, &token, client_id.as_deref());
    }
    for xml in replay {
        send(stream, &xml).await?;
    }
    let mut features = if session.is_none() {
        format!("<bind xmlns='{BIND}'/>")
    } else {
        String::new()
    };
    if rt.enabled("smacks") && !session.as_ref().is_some_and(|s| s.lock().unwrap().sm) {
        features.push_str("<sm xmlns='urn:xmpp:sm:3'/>");
    }
    if rt.enabled("csi_simple") {
        features.push_str("<csi xmlns='urn:xmpp:csi:0'/>");
    }
    if rt.enabled("roster") {
        features.push_str("<ver xmlns='urn:xmpp:features:rosterver'/><sub xmlns='urn:xmpp:features:pre-approval'/>");
    }
    if sasl2 {
        send(
            stream,
            &format!("<stream:features>{features}</stream:features>"),
        )
        .await?;
    } else {
        open(stream, &mut f, &rt.domain, &features).await?;
    }
    if let Some(full) = &jid
        && !resumed_inline
        && (rt.enabled("vcard_legacy") || rt.enabled("bookmarks"))
    {
        let result = crate::account_modules::legacy_on_bind(&rt.data, &rt.domain, full)?;
        apply(stream, session.as_ref(), &rt, result).await?;
    }
    let input_activity = Arc::new(tokio::sync::Notify::new());
    loop {
        // Capture the notifier before checking ownership. A concurrent resume then
        // either fails the ownership check or leaves a permit on this old notifier.
        let cancellation = session.as_ref().map(|s| s.lock().unwrap().cancel.clone());
        if close_retired_transport(stream, session.as_ref(), &token).await? {
            cleanup.graceful = true;
            break;
        }
        let mut reader = ActivityReader {
            inner: &mut *stream,
            activity: input_activity.clone(),
        };
        let text = tokio::select! {biased; _=async{if let Some(n)=cancellation{n.notified().await}else{std::future::pending::<()>().await}}=>{close_retired_transport(stream,session.as_ref(),&token).await?;cleanup.graceful=true;break;},input=timeout(Duration::from_secs(600),f.next(&mut reader))=>input??,_=input_activity.notified()=>{if close_retired_transport(stream,session.as_ref(),&token).await?{cleanup.graceful=true;break;}csi_activity(stream,session.as_ref()).await?;continue;},output=rx.recv()=>{if let Some(xml)=output{if close_retired_transport(stream,session.as_ref(),&token).await?{cleanup.graceful=true;break;}csi_send(stream,session.as_ref(),&xml).await?;if session.as_ref().is_some_and(|s|s.lock().unwrap().request_ack()){csi_send(stream,session.as_ref(),"<r xmlns='urn:xmpp:sm:3'/>").await?;}}else{break;}continue;}};
        if close_retired_transport(stream, session.as_ref(), &token).await? {
            cleanup.graceful = true;
            break;
        }
        csi_activity(stream, session.as_ref()).await?;
        if f.is_stream_end(&text) {
            cleanup.graceful = true;
            send(stream, "</stream:stream>").await?;
            break;
        }
        let w = f.wrap(&text);
        let d = roxmltree::Document::parse(&w)?;
        let n = d
            .root_element()
            .first_element_child()
            .context("stanza missing")?;
        let ns = n.tag_name().namespace().unwrap_or("");
        let kind = n.tag_name().name();
        if ns == "urn:xmpp:sm:3" && rt.enabled("smacks") {
            if kind == "resume" && session.is_none() {
                let h = n.attribute("h").unwrap_or("").parse::<u32>();
                let id = n.attribute("previd").unwrap_or("");
                if let Ok(h) = h
                    && let Ok((resumed, replay)) = rt.hub.resume(&owner, id, h, &token, tx.clone())
                {
                    jid = Some(resumed.lock().unwrap().jid.clone());
                    for xml in replay {
                        send(stream, &xml).await?;
                    }
                    session = Some(resumed);
                    ctx.phase = "session";
                    ctx.event(Level::Info, "session-resumed", &[("mode", "sm")]);
                    continue;
                }
                send(stream,"<failed xmlns='urn:xmpp:sm:3'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>").await?;
                continue;
            }
            if let Some(s) = &session {
                let answer = {
                    let mut s = s.lock().unwrap();
                    match kind {
                        "enable" => {
                            s.enable(matches!(n.attribute("resume"), Some("true" | "1")))?
                        }
                        "r" if s.sm => format!("<a xmlns='urn:xmpp:sm:3' h='{}'/>", s.handled),
                        "a" if s.sm => {
                            s.acknowledge(n.attribute("h").context("SM h")?.parse()?)?;
                            String::new()
                        }
                        _ => bail!("invalid stream management state"),
                    }
                };
                if !answer.is_empty() {
                    send(stream, &answer).await?;
                }
                continue;
            }
            send(stream,"<failed xmlns='urn:xmpp:sm:3'><unexpected-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>").await?;
            continue;
        }
        if ns == "urn:xmpp:csi:0"
            && rt.enabled("csi_simple")
            && matches!(kind, "active" | "inactive")
        {
            csi_inactive = kind == "inactive";
            let output = session
                .as_ref()
                .map(|s| s.lock().unwrap().csi.set_inactive(csi_inactive))
                .unwrap_or_default();
            for xml in output {
                send(stream, &xml).await?;
            }
            continue;
        }
        ensure!(
            ns == CLIENT && matches!(kind, "iq" | "message" | "presence"),
            "invalid stanza"
        );
        ctx.event(Level::Debug, "stanza-received", &[("kind", kind)]);
        if let Some(s) = &session {
            let mut s = s.lock().unwrap();
            if s.sm {
                s.handled = s.handled.wrapping_add(1);
            }
        }
        if kind == "iq" {
            let typ = n.attribute("type").unwrap_or("");
            if matches!(typ, "result" | "error") {
                let full = jid.as_deref().context("binding required")?;
                if rt.enabled("pep")
                    && let Some(result) =
                        crate::pubsub::on_disco_result(&rt.data, &rt.domain, full, n)?
                {
                    apply(stream, session.as_ref(), &rt, result).await?;
                    continue;
                }
                if let Some(to) = n.attribute("to")
                    && !blocked(&rt, &user, full, to)?
                {
                    let _ = route_delivery(&rt, to, &routed(n, full, to)).await;
                }
                continue;
            }
            let q = n.first_element_child().context("IQ payload missing")?;
            let ns = q.tag_name().namespace().unwrap_or("");
            if session.is_none() && typ == "set" && ns == BIND && q.tag_name().name() == "bind" {
                let resource = q
                    .children()
                    .find(|v| v.is_element() && v.tag_name().name() == "resource")
                    .and_then(|v| v.text())
                    .map(str::to_owned)
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                let resource = stringprep::resourceprep(&resource)
                    .map_err(|_| anyhow::anyhow!("invalid resource"))?;
                ensure!(
                    !resource.is_empty() && resource.len() <= 1023,
                    "invalid resource"
                );
                let current = crate::storage::load(&rt.data, &rt.domain, Some(&user), "accounts")?;
                ensure!(
                    current.as_ref().is_some_and(
                        |a| a.get("disabled") != Some(&crate::storage::LuaValue::Bool(true))
                    ),
                    "account unavailable"
                );
                let full = format!("{owner}/{resource}");
                match rt.bind_session(&full, &token, tx.clone()) {
                    Ok(s) => {
                        let full = s.lock().unwrap().jid.clone();
                        ctx.phase = "session";
                        ctx.event(
                            Level::Info,
                            "resource-bound",
                            &[("jid", &full), ("mode", "legacy")],
                        );
                        emit(
                            stream,
                            None,
                            &protocol::iq_result(
                                n,
                                &format!(
                                    "<bind xmlns='{BIND}'><jid>{}</jid></bind>",
                                    escape(&full)
                                ),
                            ),
                        )
                        .await?;
                        configure_bound_session(&rt, &s, client_id.clone(), csi_inactive);
                        refresh_push_session(&rt, &s)?;
                        jid = Some(full);
                        session = Some(s);
                        if rt.enabled("vcard_legacy") || rt.enabled("bookmarks") {
                            let result = crate::account_modules::legacy_on_bind(
                                &rt.data,
                                &rt.domain,
                                jid.as_deref().unwrap(),
                            )?;
                            apply(stream, session.as_ref(), &rt, result).await?;
                        }
                    }
                    Err(_) => {
                        ctx.event(
                            Level::Warn,
                            "bind-rejected",
                            &[("reason", "resource-conflict"), ("jid", &full)],
                        );
                        emit(stream, None, &protocol::iq_error(n, "conflict")).await?;
                    }
                }
                continue;
            }
            let full = jid.as_deref().context("binding required")?;
            if let Some(to) = n.attribute("to") {
                if blocked(&rt, &user, full, to)? {
                    emit(
                        stream,
                        session.as_ref(),
                        &protocol::iq_error(n, "service-unavailable"),
                    )
                    .await?;
                    continue;
                }
                if to.contains('/') && to != full {
                    if rt.hub.get(to).is_some() {
                        rt.hub.deliver(to, &routed(n, full, to));
                        continue;
                    } else if rt.owner(to).is_some() {
                        emit(
                            stream,
                            session.as_ref(),
                            &protocol::iq_error(n, "recipient-unavailable"),
                        )
                        .await?;
                        continue;
                    }
                }
            }
            if ns == "urn:xmpp:carbons:2"
                && rt.enabled("carbons")
                && typ == "set"
                && matches!(q.tag_name().name(), "enable" | "disable")
            {
                session.as_ref().unwrap().lock().unwrap().carbons = q.tag_name().name() == "enable";
                emit(stream, session.as_ref(), &protocol::iq_result(n, "")).await?;
                continue;
            }
            if ns == "jabber:iq:roster" && typ == "get" {
                session.as_ref().unwrap().lock().unwrap().roster_interested = true;
            }
            if n.attribute("to")
                .and_then(|to| protocol::bare(to).rsplit_once('@').map(|(_, d)| d))
                .is_some_and(|d| d != rt.domain && !rt.config.hosts.contains_key(d))
            {
                let to = n.attribute("to").unwrap();
                if route_delivery(&rt, to, &routed(n, full, to)).await.is_err() {
                    emit(
                        stream,
                        session.as_ref(),
                        &protocol::iq_error(n, "remote-server-not-found"),
                    )
                    .await?;
                }
                continue;
            }
            let result = match dispatch_iq(&rt, full, n) {
                Ok(Some(r)) => r,
                Ok(None) => ModuleResult::reply(protocol::iq_error(n, "service-unavailable")),
                Err(error) => {
                    let io_kind = error
                        .downcast_ref::<std::io::Error>()
                        .map(|e| format!("{:?}", e.kind()))
                        .unwrap_or_else(|| "none".into());
                    ctx.event(Level::Warn, "iq-dispatch-failed", &[("io_kind", &io_kind)]);
                    ModuleResult::reply(protocol::iq_error(n, "internal-server-error"))
                }
            };
            if let Some(fields) = pep_iq_metadata(n, &result, &rt.domain, full) {
                let values: Vec<_> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
                ctx.event(Level::Info, "pubsub-iq-result", &values);
            }
            apply(stream, session.as_ref(), &rt, result).await?;
        } else {
            let full = jid.as_deref().context("binding required")?;
            let muc_result = {
                let mut rooms = rt.mucs.lock().unwrap();
                let mut found = None;
                for muc in rooms.values_mut() {
                    if let Some(result) = muc.handle(full, n)? {
                        found = Some(result);
                        break;
                    }
                }
                found
            };
            if let Some(result) = muc_result {
                apply(stream, session.as_ref(), &rt, result).await?;
                continue;
            }
            if kind == "presence" {
                if rt.enabled("roster")
                    && let Some(result) =
                        crate::account_modules::subscription(&rt.data, &rt.domain, full, n)?
                {
                    apply(stream, session.as_ref(), &rt, result).await?;
                    continue;
                }
                if n.attribute("to").is_none() {
                    let avatar_xml = if rt.enabled("vcard_legacy") {
                        crate::account_modules::avatar_presence(&rt.data, &rt.domain, full, n)?
                    } else {
                        protocol::xml(n)
                    };
                    let available = n.attribute("type").is_none();
                    let priority = n
                        .children()
                        .find(|v| v.is_element() && v.tag_name().name() == "priority")
                        .and_then(|v| v.text())
                        .and_then(|v| v.parse::<i8>().ok())
                        .unwrap_or(0);
                    {
                        let mut s = session.as_ref().unwrap().lock().unwrap();
                        s.available = available;
                        s.priority = priority;
                        s.presence = available.then(|| avatar_xml.clone());
                    }
                    if available {
                        let recovered = {
                            let mut mucs = rt.mucs.lock().unwrap();
                            mucs.values_mut()
                                .map(|muc| muc.restore_for_session(full))
                                .collect::<Result<Vec<_>>>()?
                        };
                        for result in recovered {
                            if !result.replies.is_empty() {
                                ctx.event(Level::Info, "muc-membership-restored", &[("jid", full)]);
                            }
                            apply(stream, session.as_ref(), &rt, result).await?;
                        }
                    }
                    if rt.enabled("roster") {
                        for contact in
                            crate::account_modules::subscribers(&rt.data, &rt.domain, &user)?
                        {
                            let d = roxmltree::Document::parse(&avatar_xml)?;
                            let _ = route_delivery(
                                &rt,
                                &contact,
                                &routed(d.root_element(), full, &contact),
                            )
                            .await;
                        }
                        if available {
                            for contact in
                                crate::account_modules::subscriptions(&rt.data, &rt.domain, &user)?
                            {
                                for s in rt.hub.all() {
                                    let snapshot = {
                                        let s = s.lock().unwrap();
                                        (s.owner == contact && s.available)
                                            .then(|| (s.jid.clone(), s.presence.clone()))
                                            .and_then(|(j, p)| p.map(|p| (j, p)))
                                    };
                                    if let Some((sender, p)) = snapshot {
                                        let w = wrap(&p);
                                        let d = roxmltree::Document::parse(&w)?;
                                        if let Some(n) = d.root_element().first_element_child() {
                                            rt.hub.deliver(full, &routed(n, &sender, full));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if rt.enabled("pep") {
                        let result = crate::pubsub::on_presence(&rt.data, &rt.domain, full, n)?;
                        apply(stream, session.as_ref(), &rt, result).await?;
                    }
                    if available {
                        for request in crate::account_modules::pending_subscriptions(
                            &rt.data, &rt.domain, &user,
                        )? {
                            emit(stream, session.as_ref(), &request).await?;
                        }
                    }
                    if available && priority >= 0 {
                        let pending =
                            crate::account_modules::offline_pending(&rt.data, &rt.domain, &user)?;
                        let mut delivered = vec![];
                        for (id, xml) in pending {
                            emit(stream, session.as_ref(), &xml).await?;
                            delivered.push(id);
                        }
                        if !delivered.is_empty() {
                            crate::archive::delete_ids(
                                &rt.data,
                                &rt.domain,
                                Some(&user),
                                "offline",
                                &delivered,
                            )?;
                        }
                    }
                    continue;
                }
            }
            let Some(to) = n.attribute("to") else {
                continue;
            };
            let local = rt.owner(to);
            if crate::account_modules::is_blocked(&rt.data, &rt.domain, &user, to)? {
                continue;
            }
            if let Some(target_user) = &local
                && crate::account_modules::is_blocked(&rt.data, &rt.domain, target_user, full)?
            {
                continue;
            }
            let mut xml = routed(n, full, to);
            let mut sent_xml = xml.clone();
            if kind == "presence" {
                let _ = route_delivery(&rt, to, &xml).await;
                continue;
            }
            let remote = local.is_none()
                && !rt.config.hosts.contains_key(
                    protocol::bare(to)
                        .rsplit_once('@')
                        .map(|(_, d)| d)
                        .unwrap_or(to),
                );
            let typ = n.attribute("type").unwrap_or("normal");
            if rt.enabled("mam") {
                xml = crate::mam::strip_owner_stanza_ids(&xml, &rt.domain, &user)?;
                let now = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
                if crate::mam::should_store(n)
                    && crate::mam::should_archive_with_options(
                        &rt.data,
                        &rt.domain,
                        &user,
                        protocol::bare(to),
                        archive_policy(&rt),
                        boolean(&rt.config, &rt.domain, "mam_smart_enable", false),
                    )?
                {
                    let (_, stamped) = crate::mam::archive_for_user(
                        &rt.data,
                        &rt.domain,
                        &user,
                        protocol::bare(to),
                        &xml,
                        now,
                    )?;
                    sent_xml = stamped;
                } else {
                    sent_xml = xml.clone();
                }
                if let Some(u) = &local {
                    xml = crate::mam::strip_owner_stanza_ids(&xml, &rt.domain, u)?;
                    if u == &user {
                        xml = sent_xml.clone();
                    } else if crate::storage::load(&rt.data, &rt.domain, Some(u), "accounts")?
                        .is_some()
                        && crate::mam::should_store(n)
                        && crate::mam::should_archive_with_options(
                            &rt.data,
                            &rt.domain,
                            u,
                            &owner,
                            archive_policy(&rt),
                            boolean(&rt.config, &rt.domain, "mam_smart_enable", false),
                        )?
                    {
                        let (_, stamped) = crate::mam::archive_for_user(
                            &rt.data, &rt.domain, u, &owner, &xml, now,
                        )?;
                        xml = stamped;
                    }
                }
            }
            let remote_delivered = remote && route_delivery(&rt, to, &xml).await.is_ok();
            let targets = if local.is_some() {
                rt.hub.message_targets_for_type(to, typ)
            } else {
                vec![]
            };
            let mut delivered = usize::from(remote_delivered);
            let mut target_jids = vec![];
            for target in targets {
                let mut target = target.lock().unwrap();
                if target.transmit(xml.clone()).is_ok() {
                    delivered += 1;
                    target_jids.push(target.jid.clone());
                }
            }
            if rt.enabled("carbons")
                && matches!(typ, "chat" | "normal")
                && !n.children().any(|n| {
                    n.tag_name().namespace() == Some("urn:xmpp:carbons:2")
                        && n.tag_name().name() == "private"
                })
            {
                for s in rt.hub.all() {
                    let mut s = s.lock().unwrap();
                    if !s.carbons || s.jid == full || target_jids.contains(&s.jid) {
                        continue;
                    }
                    let direction = if s.owner == owner {
                        Some("sent")
                    } else if s.owner == protocol::bare(to) && delivered > 0 {
                        Some("received")
                    } else {
                        None
                    };
                    if let Some(direction) = direction {
                        let carbon_xml = if direction == "sent" { &sent_xml } else { &xml };
                        let carbon = format!(
                            "<message xmlns='{CLIENT}' from='{}' to='{}'><{direction} xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'>{carbon_xml}</forwarded></{direction}></message>",
                            escape(&s.owner),
                            escape(&s.jid)
                        );
                        let _ = s.transmit(carbon);
                    }
                }
            }
            if rt.enabled("cloud_notify")
                && typ != "error"
                && let Some(u) = &local
            {
                let doc = roxmltree::Document::parse(&xml)?;
                let pushes = message_pushes(&rt, u, to, delivered, doc.root_element())?;
                for (to, payload) in pushes {
                    let _ = route_delivery(&rt, &to, &payload).await;
                }
            }

            if delivered == 0 && !matches!(typ, "error" | "headline") {
                let queued = if let Some(u) = local {
                    crate::account_modules::offline_enqueue(&rt.data, &rt.domain, &u, &xml)?
                } else {
                    false
                };
                if !queued {
                    emit(stream,session.as_ref(),&format!("<message xmlns='{CLIENT}' type='error' id='{}' from='{}' to='{}'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",escape(n.attribute("id").unwrap_or("")),escape(to),escape(full))).await?;
                }
            }
        }
    }
    Ok(())
}
fn period(value: Option<&serde_json::Value>, default: Option<f64>) -> Option<f64> {
    match value {
        Some(serde_json::Value::Number(n)) => n.as_f64(),
        Some(serde_json::Value::String(s)) => {
            if s == "never" {
                return None;
            }
            for (unit, scale) in [
                ("s", 1.0),
                ("m", 60.0),
                ("h", 3600.0),
                ("d", 86400.0),
                ("w", 604800.0),
            ] {
                if let Some(n) = s
                    .strip_suffix(unit)
                    .and_then(|n| n.trim().parse::<f64>().ok())
                {
                    return Some(n * scale);
                }
            }
            default
        }
        _ => default,
    }
}
async fn route_delivery(rt: &Runtime, to: &str, xml: &str) -> Result<usize> {
    let domain = protocol::bare(to)
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(protocol::bare(to));
    if rt.config.hosts.contains_key(domain) {
        return Ok(rt.hub.deliver(to, xml));
    }
    let fed = rt.federation.as_ref().context("federation disabled")?;
    let d = roxmltree::Document::parse(xml)?;
    let from = d
        .root_element()
        .attribute("from")
        .context("federation requires from")?;
    let from_domain = protocol::bare(from)
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(from);
    fed.route(from_domain, to, xml).await?;
    Ok(1)
}
async fn incoming_federated(rt: Runtime, stanza: crate::federation::FederatedStanza) -> Result<()> {
    let d = roxmltree::Document::parse(&stanza.xml)?;
    let xml = protocol::xml_namespace(d.root_element(), Some(("jabber:server", CLIENT)));
    let d = roxmltree::Document::parse(&xml)?;
    let n = d.root_element();
    let from = n.attribute("from").context("federated source")?;
    let to = n.attribute("to").context("federated target")?;
    let from_domain = protocol::bare(from)
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(from);
    ensure!(from_domain == stanza.from_domain, "unverified source");
    let dest_domain = protocol::bare(to)
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(to);
    ensure!(
        rt.config.hosts.contains_key(dest_domain),
        "not a local destination"
    );
    if let Some(user) = rt.owner(to)
        && crate::account_modules::is_blocked(&rt.data, &rt.domain, &user, from)?
    {
        return Ok(());
    }
    if n.tag_name().name() == "iq" && matches!(n.attribute("type"), Some("result" | "error")) {
        if rt.enabled("pep")
            && let Some(result) = crate::pubsub::on_disco_result(&rt.data, &rt.domain, from, n)?
        {
            for (to, xml) in result.deliveries {
                route_delivery(&rt, &to, &xml).await?;
            }
            return Ok(());
        }
        if rt.enabled("cloud_notify") {
            let consumed = rt.push.lock().unwrap().result(
                &rt.data,
                &rt.domain,
                n,
                number(&rt.config, &rt.domain, "push_max_errors", 16),
            )?;
            remove_push_sessions(&rt);
            if consumed {
                return Ok(());
            }
        }
        rt.hub.deliver(to, &xml);
        return Ok(());
    }
    if n.tag_name().name() == "iq" {
        if rt.hub.get(to).is_some() {
            rt.hub.deliver(to, &xml);
            return Ok(());
        }
        let q = n.first_element_child().context("IQ payload")?;
        if matches!(
            q.tag_name().namespace(),
            Some(
                "urn:xmpp:extdisco:1"
                    | "urn:xmpp:extdisco:2"
                    | "jabber:iq:register"
                    | "urn:xmpp:push:0"
            )
        ) {
            let error = protocol::iq_error(n, "forbidden");
            let d = roxmltree::Document::parse(&error)?;
            let reply = routed(d.root_element(), to, from);
            route_delivery(&rt, from, &reply).await?;
            return Ok(());
        }
        let result = dispatch_iq(&rt, from, n)?
            .unwrap_or_else(|| ModuleResult::reply(protocol::iq_error(n, "service-unavailable")));
        for reply in result.replies {
            let d = roxmltree::Document::parse(&reply)?;
            route_delivery(&rt, from, &routed(d.root_element(), to, from)).await?;
        }
        for (to, xml) in result.deliveries {
            route_delivery(&rt, &to, &xml).await?;
        }
        return Ok(());
    }
    let muc_result = {
        let mut rooms = rt.mucs.lock().unwrap();
        let mut out = None;
        for room in rooms.values_mut() {
            if let Some(result) = room.handle(from, n)? {
                out = Some(result);
                break;
            }
        }
        out
    };
    if let Some(result) = muc_result {
        for reply in result.replies {
            let d = roxmltree::Document::parse(&reply)?;
            let addressed = routed(d.root_element(), to, from);
            route_delivery(&rt, from, &addressed).await?;
        }
        for (to, xml) in result.deliveries {
            route_delivery(&rt, &to, &xml).await?;
        }
        return Ok(());
    }
    if n.tag_name().name() == "presence" {
        if let Some(result) =
            crate::account_modules::inbound_subscription(&rt.data, &rt.domain, from, n)?
        {
            for (to, xml) in result.deliveries {
                route_delivery(&rt, &to, &xml).await?;
            }
            return Ok(());
        }
        if rt.enabled("pep") {
            let result = crate::pubsub::on_remote_presence(&rt.data, &rt.domain, from, n)?;
            for (to, xml) in result.deliveries {
                route_delivery(&rt, &to, &xml).await?;
            }
        }
        rt.hub.deliver(to, &xml);
        return Ok(());
    }
    if n.tag_name().name() == "message" {
        let Some(user) = rt.owner(to) else {
            return Ok(());
        };
        let typ = n.attribute("type").unwrap_or("normal");
        let mut delivery_xml = xml.clone();
        if rt.enabled("mam") {
            delivery_xml = crate::mam::strip_owner_stanza_ids(&delivery_xml, &rt.domain, &user)?;
        }
        if rt.enabled("mam")
            && crate::mam::should_store(n)
            && crate::mam::should_archive_with_options(
                &rt.data,
                &rt.domain,
                &user,
                protocol::bare(from),
                archive_policy(&rt),
                boolean(&rt.config, &rt.domain, "mam_smart_enable", false),
            )?
        {
            delivery_xml = crate::mam::archive_for_user(
                &rt.data,
                &rt.domain,
                &user,
                protocol::bare(from),
                &delivery_xml,
                chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
            )?
            .1;
        }
        let targets = rt.hub.message_targets_for_type(to, typ);
        let mut delivered = 0;
        for s in targets {
            if s.lock().unwrap().transmit(delivery_xml.clone()).is_ok() {
                delivered += 1;
            }
        }
        if delivered == 0 && typ != "error" {
            crate::account_modules::offline_enqueue(&rt.data, &rt.domain, &user, &delivery_xml)?;
        }
        let notifications = message_pushes(&rt, &user, to, delivered, n)?;
        for (to, xml) in notifications {
            let _ = route_delivery(&rt, &to, &xml).await;
        }
    }
    Ok(())
}
fn blocked(rt: &Runtime, user: &str, from: &str, to: &str) -> Result<bool> {
    if crate::account_modules::is_blocked(&rt.data, &rt.domain, user, to)? {
        return Ok(true);
    }
    if let Some(u) = rt.owner(to)
        && crate::account_modules::is_blocked(&rt.data, &rt.domain, &u, from)?
    {
        return Ok(true);
    }
    Ok(false)
}
pub fn admin_path(c: &Config, domain: &str, data: &Path) -> PathBuf {
    let value = c
        .option(domain, "admin_socket")
        .and_then(|v| v.as_str())
        .unwrap_or("prosody.sock");
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        data.join(path)
    }
}
fn maintenance_run(rt: &Runtime) -> Result<()> {
    for upload in rt.uploads.values() {
        upload.prune()?;
    }
    let now = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
    for muc in rt.mucs.lock().unwrap().values_mut() {
        muc.maintenance(now)?;
    }
    for (host, h) in &rt.config.hosts {
        let (store, retention) = if h.component.is_none() {
            (
                "archive",
                period(
                    rt.config.option(host, "archive_expires_after"),
                    Some(604800.0),
                ),
            )
        } else {
            continue;
        };
        let Some(age) = retention else { continue };
        let dir = rt.data.join(crate::storage::encode_name(host)).join(store);
        if !dir.exists() {
            continue;
        }
        for entry in fs::read_dir(dir)? {
            let e = entry?;
            if !e.file_type()?.is_file()
                || e.path().extension().and_then(|s| s.to_str()) != Some("list")
            {
                continue;
            }
            let Some(encoded) = e
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_owned)
            else {
                continue;
            };
            let mut bytes = vec![];
            let mut i = 0;
            while i < encoded.len() {
                if encoded.as_bytes()[i] == b'%' && i + 2 < encoded.len() {
                    bytes.push(u8::from_str_radix(&encoded[i + 1..i + 3], 16)?);
                    i += 3;
                } else {
                    bytes.push(encoded.as_bytes()[i]);
                    i += 1;
                }
            }
            let user = String::from_utf8(bytes)?;
            crate::archive::expire_before(&rt.data, host, Some(&user), store, now - age)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod authorization_tests {
    use super::*;
    #[test]
    fn http_interfaces_follow_secure_override_wildcards_and_global_fallback() {
        let config: Config = serde_json::from_value(serde_json::json!({"global":{"interfaces":["127.0.0.1"],"https_interfaces":["*","0.0.0.0"],"http_interfaces":["::1"]},"hosts":{"example.test":{"options":{}}}})).unwrap();
        assert_eq!(
            http_interfaces(&config, "example.test", true).unwrap(),
            vec![
                "0.0.0.0".parse::<std::net::IpAddr>().unwrap(),
                "::".parse().unwrap()
            ]
        );
        assert_eq!(
            http_interfaces(&config, "example.test", false).unwrap(),
            vec!["::1".parse::<std::net::IpAddr>().unwrap()]
        );
        let config: Config = serde_json::from_value(serde_json::json!({"global":{"interfaces":["127.0.0.1"]},"hosts":{"example.test":{"options":{}}}})).unwrap();
        assert_eq!(
            http_interfaces(&config, "example.test", true).unwrap(),
            vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
    }
    #[test]
    fn pep_diagnostics_exclude_payloads_and_identifiers() {
        let request = roxmltree::Document::parse("<iq id='PRIVATE-IQ' type='set'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.bundles:PRIVATE-DEVICE'><item id='PRIVATE-ITEM'><data>PRIVATE-KEY</data></item></publish></pubsub></iq>").unwrap();
        let result = ModuleResult::reply(protocol::iq_error(request.root_element(), "forbidden"));
        let fields = pep_iq_metadata(
            request.root_element(),
            &result,
            "example.test",
            "alice@example.test/phone",
        )
        .unwrap();
        assert!(fields.contains(&("node_kind", "omemo-bundle".into())));
        assert!(fields.contains(&("status", "error".into())));
        assert!(fields.contains(&("condition", "forbidden".into())));
        assert!(!format!("{fields:?}").contains("PRIVATE"));
        let query = roxmltree::Document::parse(
            "<iq><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
        )
        .unwrap();
        let reply = ModuleResult::reply("<iq xmlns='jabber:client' type='result'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='pubsub' type='pep'/><feature var='http://jabber.org/protocol/pubsub#persistent-items'/></query></iq>".into());
        let fields = pep_iq_metadata(
            query.root_element(),
            &reply,
            "example.test",
            "alice@example.test/phone",
        )
        .unwrap();
        assert!(fields.contains(&("pep_identity", "true".into())));
        assert!(fields.contains(&("persistent_items", "true".into())));
        assert!(fields.contains(&("publish_options", "false".into())));
    }
    #[test]
    fn pep_diagnostics_count_only_first_item_devices_without_logging_ids() {
        let query = roxmltree::Document::parse("<iq to='alice@example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist'/></pubsub></iq>").unwrap();
        let reply = ModuleResult::reply("<iq type='result' xmlns='jabber:client'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items><item id='PRIVATE-ITEM'><list xmlns='eu.siacs.conversations.axolotl'><device id='PRIVATE-DEVICE'/></list></item><item><list xmlns='eu.siacs.conversations.axolotl'/></item></items></pubsub></iq>".into());
        let fields = pep_iq_metadata(
            query.root_element(),
            &reply,
            "example.test",
            "alice@example.test/phone",
        )
        .unwrap();
        assert!(fields.contains(&("items_count", "2".into())));
        assert!(fields.contains(&("first_content_kind", "omemo-devices".into())));
        assert!(fields.contains(&("first_device_count", "1".into())));
        assert!(fields.contains(&("target_scope", "self-account".into())));
        assert!(!format!("{fields:?}").contains("PRIVATE"));
    }
    #[test]
    fn upload_requires_registered_local_account_or_explicit_remote_access() {
        let root = tempfile::tempdir().unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({"global":{},"hosts":{"local.test":{"options":{}},"upload.local.test":{"component":"http_file_share","options":{"http_file_share_access":["trusted.test","friend@remote.test"]}}}})).unwrap();
        auth::create(root.path(), "local.test", "alice", "secret", "SHA-256").unwrap();
        let allowed = |jid| {
            upload_allowed(root.path(), &config, "local.test", "upload.local.test", jid).unwrap()
        };
        assert!(allowed("alice@local.test/mobile"));
        assert!(!allowed("unknown@local.test/mobile"));
        assert!(!allowed("alice@evil.test/mobile"));
        assert!(allowed("user@trusted.test/mobile"));
        assert!(allowed("friend@remote.test/mobile"));
        assert!(!allowed("stranger@remote.test/mobile"));
    }
}
