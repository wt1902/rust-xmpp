//! Streaming XEP-0363 upload endpoint. Slots are single-use and bounded before streaming.
use crate::{
    logging::{Level, Logger},
    object_store::{ObjectStore, PART_SIZE, UploadBackendConfig},
    storage,
    wire::escape,
};
use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    response::Response,
    routing::any,
};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncSeekExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
const NS: &str = "urn:xmpp:http:upload:0";
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
#[derive(Clone, Debug)]
pub struct UploadConfig {
    pub root: PathBuf,
    pub host: String,
    pub base_url: String,
    pub size_limit: u64,
    pub daily_quota: u64,
    pub global_quota: u64,
    pub expires_after: Option<u64>,
    pub allowed_types: Vec<String>,
    pub secret: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    owner: String,
    filename: String,
    size: u64,
    content_type: String,
    created: u64,
    token: String,
    complete: bool,
    #[serde(default)]
    upload_id: Option<String>,
    // Durable before CreateMultipartUpload: UploadId may be lost in a crash.
    #[serde(default)]
    multipart_intent: bool,
    #[serde(default)]
    completion_attempted: bool,
    #[serde(default)]
    xml: Option<String>,
}
#[derive(Debug)]
struct CompletionUncertain;
impl std::fmt::Display for CompletionUncertain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S3 completion outcome uncertain; reservation quarantined for reconciliation")
    }
}
impl std::error::Error for CompletionUncertain {}
#[derive(Clone)]
pub struct UploadService {
    config: Arc<UploadConfig>,
    records: Arc<Mutex<BTreeMap<String, Record>>>,
    active: Arc<Mutex<BTreeSet<String>>>,
    backend: Option<Arc<ObjectStore>>,
}
pub struct Slot {
    pub url: String,
    pub authorization: String,
}
impl Slot {
    pub fn xml(&self) -> String {
        format!(
            "<slot xmlns='{NS}'><get url='{}'/><put url='{}'><header name='Authorization'>{}</header></put></slot>",
            escape(&self.url),
            escape(&self.url),
            escape(&self.authorization)
        )
    }
}
fn url_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char)
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
fn url_decode(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let h = (bytes.next()? as char).to_digit(16)?;
            let l = (bytes.next()? as char).to_digit(16)?;
            out.push((h * 16 + l) as u8);
        } else {
            out.push(byte);
        }
    }
    Some(out)
}
impl UploadService {
    pub fn new(config: UploadConfig) -> Result<Self> {
        Self::new_with_backend(config, UploadBackendConfig::Local)
    }
    pub fn new_with_backend(config: UploadConfig, backend: UploadBackendConfig) -> Result<Self> {
        let backend = match backend {
            UploadBackendConfig::Local => None,
            UploadBackendConfig::S3(c) => Some(Arc::new(ObjectStore::new(c)?)),
        };
        ensure!(
            config.base_url.starts_with("https://") || config.base_url.starts_with("http://"),
            "invalid upload base URL"
        );
        let path = config
            .root
            .join(storage::encode_name(&config.host))
            .join("rust_uploads.json");
        let mut records: BTreeMap<String, Record> = if path.exists() {
            serde_json::from_slice(&std::fs::read(path)?)?
        } else {
            BTreeMap::new()
        };
        let entries = crate::archive::load_store(&config.root, &config.host, None, "uploads")?;
        let mut authoritative = BTreeMap::new();
        for e in entries {
            let doc = roxmltree::Document::parse(&e.xml)?;
            let node = doc.root_element();
            let filename = node
                .attribute("filename")
                .ok_or_else(|| anyhow::anyhow!("upload filename missing"))?
                .to_string();
            let size = node
                .attribute("size")
                .ok_or_else(|| anyhow::anyhow!("upload size missing"))?
                .parse()?;
            let cached = records.remove(&e.id);
            let complete = cached.as_ref().is_some_and(|r| {
                r.complete && r.owner == e.peer && r.filename == filename && r.size == size
            });
            let upload_id = cached
                .as_ref()
                .filter(|r| r.owner == e.peer && r.filename == filename && r.size == size)
                .and_then(|r| r.upload_id.clone());
            let multipart_intent = cached.as_ref().is_some_and(|r| {
                r.owner == e.peer && r.filename == filename && r.size == size && r.multipart_intent
            });
            let completion_attempted = cached.as_ref().is_some_and(|r| {
                r.owner == e.peer
                    && r.filename == filename
                    && r.size == size
                    && r.completion_attempted
            });
            let token = cached.map(|r| r.token).unwrap_or_default();
            authoritative.insert(
                e.id,
                Record {
                    owner: e.peer,
                    filename,
                    size,
                    content_type: node
                        .attribute("content-type")
                        .unwrap_or("application/octet-stream")
                        .into(),
                    created: e.when as u64,
                    token,
                    complete,
                    upload_id,
                    multipart_intent,
                    completion_attempted,
                    xml: Some(e.xml),
                },
            );
        }
        records = authoritative;
        let identity = backend
            .as_ref()
            .map(|b| b.identity())
            .unwrap_or_else(|| serde_json::json!({"backend":"local"}));
        let identity_path = config
            .root
            .join(storage::encode_name(&config.host))
            .join("rust_upload_backend.json");
        if identity_path.exists() {
            let previous: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&identity_path)?)?;
            ensure!(
                records.is_empty() || previous == identity,
                "upload backend changed while slots still exist"
            );
        } else {
            ensure!(
                backend.is_none() || records.is_empty(),
                "existing upload slots require an explicit storage migration"
            );
        }
        storage::atomic_write(&identity_path, &serde_json::to_vec(&identity)?)?;
        let s = Self {
            config: Arc::new(config),
            records: Arc::new(Mutex::new(records)),
            active: Arc::new(Mutex::new(BTreeSet::new())),
            backend,
        };
        // Remote pending records must be reconciled before the abandoned-slot
        // timeout is applied. The caller awaits recover_backend before listening.
        if s.backend.is_none() {
            s.prune()?;
        }
        Ok(s)
    }
    /// Recover durable multipart state before enabling listeners or slot requests.
    pub async fn recover_backend(&self) -> Result<()> {
        if self.backend.is_none() {
            return Ok(());
        }
        let pending: Vec<_> = self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, r)| {
                !r.complete || r.upload_id.is_some() || r.multipart_intent || r.completion_attempted
            })
            .map(|(id, r)| (id.clone(), r.clone()))
            .collect();
        for (id, record) in pending {
            if let Err(error) = self.reconcile_record(id, record).await
                && error.downcast_ref::<CompletionUncertain>().is_none()
            {
                return Err(error);
            }
        }
        let service = self.clone();
        tokio::task::spawn_blocking(move || service.prune()).await??;
        Ok(())
    }
    async fn reconcile_record(&self, id: String, record: Record) -> Result<()> {
        let Some(backend) = &self.backend else {
            return Ok(());
        };
        if !record.complete || record.multipart_intent {
            // Also cover old journals from before multipart_intent existed.
            // This exact durable reservation is exclusively claimed by the
            // startup barrier or the active-set lock. Never sweep a bucket.
            backend.abort_pending(&id).await?;
        }
        if let Some(upload_id) = &record.upload_id {
            backend.abort(&id, upload_id).await?;
        }
        // Completion may have committed while abort was in flight. Only the
        // post-abort HEAD can establish the current single-use object state.
        let head = backend.read(&id, true, None).await?;
        let complete = match head.status() {
            StatusCode::OK => {
                ensure!(
                    head.headers()
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        == Some(record.size),
                    "S3 recovered object size mismatch"
                );
                true
            }
            StatusCode::NOT_FOUND => false,
            _ => anyhow::bail!("S3 recovery HEAD failed"),
        };
        if !complete && record.completion_attempted {
            return Err(CompletionUncertain.into());
        }
        let service = self.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut records = service.records.lock().unwrap();
            if let Some(r) = records.get_mut(&id)
                && r.upload_id == record.upload_id
                && r.multipart_intent == record.multipart_intent
            {
                r.complete = complete;
                r.upload_id = None;
                r.multipart_intent = false;
                r.completion_attempted = false;
            }
            service.persist(&records)
        })
        .await??;
        Ok(())
    }
    /// Read-only identifiers for unresolved completion attempts. Credentials,
    /// bearer tokens and object contents are never included.
    pub fn quarantined_slots(&self) -> Vec<String> {
        let records = self.records.lock().unwrap();
        let active = self.active.lock().unwrap();
        records
            .iter()
            .filter(|(id, r)| r.completion_attempted && !r.complete && !active.contains(*id))
            .map(|(id, _)| id.clone())
            .collect()
    }
    fn claim_upload(&self, id: &str) -> std::result::Result<Record, StatusCode> {
        // Match prune's lock order, and read all mutable completion state under
        // the same records lock used to establish the active claim.
        let records = self.records.lock().unwrap();
        let record = records.get(id).ok_or(StatusCode::GONE)?;
        if record.complete || (self.backend.is_none() && self.file(id).exists()) {
            return Err(StatusCode::CONFLICT);
        }
        if !self.active.lock().unwrap().insert(id.to_owned()) {
            return Err(StatusCode::CONFLICT);
        }
        Ok(record.clone())
    }
    fn persist(&self, r: &BTreeMap<String, Record>) -> Result<()> {
        let mut entries: Vec<_> = r
            .iter()
            .map(|(id, v)| crate::archive::Entry {
                id: id.clone(),
                when: v.created as f64,
                peer: v.owner.clone(),
                xml: v.xml.clone().unwrap_or_else(|| {
                    format!(
                        "<request xmlns='{NS}' filename='{}' size='{}' content-type='{}'/>",
                        escape(&v.filename),
                        v.size,
                        escape(&v.content_type)
                    )
                }),
            })
            .collect();
        entries.sort_by(|a, b| a.when.total_cmp(&b.when).then_with(|| a.id.cmp(&b.id)));
        crate::archive::save_store(
            &self.config.root,
            &self.config.host,
            None,
            "uploads",
            &entries,
        )?;
        let total: u64 = r
            .values()
            .fold(0u64, |total, r| total.saturating_add(r.size));
        storage::update(
            &self.config.root,
            &self.config.host,
            None,
            "upload_stats",
            |v| {
                v.set("total", storage::LuaValue::Number(total as f64));
                Ok(())
            },
        )?;
        storage::atomic_write(
            &self
                .config
                .root
                .join(storage::encode_name(&self.config.host))
                .join("rust_uploads.json"),
            &serde_json::to_vec(r)?,
        )
    }
    fn file(&self, id: &str) -> PathBuf {
        self.config
            .root
            .join(storage::encode_name(&self.config.host))
            .join("http_file_share")
            .join(format!("{}.bin", storage::encode_name(id)))
    }
    pub fn prune(&self) -> Result<()> {
        let mut r = self.records.lock().unwrap();
        let mut active = self.active.lock().unwrap();
        if self.backend.is_some()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            for (id, record) in r
                .iter()
                .filter(|(id, r)| {
                    (r.upload_id.is_some() || r.multipart_intent || r.completion_attempted)
                        && !active.contains(*id)
                })
                .map(|(id, r)| (id.clone(), r.clone()))
                .collect::<Vec<_>>()
            {
                active.insert(id.clone());
                let service = self.clone();
                handle.spawn(async move {
                    let recovered = service.reconcile_record(id.clone(), record).await.is_ok();
                    tokio::task::spawn_blocking(move || {
                        service.active.lock().unwrap().remove(&id);
                        if recovered {
                            let _ = service.prune();
                        }
                    })
                    .await
                    .ok();
                });
            }
        }
        let obsolete: Vec<String> = r
            .iter()
            .filter(|(id, v)| {
                !active.contains(*id)
                    && v.upload_id.is_none()
                    && !v.multipart_intent
                    && !v.completion_attempted
                    && (self
                        .config
                        .expires_after
                        .is_some_and(|age| v.created.saturating_add(age) <= now())
                        || (!v.complete
                            && v.created.saturating_add(600) <= now()
                            && !self.file(id).exists()))
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in obsolete {
            if let Some(backend) = self.backend.clone() {
                // Keep the reservation and metadata until remote deletion succeeds.
                // The active claim prevents duplicate workers and concurrent PUTs.
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    active.insert(id.clone());
                    let service = self.clone();
                    handle.spawn(async move {
                        let deleted = backend.delete(&id).await.is_ok();
                        tokio::task::spawn_blocking(move || {
                            let mut records = service.records.lock().unwrap();
                            let mut active = service.active.lock().unwrap();
                            if deleted {
                                records.remove(&id);
                                let _ = service.persist(&records);
                            }
                            active.remove(&id);
                        })
                        .await
                        .ok();
                    });
                }
                continue;
            }
            match std::fs::remove_file(self.file(&id)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            r.remove(&id);
        }
        self.persist(&r)
    }
    /// Caller must authenticate and authorize the bare JID before issuing a slot.
    pub fn request_slot(
        &self,
        owner: &str,
        filename: &str,
        size: u64,
        content_type: &str,
    ) -> Result<Slot> {
        self.prune()?;
        ensure!(!owner.is_empty(), "forbidden");
        ensure!(
            !filename.is_empty()
                && filename.len() <= 1024
                && !filename
                    .chars()
                    .any(|c| c == '/' || c == '\\' || c.is_control())
                && filename != "."
                && filename != "..",
            "bad-request: invalid filename"
        );
        ensure!(
            size <= self.config.size_limit,
            "not-acceptable: file too large"
        );
        ensure!(
            HeaderValue::from_str(content_type).is_ok(),
            "bad-request: content type"
        );
        ensure!(
            self.config.allowed_types.is_empty()
                || self.config.allowed_types.iter().any(|t| t == content_type
                    || t.strip_suffix("/*")
                        .is_some_and(|prefix| content_type.starts_with(&format!("{prefix}/")))),
            "not-acceptable: file type"
        );
        let mut r = self.records.lock().unwrap();
        let total: u128 = r.values().map(|r| r.size as u128).sum();
        let daily: u128 = r
            .values()
            .filter(|r| r.owner == owner && r.created.saturating_add(86400) > now())
            .map(|r| r.size as u128)
            .sum();
        ensure!(
            total + size as u128 <= self.config.global_quota as u128,
            "resource-constraint: global quota"
        );
        ensure!(
            daily + size as u128 <= self.config.daily_quota as u128,
            "resource-constraint: daily quota"
        );
        let id = uuid::Uuid::new_v4().to_string();
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let token = if let Some(secret) = &self.config.secret {
            sign_jwt(
                secret,
                &serde_json::json!({"sub":owner,"slot":id,"filename":filename,"filesize":size,"filetype":content_type,"iat":now(),"exp":now()+600,"expires":self.config.expires_after.map(|age|now()+age)}),
            )
        } else {
            token
        };
        let auth = format!("Bearer {token}");
        r.insert(
            id.clone(),
            Record {
                owner: owner.into(),
                filename: filename.into(),
                size,
                content_type: content_type.into(),
                created: now(),
                token,
                complete: false,
                upload_id: None,
                multipart_intent: false,
                completion_attempted: false,
                xml: None,
            },
        );
        if let Err(e) = self.persist(&r) {
            r.remove(&id);
            return Err(e);
        };
        Ok(Slot {
            url: format!(
                "{}/{}/{}",
                self.config.base_url.trim_end_matches('/'),
                id,
                url_escape(filename)
            ),
            authorization: auth,
        })
    }
    pub fn disco_info(&self) -> String {
        format!(
            "<identity category='store' type='file' name='HTTP File Upload'/><feature var='{NS}'/><x xmlns='jabber:x:data' type='result'><field var='FORM_TYPE' type='hidden'><value>{NS}</value></field><field var='max-file-size'><value>{}</value></field></x>",
            self.config.size_limit
        )
    }
    pub fn router(&self) -> Router {
        let prefix = self
            .config
            .base_url
            .split_once("://")
            .and_then(|(_, a)| a.find('/').map(|i| &a[i..]))
            .unwrap_or("")
            .trim_end_matches('/')
            .to_owned();
        self.router_with_prefix(prefix)
    }
    /// Use the listener's mount path independently of the advertised public URL.
    pub fn router_at(&self, internal_path: &str) -> Result<Router> {
        let prefix = crate::http_config::normalize_path(internal_path)?;
        Ok(self.router_with_prefix(prefix.trim_end_matches('/').to_owned()))
    }
    fn router_with_prefix(&self, prefix: String) -> Router {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let config = Arc::downgrade(&self.config);
            let records = Arc::downgrade(&self.records);
            let active = Arc::downgrade(&self.active);
            let backend = self.backend.clone();
            handle.spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    let (Some(config), Some(records), Some(active)) =
                        (config.upgrade(), records.upgrade(), active.upgrade())
                    else {
                        break;
                    };
                    let service = UploadService {
                        config,
                        records,
                        active,
                        backend: backend.clone(),
                    };
                    let _ = tokio::task::spawn_blocking(move || service.prune()).await;
                }
            });
        }
        Router::new()
            .fallback(any(endpoint))
            .with_state(self.clone())
            .layer(axum::Extension(UploadPath(prefix)))
    }
    pub async fn handle_at(&self, req: Request, internal_path: &str) -> Response {
        endpoint(
            State(self.clone()),
            axum::Extension(UploadPath(internal_path.trim_end_matches('/').to_owned())),
            req,
        )
        .await
    }
    pub async fn serve(&self, listener: TcpListener, tls: Option<TlsAcceptor>) -> Result<()> {
        serve_router(listener, tls, self.router()).await
    }
}
pub async fn serve_router(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    app: Router,
) -> Result<()> {
    serve_router_inner(
        listener,
        tls,
        app,
        None,
        crate::http_proxy::ProxyConfig::default(),
    )
    .await
}

/// Serve HTTP with instance-owned diagnostics. Request bodies, headers and raw
/// URLs are deliberately excluded; paths are reduced to fixed route classes.
pub async fn serve_router_logged(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    app: Router,
    logger: Logger,
) -> Result<()> {
    serve_router_inner(
        listener,
        tls,
        app,
        Some(logger),
        crate::http_proxy::ProxyConfig::default(),
    )
    .await
}

/// Serve with configured proxy trust and attach effective context to every request.
pub async fn serve_router_configured(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    app: Router,
    logger: Option<Logger>,
    proxy: crate::http_proxy::ProxyConfig,
) -> Result<()> {
    serve_router_inner(listener, tls, app, logger, proxy).await
}

fn http_event(
    logger: &Option<Logger>,
    id: &str,
    level: Level,
    event: &str,
    fields: &[(&str, &str)],
) {
    if let Some(logger) = logger {
        logger.event(level, "http", Some(id), event, fields);
    }
}

async fn serve_router_inner(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    app: Router,
    logger: Option<Logger>,
    proxy: crate::http_proxy::ProxyConfig,
) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(256));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let mut app = app.clone();
        let tls = tls.clone();
        let logger = logger.clone();
        let id = uuid::Uuid::new_v4().to_string();
        http_event(
            &logger,
            &id,
            Level::Info,
            "connection-open",
            &[
                ("peer", &peer.to_string()),
                ("transport", if tls.is_some() { "https" } else { "http" }),
            ],
        );
        let proxy = proxy.clone();
        let transport_secure = tls.is_some();
        app = app.layer(axum::middleware::from_fn(
            move |mut req: Request, next: axum::middleware::Next| {
                let context = proxy.resolve(peer, transport_secure, req.headers());
                req.extensions_mut().insert(context);
                async move { next.run(req).await }
            },
        ));
        if let Some(request_logger) = logger.clone() {
            let request_id = id.clone();
            app = app.layer(axum::middleware::from_fn(
                move |req: Request, next: axum::middleware::Next| {
                    let logger = request_logger.clone();
                    let id = request_id.clone();
                    async move {
                        let default_route = match req.uri().path() {
                            "/xmpp-websocket" | "/xmpp-websocket/" => "websocket",
                            "/http-bind" | "/http-bind/" => "bosh",
                            _ => "other",
                        };
                        let response = next.run(req).await;
                        let route = match response
                            .extensions()
                            .get::<crate::http_transport::HttpRoute>()
                        {
                            Some(crate::http_transport::HttpRoute::Websocket) => "websocket",
                            Some(crate::http_transport::HttpRoute::Bosh) => "bosh",
                            Some(crate::http_transport::HttpRoute::Altconnect) => "altconnect",
                            Some(crate::http_transport::HttpRoute::Upload) => "upload",
                            None => default_route,
                        };
                        let status = response.status();
                        logger.event(
                            if status.is_client_error() || status.is_server_error() {
                                Level::Warn
                            } else {
                                Level::Info
                            },
                            "http",
                            Some(&id),
                            "request-complete",
                            &[("route", route), ("status", status.as_str())],
                        );
                        response
                    }
                },
            ));
        }
        tokio::spawn(async move {
            let _permit = permit;
            let service = hyper_util::service::TowerToHyperService::new(app);
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(std::time::Duration::from_secs(15));
            let result = if let Some(tls) = tls {
                let stream = match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    tls.accept(stream),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    result => {
                        http_event(
                            &logger,
                            &id,
                            Level::Warn,
                            "connection-closed",
                            &[
                                ("phase", "tls-handshake"),
                                (
                                    "reason",
                                    if result.is_err() {
                                        "timeout"
                                    } else {
                                        "tls-handshake-failed"
                                    },
                                ),
                            ],
                        );
                        return;
                    }
                };
                http_event(&logger, &id, Level::Info, "tls-established", &[]);
                builder
                    .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(stream), service)
                    .await
            } else {
                builder
                    .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(stream), service)
                    .await
            };
            http_event(
                &logger,
                &id,
                if result.is_ok() {
                    Level::Info
                } else {
                    Level::Warn
                },
                "connection-closed",
                &[
                    ("phase", "http"),
                    (
                        "reason",
                        if result.is_ok() {
                            "http-complete-or-upgraded"
                        } else {
                            "http-transport-error"
                        },
                    ),
                ],
            );
        });
    }
}

fn response(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap()
}
fn bearer_token(authorization: &[u8]) -> Option<&str> {
    let value = std::str::from_utf8(authorization).ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then(|| token.trim_start_matches(' '))
}
struct UploadGuard {
    active: Arc<Mutex<BTreeSet<String>>>,
    id: String,
    temp: PathBuf,
}
impl Drop for UploadGuard {
    fn drop(&mut self) {
        self.active.lock().unwrap().remove(&self.id);
        let _ = std::fs::remove_file(&self.temp);
    }
}
#[derive(Clone)]
struct UploadPath(String);
async fn endpoint(
    State(s): State<UploadService>,
    axum::Extension(prefix): axum::Extension<UploadPath>,
    req: Request,
) -> Response {
    let mut reply = handle_at(s, req, &prefix.0).await;
    reply
        .headers_mut()
        .insert("access-control-allow-origin", HeaderValue::from_static("*"));
    reply
}
async fn handle_at(s: UploadService, req: Request, prefix: &str) -> Response {
    let request_path = req.uri().path().to_string();
    let Some(path) = request_path.strip_prefix(&format!("{prefix}/")) else {
        return response(StatusCode::NOT_FOUND);
    };
    let Some((id, name)) = path.split_once('/') else {
        return response(StatusCode::NOT_FOUND);
    };
    let Some(decoded_id) = url_decode(id).and_then(|v| String::from_utf8(v).ok()) else {
        return response(StatusCode::BAD_REQUEST);
    };
    let id = decoded_id.as_str();
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return response(StatusCode::BAD_REQUEST);
    }
    let record = s.records.lock().unwrap().get(id).cloned();
    let Some(record) = record else {
        return response(StatusCode::NOT_FOUND);
    };
    if url_decode(name).as_deref() != Some(record.filename.as_bytes()) {
        return response(StatusCode::NOT_FOUND);
    };
    if s.config
        .expires_after
        .is_some_and(|age| record.created.saturating_add(age) <= now())
    {
        return response(StatusCode::GONE);
    }
    if req.method() == "OPTIONS" {
        return Response::builder()
            .status(204)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "GET, HEAD, PUT, OPTIONS")
            .header(
                "access-control-allow-headers",
                "Authorization, Content-Type",
            )
            .body(Body::empty())
            .unwrap();
    }
    if req.method() == "PUT" {
        use subtle::ConstantTimeEq;
        let auth = req
            .headers()
            .get("authorization")
            .map(|v| v.as_bytes())
            .unwrap_or_default();
        let valid_saved = s.config.secret.is_none()
            && !record.token.is_empty()
            && bearer_token(auth)
                .is_some_and(|token| bool::from(token.as_bytes().ct_eq(record.token.as_bytes())))
            && record.created.saturating_add(600) > now();
        let valid_jwt = s
            .config
            .secret
            .as_ref()
            .is_some_and(|secret| verify_jwt(secret, auth, id, &record));
        if !valid_saved && !valid_jwt {
            return response(StatusCode::FORBIDDEN);
        }
        if let Some(len) = req.headers().get("content-length")
            && len.to_str().ok().and_then(|v| v.parse::<u64>().ok()) != Some(record.size)
        {
            return response(StatusCode::PAYLOAD_TOO_LARGE);
        }
        if record.complete || (s.backend.is_none() && s.file(id).exists()) {
            return response(StatusCode::CONFLICT);
        };
        // Refresh the snapshot atomically with the exclusive claim. A request
        // may have waited while an earlier PUT committed or was quarantined.
        let record = match s.claim_upload(id) {
            Ok(record) => record,
            Err(status) => return response(status),
        };
        let dest = s.file(id);
        let temp = dest.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let _guard = UploadGuard {
            active: s.active.clone(),
            id: id.into(),
            temp: temp.clone(),
        };
        if let Some(backend) = &s.backend {
            if (record.upload_id.is_some()
                || record.multipart_intent
                || record.completion_attempted)
                && let Err(error) = s.reconcile_record(id.to_owned(), record.clone()).await
            {
                return response(if error.downcast_ref::<CompletionUncertain>().is_some() {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_GATEWAY
                });
            }
            // Reconcile a remote commit whose response or local metadata write
            // was interrupted, rather than overwriting a single-use object.
            match backend.read(id, true, None).await {
                Ok(reply) if reply.status() == StatusCode::NOT_FOUND => {}
                Ok(reply) if reply.status() == StatusCode::OK => {
                    if reply
                        .headers()
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        != Some(record.size)
                    {
                        return response(StatusCode::BAD_GATEWAY);
                    }
                    let service = s.clone();
                    let id = id.to_owned();
                    return response(
                        tokio::task::spawn_blocking(move || {
                            let _guard = _guard;
                            let mut records = service.records.lock().unwrap();
                            if let Some(r) = records.get_mut(&id) {
                                r.complete = true;
                                r.upload_id = None;
                                r.multipart_intent = false;
                                r.completion_attempted = false;
                            }
                            if service.persist(&records).is_err() {
                                StatusCode::INTERNAL_SERVER_ERROR
                            } else {
                                StatusCode::CONFLICT
                            }
                        })
                        .await
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    );
                }
                _ => return response(StatusCode::BAD_GATEWAY),
            }
            // Hold the single-use claim across initiation and journaling even
            // if the HTTP request is cancelled. A persisted intent closes the
            // crash window before S3 returns its UploadId.
            let service = s.clone();
            let backend = backend.clone();
            let slot_id = id.to_owned();
            let content_type = record.content_type.clone();
            let initiation = tokio::spawn(async move {
                let guard = _guard;
                let journal = service.clone();
                let journal_id = slot_id.clone();
                tokio::task::spawn_blocking(move || -> Result<()> {
                    let mut records = journal.records.lock().unwrap();
                    let r = records
                        .get_mut(&journal_id)
                        .ok_or_else(|| anyhow::anyhow!("upload reservation missing"))?;
                    r.multipart_intent = true;
                    journal.persist(&records)
                })
                .await??;
                let mut upload = backend.begin(&slot_id, &content_type).await?;
                let upload_id = upload.upload_id().to_owned();
                let cleanup = service.clone();
                upload.after_abort(move || {
                    // HEAD must reconcile a possible remote commit before
                    // clearing the intent, even when abort returns 404.
                    tokio::task::spawn_blocking(move || {
                        let _ = cleanup.prune();
                    });
                });
                tokio::task::spawn_blocking(move || -> Result<()> {
                    let mut records = service.records.lock().unwrap();
                    let r = records
                        .get_mut(&slot_id)
                        .ok_or_else(|| anyhow::anyhow!("upload reservation missing"))?;
                    r.upload_id = Some(upload_id);
                    service.persist(&records)
                })
                .await??;
                Ok::<_, anyhow::Error>((upload, guard))
            });
            let (mut upload, _guard) = match initiation.await {
                Ok(Ok(value)) => value,
                _ => return response(StatusCode::BAD_GATEWAY),
            };
            let mut body = req.into_body();
            let mut count = 0u64;
            let mut part = Vec::with_capacity(PART_SIZE);
            loop {
                let frame =
                    match tokio::time::timeout(std::time::Duration::from_secs(120), body.frame())
                        .await
                    {
                        Ok(Some(Ok(frame))) => frame,
                        Ok(Some(Err(_))) => return response(StatusCode::BAD_REQUEST),
                        Ok(None) => break,
                        Err(_) => return response(StatusCode::REQUEST_TIMEOUT),
                    };
                if let Ok(bytes) = frame.into_data() {
                    count = count.saturating_add(bytes.len() as u64);
                    if count > record.size {
                        return response(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    let mut bytes = bytes.as_ref();
                    while !bytes.is_empty() {
                        let take = (PART_SIZE - part.len()).min(bytes.len());
                        part.extend_from_slice(&bytes[..take]);
                        bytes = &bytes[take..];
                        if part.len() == PART_SIZE
                            && upload
                                .part(std::mem::replace(&mut part, Vec::with_capacity(PART_SIZE)))
                                .await
                                .is_err()
                        {
                            return response(StatusCode::BAD_GATEWAY);
                        }
                    }
                }
            }
            if count != record.size {
                return response(StatusCode::BAD_REQUEST);
            }
            if (!part.is_empty() || count == 0) && upload.part(part).await.is_err() {
                return response(StatusCode::BAD_GATEWAY);
            }
            // Once completing begins, finish the durable commit even if the
            // HTTP client disconnects. Keep the single-use claim until then.
            let service = s.clone();
            let id = id.to_owned();
            let commit = tokio::spawn(async move {
                let _guard = _guard;
                let journal = service.clone();
                let journal_id = id.clone();
                if !matches!(
                    tokio::task::spawn_blocking(move || -> Result<()> {
                        let mut records = journal.records.lock().unwrap();
                        let r = records
                            .get_mut(&journal_id)
                            .ok_or_else(|| anyhow::anyhow!("upload reservation missing"))?;
                        r.completion_attempted = true;
                        journal.persist(&records)
                    })
                    .await,
                    Ok(Ok(()))
                ) {
                    return StatusCode::INTERNAL_SERVER_ERROR;
                }
                if let Err(error) = upload.complete().await {
                    if error
                        .downcast_ref::<crate::object_store::CompletionRejected>()
                        .is_some()
                    {
                        // Explicit terminal rejection is retryable after HEAD
                        // reconciliation. Network/XML uncertainty stays frozen.
                        let journal = service.clone();
                        let journal_id = id.clone();
                        let _ = tokio::task::spawn_blocking(move || -> Result<()> {
                            let mut records = journal.records.lock().unwrap();
                            if let Some(r) = records.get_mut(&journal_id) {
                                r.completion_attempted = false;
                            }
                            journal.persist(&records)
                        })
                        .await;
                    }
                    // Multipart::drop may finish its abort while this commit
                    // still owns the active claim. Its callback's prune then
                    // correctly skips the slot, so it cannot be our only
                    // reconciliation trigger. Reconcile under this same claim
                    // before returning the ambiguous completion response.
                    let pending = service.records.lock().unwrap().get(&id).cloned();
                    if let Some(record) = pending {
                        let _ = service.reconcile_record(id.clone(), record).await;
                    }
                    return StatusCode::BAD_GATEWAY;
                }
                tokio::task::spawn_blocking(move || {
                    let _guard = _guard;
                    let mut records = service.records.lock().unwrap();
                    if let Some(r) = records.get_mut(&id) {
                        r.complete = true;
                        r.upload_id = None;
                        r.multipart_intent = false;
                        r.completion_attempted = false;
                    }
                    if service.persist(&records).is_err() {
                        StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        StatusCode::CREATED
                    }
                })
                .await
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            });
            return response(commit.await.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
        }
        if tokio::fs::create_dir_all(dest.parent().unwrap())
            .await
            .is_err()
        {
            return response(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let Ok(mut file) = options.open(&temp).await else {
            return response(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let mut body = req.into_body();
        let mut count = 0u64;
        loop {
            let frame =
                match tokio::time::timeout(std::time::Duration::from_secs(120), body.frame()).await
                {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(_) => return response(StatusCode::REQUEST_TIMEOUT),
                };
            let Ok(frame) = frame else {
                return response(StatusCode::BAD_REQUEST);
            };
            if let Ok(bytes) = frame.into_data() {
                count = count.saturating_add(bytes.len() as u64);
                if count > record.size {
                    return response(StatusCode::PAYLOAD_TOO_LARGE);
                };
                if file.write_all(&bytes).await.is_err() {
                    return response(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
        if count != record.size {
            return response(StatusCode::BAD_REQUEST);
        };
        if file.sync_all().await.is_err() {
            return response(StatusCode::INTERNAL_SERVER_ERROR);
        };
        drop(file);
        if tokio::fs::hard_link(&temp, &dest).await.is_err() {
            return response(StatusCode::CONFLICT);
        };
        #[cfg(unix)]
        {
            let Ok(directory) = tokio::fs::File::open(dest.parent().unwrap()).await else {
                return response(StatusCode::INTERNAL_SERVER_ERROR);
            };
            if directory.sync_all().await.is_err() {
                return response(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
        let id = id.to_owned();
        return response(
            tokio::task::spawn_blocking(move || {
                let _guard = _guard;
                let mut records = s.records.lock().unwrap();
                if let Some(r) = records.get_mut(&id) {
                    r.complete = true;
                }
                if s.persist(&records).is_err() {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::CREATED
                }
            })
            .await
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        );
    }
    if req.method() != "GET" && req.method() != "HEAD" {
        return response(StatusCode::METHOD_NOT_ALLOWED);
    }
    if s.backend.is_some() && !record.complete {
        return response(StatusCode::GONE);
    }
    let mut local_file = if s.backend.is_none() {
        match tokio::fs::File::open(s.file(id)).await {
            Ok(file) => Some(file),
            Err(_) => return response(StatusCode::GONE),
        }
    } else {
        None
    };
    let modified = chrono::DateTime::from_timestamp(record.created as i64, 0)
        .map(|d| d.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_default();
    let etag = format!("\"{id}-{}\"", record.size);
    let date_matches = |value: &str| {
        chrono::DateTime::parse_from_rfc2822(value)
            .ok()
            .is_some_and(|d| d.timestamp() >= record.created as i64)
    };
    let not_modified = if let Some(value) = req.headers().get("if-none-match") {
        value.to_str().ok().is_some_and(|v| {
            v.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
            })
        })
    } else {
        req.headers()
            .get("if-modified-since")
            .and_then(|v| v.to_str().ok())
            .is_some_and(date_matches)
    };
    if not_modified {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("etag", &etag)
            .header("last-modified", &modified)
            .body(Body::empty())
            .unwrap();
    }
    let range_allowed = req.headers().get("if-range").is_none_or(|value| {
        value
            .to_str()
            .ok()
            .is_some_and(|v| v == etag || date_matches(v))
    });
    let mut status = StatusCode::OK;
    let mut start = 0;
    let mut end = record.size.saturating_sub(1);
    if let Some(range) = req.headers().get("range").filter(|_| range_allowed) {
        let parsed = range
            .to_str()
            .ok()
            .and_then(|r| r.strip_prefix("bytes="))
            .and_then(|r| r.split_once('-'))
            .and_then(|(a, b)| {
                if a.is_empty() {
                    let suffix = b.parse::<u64>().ok()?;
                    if suffix == 0 || record.size == 0 {
                        return None;
                    }
                    return Some((record.size.saturating_sub(suffix), record.size - 1));
                }
                let start = a.parse::<u64>().ok()?;
                let end = if b.is_empty() {
                    record.size.checked_sub(1)?
                } else {
                    b.parse().ok()?
                };
                (start <= end && start < record.size)
                    .then_some((start, end.min(record.size.saturating_sub(1))))
            });
        let Some((a, b)) = parsed else {
            return Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("content-range", format!("bytes */{}", record.size))
                .body(Body::empty())
                .unwrap();
        };
        start = a;
        end = b;
        status = StatusCode::PARTIAL_CONTENT;
    }
    let length = if record.size == 0 { 0 } else { end - start + 1 };
    use tokio::io::AsyncReadExt;
    let body = if let Some(backend) = &s.backend {
        let range = (status == StatusCode::PARTIAL_CONTENT).then(|| format!("bytes={start}-{end}"));
        let Ok(reply) = backend
            .read(id, req.method() == "HEAD", range.as_deref())
            .await
        else {
            return response(StatusCode::BAD_GATEWAY);
        };
        if reply.status() == StatusCode::NOT_FOUND {
            return response(StatusCode::GONE);
        }
        if reply.status() != status {
            return response(StatusCode::BAD_GATEWAY);
        }
        if reply
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            != Some(length)
        {
            return response(StatusCode::BAD_GATEWAY);
        }
        if status == StatusCode::PARTIAL_CONTENT
            && reply
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                != Some(format!("bytes {start}-{end}/{}", record.size).as_str())
        {
            return response(StatusCode::BAD_GATEWAY);
        }
        reply.into_body()
    } else {
        let mut file = local_file.take().unwrap();
        if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
            return response(StatusCode::INTERNAL_SERVER_ERROR);
        }
        if req.method() == "HEAD" {
            Body::empty()
        } else {
            Body::from_stream(ReaderStream::new(file.take(length)))
        }
    };
    let disposition = if record.content_type == "text/plain"
        || ["image/", "video/", "audio/"]
            .iter()
            .any(|p| record.content_type.starts_with(p))
    {
        "inline"
    } else {
        "attachment"
    };
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", &record.content_type)
        .header("content-length", length)
        .header(
            "content-disposition",
            format!(
                "{disposition}; filename*=UTF-8''{}",
                url_escape(&record.filename)
            ),
        )
        .header("x-content-type-options", "nosniff")
        .header(
            "content-security-policy",
            "default-src 'none'; media-src 'self'; frame-ancestors 'none'",
        )
        .header("access-control-allow-origin", "*")
        .header("accept-ranges", "bytes")
        .header("etag", etag)
        .header("last-modified", modified)
        .header("cache-control", "max-age=31556952, immutable")
        .header("x-frame-options", "DENY")
        .header("strict-transport-security", "max-age=31556952");
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            "content-range",
            format!("bytes {start}-{end}/{}", record.size),
        );
    }
    builder.body(body).unwrap()
}

fn sign_jwt(secret: &str, payload: &serde_json::Value) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
    use hmac::{Hmac, Mac};
    let signed = format!(
        "{}.{}",
        B.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        B.encode(serde_json::to_vec(payload).unwrap())
    );
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    format!("{signed}.{}", B.encode(mac.finalize().into_bytes()))
}
fn verify_jwt(secret: &str, authorization: &[u8], id: &str, r: &Record) -> bool {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
    use hmac::{Hmac, Mac};
    let check = || -> Option<()> {
        let token = bearer_token(authorization)?;
        if token.len() > 8192 {
            return None;
        }
        let (signed, sig) = token.rsplit_once('.')?;
        let (head, body) = signed.split_once('.')?;
        let header: serde_json::Value = serde_json::from_slice(&B.decode(head).ok()?).ok()?;
        if header.get("alg")?.as_str()? != "HS256" {
            return None;
        }
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).ok()?;
        mac.update(signed.as_bytes());
        mac.verify_slice(&B.decode(sig).ok()?).ok()?;
        let p: serde_json::Value = serde_json::from_slice(&B.decode(body).ok()?).ok()?;
        if p.get("exp")?.as_u64()? <= now()
            || p.get("nbf")
                .and_then(|v| v.as_u64())
                .is_some_and(|t| t > now())
            || p.get("slot")?.as_str()? != id
            || p.get("sub")?.as_str()? != r.owner
            || p.get("filename")?.as_str()? != r.filename
            || p.get("filesize")?.as_u64()? != r.size
            || p.get("filetype")?.as_str()? != r.content_type
        {
            return None;
        }
        Some(())
    };
    check().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upload_internal_mount_is_independent_of_advertised_proxy_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let service = UploadService::new(UploadConfig {
            root: temp.path().into(),
            host: "upload.example.test".into(),
            base_url: "https://public.example.test/proxy/files".into(),
            size_limit: 8,
            daily_quota: 8,
            global_quota: 8,
            expires_after: None,
            allowed_types: vec![],
            secret: None,
        })
        .unwrap();
        let slot = service
            .request_slot("a@example.test", "hello.txt", 2, "text/plain")
            .unwrap();
        assert!(
            slot.url
                .starts_with("https://public.example.test/proxy/files/")
        );
        let suffix = slot
            .url
            .strip_prefix("https://public.example.test/proxy/files")
            .unwrap();
        assert!(service.router_at("/internal/files").is_ok());
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/internal/files{suffix}"))
            .header("authorization", &slot.authorization)
            .body(Body::from("hi"))
            .unwrap();
        assert_eq!(
            handle_at(service.clone(), request, "/internal/files")
                .await
                .status(),
            StatusCode::CREATED
        );
        let request = Request::builder()
            .uri(format!("/internal/files{suffix}"))
            .body(Body::empty())
            .unwrap();
        let reply = handle_at(service.clone(), request, "/internal/files").await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.into_body().collect().await.unwrap().to_bytes(), "hi");
        let request = Request::builder()
            .uri(format!("/proxy/files{suffix}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            handle_at(service, request, "/internal/files")
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn upload_claim_refreshes_completion_state_after_an_earlier_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let service = UploadService::new(UploadConfig {
            root: temp.path().into(),
            host: "upload.example.test".into(),
            base_url: "https://upload.example.test/file_share".into(),
            size_limit: 1,
            daily_quota: 3,
            global_quota: 3,
            expires_after: None,
            allowed_types: vec![],
            secret: None,
        })
        .unwrap();
        service
            .request_slot("a@example.test", "pending", 1, "text/plain")
            .unwrap();
        let (id, stale) = service
            .records
            .lock()
            .unwrap()
            .iter()
            .next()
            .map(|(id, r)| (id.clone(), r.clone()))
            .unwrap();
        assert!(!stale.completion_attempted);
        // Another PUT finishes ambiguously after this request has read its
        // initial snapshot, but before it acquires the active claim.
        service
            .records
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .completion_attempted = true;
        let fresh = service.claim_upload(&id).unwrap();
        assert!(fresh.completion_attempted);
        assert!(service.active.lock().unwrap().contains(&id));
        service.active.lock().unwrap().remove(&id);
        service
            .records
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .complete = true;
        assert!(matches!(
            service.claim_upload(&id),
            Err(StatusCode::CONFLICT)
        ));
        assert!(!service.active.lock().unwrap().contains(&id));
    }

    #[test]
    fn abandoned_slots_release_quota_without_pruning_existing_or_active_files() {
        let temp = tempfile::tempdir().unwrap();
        let service = UploadService::new(UploadConfig {
            root: temp.path().into(),
            host: "upload.example.test".into(),
            base_url: "https://upload.example.test/file_share".into(),
            size_limit: 1,
            daily_quota: 3,
            global_quota: 3,
            expires_after: None,
            allowed_types: vec![],
            secret: None,
        })
        .unwrap();
        for name in ["abandoned", "existing", "active"] {
            service
                .request_slot("a@example.test", name, 1, "text/plain")
                .unwrap();
        }
        {
            let mut records = service.records.lock().unwrap();
            for (id, record) in records.iter_mut() {
                record.created = now() - 601;
                if record.filename == "existing" {
                    // Imported archives do not carry a completion flag.
                    let path = service.file(id);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(path, b"x").unwrap();
                } else if record.filename == "active" {
                    service.active.lock().unwrap().insert(id.clone());
                }
            }
        }
        service
            .request_slot("a@example.test", "replacement", 1, "text/plain")
            .unwrap();
        let records = service.records.lock().unwrap();
        assert_eq!(records.len(), 3);
        assert!(!records.values().any(|r| r.filename == "abandoned"));
        assert!(records.values().any(|r| r.filename == "existing"));
        assert!(records.values().any(|r| r.filename == "active"));
    }
}
