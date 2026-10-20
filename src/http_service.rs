//! Streaming XEP-0363 upload endpoint. Slots are single-use and bounded before streaming.
use crate::{
    logging::{Level, Logger},
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
    xml: Option<String>,
}
#[derive(Clone)]
pub struct UploadService {
    config: Arc<UploadConfig>,
    records: Arc<Mutex<BTreeMap<String, Record>>>,
    active: Arc<Mutex<BTreeSet<String>>>,
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
            let token = records.remove(&e.id).map(|r| r.token).unwrap_or_default();
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
                    complete: false,
                    xml: Some(e.xml),
                },
            );
        }
        records = authoritative;
        let s = Self {
            config: Arc::new(config),
            records: Arc::new(Mutex::new(records)),
            active: Arc::new(Mutex::new(BTreeSet::new())),
        };
        s.prune()?;
        Ok(s)
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
        let active = self.active.lock().unwrap();
        let obsolete: Vec<String> = r
            .iter()
            .filter(|(id, v)| {
                !active.contains(*id)
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
            handle.spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    let (Some(config), Some(records), Some(active)) =
                        (config.upgrade(), records.upgrade(), active.upgrade())
                    else {
                        break;
                    };
                    let service = UploadService {
                        config,
                        records,
                        active,
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
        if record.complete || s.file(id).exists() {
            return response(StatusCode::CONFLICT);
        };
        {
            // Use the same lock order as prune: a reservation must still exist
            // when it becomes active, so pruning cannot orphan an upload.
            let records = s.records.lock().unwrap();
            if !records.contains_key(id) {
                return response(StatusCode::GONE);
            }
            if !s.active.lock().unwrap().insert(id.into()) {
                return response(StatusCode::CONFLICT);
            }
        }
        let dest = s.file(id);
        let temp = dest.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let _guard = UploadGuard {
            active: s.active.clone(),
            id: id.into(),
            temp: temp.clone(),
        };
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
        let mut records = s.records.lock().unwrap();
        if let Some(r) = records.get_mut(id) {
            r.complete = true;
        }
        if s.persist(&records).is_err() {
            return response(StatusCode::INTERNAL_SERVER_ERROR);
        };
        return response(StatusCode::CREATED);
    }
    if req.method() != "GET" && req.method() != "HEAD" {
        return response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let Ok(mut file) = tokio::fs::File::open(s.file(id)).await else {
        return response(StatusCode::GONE);
    };
    let modified = chrono::DateTime::from_timestamp(record.created as i64, 0)
        .map(|d| d.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_default();
    if req
        .headers()
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
        == Some(modified.as_str())
    {
        return response(StatusCode::NOT_MODIFIED);
    }
    let mut status = StatusCode::OK;
    let mut start = 0;
    let mut end = record.size.saturating_sub(1);
    if let Some(range) = req.headers().get("range") {
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
    if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    use tokio::io::AsyncReadExt;
    let body = if req.method() == "HEAD" {
        Body::empty()
    } else {
        Body::from_stream(ReaderStream::new(file.take(length)))
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
