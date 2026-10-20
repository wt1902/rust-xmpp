//! RFC 7395 WebSocket adapter to the shared XMPP stream engine.
use crate::wire::{Framer, escape};
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::io::{AsyncWriteExt, DuplexStream};
pub type ConnectionHandler =
    Arc<dyn Fn(DuplexStream) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;
/// The effective HTTP connection context is supplied by the HTTP listener.
pub type ContextConnectionHandler = Arc<
    dyn Fn(
            DuplexStream,
            Option<crate::http_proxy::RequestContext>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpRoute {
    Websocket,
    Bosh,
    Altconnect,
}

#[derive(Clone)]
struct ConfiguredState {
    handler: ContextConnectionHandler,
    bosh: BoshState,
    config: crate::http_config::HttpConfig,
    websocket: bool,
    bosh_enabled: bool,
    secure: bool,
}
/// A fallback dispatcher uses literal mount paths, avoiding route-pattern conflicts and panics.
pub fn configured_router(
    handler: ContextConnectionHandler,
    config: crate::http_config::HttpConfig,
    websocket: bool,
    bosh: bool,
    secure: bool,
) -> anyhow::Result<Router> {
    configured_router_with_fallback(handler, config, websocket, bosh, secure, Router::new())
}
/// Compose transport mounts with an existing HTTP app without merging fallbacks.
pub fn configured_router_with_fallback(
    handler: ContextConnectionHandler,
    config: crate::http_config::HttpConfig,
    websocket: bool,
    bosh: bool,
    secure: bool,
    fallback: Router,
) -> anyhow::Result<Router> {
    anyhow::ensure!(
        !(websocket && bosh && config.websocket_path == config.bosh_path),
        "websocket and bosh HTTP paths conflict"
    );
    let legacy: ConnectionHandler = {
        let handler = handler.clone();
        Arc::new(move |stream| handler(stream, None))
    };
    let mut bosh_state = new_bosh_state(legacy);
    bosh_state.context_handler = Some(handler.clone());
    let state = ConfiguredState {
        handler,
        bosh: bosh_state,
        config,
        websocket,
        bosh_enabled: bosh,
        secure,
    };
    Ok(fallback
        .layer(axum::middleware::from_fn_with_state(
            state,
            configured_middleware,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024)))
}
async fn configured_middleware(
    State(state): State<ConfiguredState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path();
    let matches =
        |mount: &str| path == mount || (mount != "/" && path.strip_suffix('/') == Some(mount));
    if (state.websocket && matches(&state.config.websocket_path))
        || (state.bosh_enabled && matches(&state.config.bosh_path))
    {
        let route = if state.websocket && matches(&state.config.websocket_path) {
            HttpRoute::Websocket
        } else {
            HttpRoute::Bosh
        };
        let mut response = configured_request(State(state), request).await;
        response.extensions_mut().insert(route);
        response
    } else {
        next.run(request).await
    }
}
async fn configured_request(
    State(state): State<ConfiguredState>,
    request: axum::extract::Request,
) -> Response {
    use axum::extract::{FromRequest, FromRequestParts};
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    let Some(host) = host else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !state.config.accepts_host(host) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = request.uri().path();
    let matches =
        |mount: &str| path == mount || (mount != "/" && path.strip_suffix('/') == Some(mount));
    let websocket = state.websocket && matches(&state.config.websocket_path);
    let bosh = state.bosh_enabled && matches(&state.config.bosh_path);
    if !websocket && !bosh {
        return StatusCode::NOT_FOUND.into_response();
    }
    let context = request
        .extensions()
        .get::<crate::http_proxy::RequestContext>()
        .cloned();
    let secure = context.as_ref().map(|c| c.secure).unwrap_or(state.secure);
    let considered = if websocket {
        state.config.consider_websocket_secure
    } else {
        state.config.consider_bosh_secure
    };
    if !secure && !considered {
        return StatusCode::FORBIDDEN.into_response();
    }
    let origins = if websocket {
        &state.config.websocket_origins
    } else {
        &state.config.bosh_origins
    };
    let origin = request.headers().get(axum::http::header::ORIGIN).cloned();
    if let Some(origin) = &origin
        && !origin
            .to_str()
            .ok()
            .is_some_and(|o| origins.iter().any(|a| a == o || a == "*"))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let method = request.method().clone();
    let mut response = if method == axum::http::Method::OPTIONS {
        preflight(if websocket {
            "GET, OPTIONS"
        } else {
            "POST, OPTIONS"
        })
    } else if websocket && method == axum::http::Method::GET {
        let (mut parts, _) = request.into_parts();
        match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
            Ok(ws) => {
                let handler: ConnectionHandler =
                    Arc::new(move |stream| (state.handler)(stream, context));
                upgrade(State(handler), parts.headers, ws).await
            }
            Err(e) => e.into_response(),
        }
    } else if bosh && method == axum::http::Method::POST {
        match Bytes::from_request(request, &()).await {
            Ok(bytes) => bosh_with_context(state.bosh, bytes, context).await,
            Err(e) => e.into_response(),
        }
    } else {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            [(
                axum::http::header::ALLOW,
                if websocket {
                    "GET, OPTIONS"
                } else {
                    "POST, OPTIONS"
                },
            )],
        )
            .into_response()
    };
    response
        .headers_mut()
        .remove(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN);
    if let Some(origin) = origin {
        response
            .headers_mut()
            .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        response.headers_mut().append(
            axum::http::header::VARY,
            axum::http::HeaderValue::from_static("Origin"),
        );
    }
    response
}
pub fn websocket_router(handler: ConnectionHandler) -> Router {
    let route = get(upgrade).options(|| async { preflight("GET, OPTIONS") });
    Router::new()
        .route("/xmpp-websocket", route.clone())
        .route("/xmpp-websocket/", route)
        .with_state(handler)
}
fn preflight(methods: &'static str) -> Response {
    (
        [
            ("access-control-allow-origin", "*"),
            ("access-control-allow-methods", methods),
            ("access-control-allow-headers", "Content-Type"),
        ],
        "",
    )
        .into_response()
}
async fn upgrade(
    State(handler): State<ConnectionHandler>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|p| p.split(',').any(|p| p.trim() == "xmpp"))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    ws.protocols(["xmpp"])
        .max_message_size(256 * 1024)
        .max_frame_size(256 * 1024)
        .on_upgrade(move |socket| bridge(socket, handler))
}
fn from_websocket(input: &str) -> anyhow::Result<String> {
    let d = roxmltree::Document::parse(input)?;
    let n = d.root_element();
    if n.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-framing") {
        match n.tag_name().name() {
            "open" => {
                let mut out="<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'".to_string();
                for key in ["to", "from", "id", "version"] {
                    if let Some(v) = n.attribute(key) {
                        out.push_str(&format!(" {key}='{}'", escape(v)));
                    }
                }
                out.push('>');
                Ok(out)
            }
            "close" => Ok("</stream:stream>".into()),
            _ => anyhow::bail!("unknown framing element"),
        }
    } else {
        anyhow::ensure!(
            matches!(
                n.tag_name().namespace(),
                Some(
                    "jabber:client"
                        | "urn:ietf:params:xml:ns:xmpp-sasl"
                        | "urn:xmpp:sasl:2"
                        | "urn:xmpp:sm:3"
                        | "urn:xmpp:csi:0"
                )
            ),
            "unexpected websocket namespace"
        );
        Ok(input.into())
    }
}
fn to_websocket(input: &str) -> anyhow::Result<Option<String>> {
    if input.starts_with("<?xml") {
        return Ok(None);
    }
    if input == "</stream:stream>" {
        return Ok(Some(
            "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>".into(),
        ));
    }
    if input.starts_with("<stream:stream ") {
        let xml = format!("{input}</stream:stream>");
        let d = roxmltree::Document::parse(&xml)?;
        let n = d.root_element();
        let mut out = "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'".to_string();
        for key in ["to", "from", "id", "version"] {
            if let Some(v) = n.attribute(key) {
                out.push_str(&format!(" {key}='{}'", escape(v)));
            }
        }
        out.push_str("/>");
        return Ok(Some(out));
    }
    let wrapped = format!(
        "<root xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>{input}</root>"
    );
    let d = roxmltree::Document::parse(&wrapped)?;
    let n = d
        .root_element()
        .first_element_child()
        .ok_or_else(|| anyhow::anyhow!("no XML"))?;
    // Every message is an independent XML document. Serialize the parsed
    // subtree so inherited namespaces also survive on children and attributes.
    Ok(Some(crate::protocol::xml(n)))
}
async fn bridge(socket: WebSocket, handler: ConnectionHandler) {
    let (internal, transport) = tokio::io::duplex(256 * 1024);
    let mut worker = tokio::spawn(handler(internal));
    let (mut read, mut write) = tokio::io::split(transport);
    let (mut tx, mut rx) = socket.split();
    let incoming = async {
        while let Some(Ok(message)) = rx.next().await {
            match message {
                Message::Text(text) => {
                    let text = from_websocket(&text)?;
                    write.write_all(text.as_bytes()).await?;
                }
                Message::Close(_) => break,
                Message::Binary(_) => anyhow::bail!("binary XMPP frames forbidden"),
                _ => {}
            }
        }
        anyhow::Ok(())
    };
    let outgoing = async {
        let mut framer = Framer::default();
        loop {
            let frame = framer.next(&mut read).await?;
            if let Some(text) = to_websocket(&frame)? {
                tx.send(Message::Text(text.into())).await?;
            }
            if frame == "</stream:stream>" {
                break;
            }
        }
        anyhow::Ok(())
    };
    tokio::select! {_=incoming=>{},_=outgoing=>{}}
    let _ = tokio::time::timeout(Duration::from_secs(2), tx.close()).await;
    // Deliver buffered XMPP close frames before retiring the engine. EOF alone
    // remains an ungraceful disconnect, allowing stream management to hibernate.
    let _ = write.shutdown().await;
    if tokio::time::timeout(Duration::from_secs(5), &mut worker)
        .await
        .is_err()
    {
        worker.abort();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn configured_state(secure: bool) -> ConfiguredState {
        let config = serde_json::from_value(serde_json::json!({"global":{"http_paths":{"websocket":"/custom/ws","bosh":"/custom/bind"},"http_cors_override":{"websocket":{"origins":["https://allowed.test"]},"bosh":{"origins":["https://allowed.test"]}}},"hosts":{"a.test":{"options":{}}}})).unwrap();
        let handler: ContextConnectionHandler =
            Arc::new(|_, _| Box::pin(async { panic!("no stream expected") }));
        let legacy: ConnectionHandler =
            Arc::new(|_| Box::pin(async { panic!("no stream expected") }));
        ConfiguredState {
            handler,
            bosh: new_bosh_state(legacy),
            config: crate::http_config::HttpConfig::for_host(&config, "a.test").unwrap(),
            websocket: true,
            bosh_enabled: true,
            secure,
        }
    }
    async fn configured_status(
        state: ConfiguredState,
        method: &str,
        path: &str,
        host: &str,
        origin: Option<&str>,
        context: Option<crate::http_proxy::RequestContext>,
    ) -> Response {
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", host);
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let mut request = request.body(axum::body::Body::empty()).unwrap();
        if let Some(context) = context {
            request.extensions_mut().insert(context);
        }
        configured_request(State(state), request).await
    }
    #[tokio::test]
    async fn configured_mount_host_origin_and_secure_dispatch() {
        assert_eq!(
            configured_status(
                configured_state(true),
                "OPTIONS",
                "/custom/ws/",
                "a.test",
                Some("https://allowed.test"),
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            configured_status(
                configured_state(true),
                "OPTIONS",
                "/xmpp-websocket",
                "a.test",
                None,
                None
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            configured_status(
                configured_state(true),
                "OPTIONS",
                "/custom/bind",
                "unknown.test",
                None,
                None
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            configured_status(
                configured_state(true),
                "OPTIONS",
                "/custom/bind",
                "a.test",
                Some("https://bad.test"),
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            configured_status(
                configured_state(false),
                "OPTIONS",
                "/custom/bind",
                "a.test",
                None,
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let context = crate::http_proxy::RequestContext {
            socket_peer: "127.0.0.1:1234".parse().unwrap(),
            peer_ip: "198.51.100.1".parse().unwrap(),
            secure: true,
        };
        let response = configured_status(
            configured_state(false),
            "OPTIONS",
            "/custom/bind",
            "a.test",
            Some("https://allowed.test"),
            Some(context),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://allowed.test"
        );
        assert_eq!(
            configured_status(
                configured_state(true),
                "GET",
                "/custom/bind",
                "a.test",
                None,
                None
            )
            .await
            .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    #[test]
    fn independent_framing() {
        assert!(from_websocket("<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test' version='1.0'/>").unwrap().starts_with("<stream:stream"));
        assert!(from_websocket("<message/>").is_err());
        assert!(from_websocket("<inactive xmlns='urn:xmpp:csi:0'/>").is_ok());
        assert!(from_websocket("<active xmlns='urn:xmpp:csi:0'/>").is_ok());
        assert!(to_websocket("<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/></stream:features>").unwrap().unwrap().contains("xmlns:stream="));
        let xml = to_websocket("<message to='a'><body>x</body></message>")
            .unwrap()
            .unwrap();
        assert_eq!(
            roxmltree::Document::parse(&xml)
                .unwrap()
                .root_element()
                .tag_name()
                .namespace(),
            Some("jabber:client")
        );
    }
    #[test]
    fn websocket_preserves_inherited_namespaces_and_spaced_declarations() {
        for input in [
            "<message xmlns = 'jabber:client'><body>hello</body></message>",
            "<stream:features><message><body>hello</body></message></stream:features>",
            "<message><body stream:test='value'>hello</body></message>",
        ] {
            let xml = to_websocket(input).unwrap().unwrap();
            let doc = roxmltree::Document::parse(&xml).unwrap();
            let body = doc.descendants().find(|n| n.has_tag_name("body")).unwrap();
            assert_eq!(body.tag_name().namespace(), Some("jabber:client"));
            if input.contains("stream:test") {
                assert_eq!(
                    body.attribute(("http://etherx.jabber.org/streams", "test")),
                    Some("value")
                );
            }
        }
    }
    #[tokio::test]
    async fn bosh_processing_capacity_is_bounded() {
        let requests = Arc::new(tokio::sync::Semaphore::new(256));
        let _occupied = requests.clone().acquire_many_owned(256).await.unwrap();
        let state = BoshState {
            handler: Arc::new(|_| Box::pin(async { panic!("must not create a session") })),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            requests,
            context_handler: None,
        };
        let response = bosh(State(state), Bytes::from_static(b"<body/>")).await;
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert!(
            std::str::from_utf8(&bytes)
                .unwrap()
                .contains("resource-constraint")
        );
    }
}

use axum::{body::Bytes, routing::post};
use std::{
    collections::{BTreeMap, HashSet},
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Notify, mpsc};
const BOSH: &str = "http://jabber.org/protocol/httpbind";
struct Sequence {
    next: u64,
    pending: HashSet<u64>,
    responses: BTreeMap<u64, String>,
}
struct BoshSession {
    domain: String,
    wait: u64,
    sequence: Mutex<Sequence>,
    changed: Notify,
    poll_wakeup: Notify,
    writer: Mutex<tokio::io::WriteHalf<DuplexStream>>,
    output: Mutex<mpsc::Receiver<String>>,
    last: std::sync::Mutex<Instant>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    engine_done: Arc<Notify>,
}
impl Drop for BoshSession {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
#[derive(Clone)]
struct BoshState {
    handler: ConnectionHandler,
    context_handler: Option<ContextConnectionHandler>,
    sessions: Arc<Mutex<BTreeMap<String, Arc<BoshSession>>>>,
    requests: Arc<tokio::sync::Semaphore>,
}
fn new_bosh_state(handler: ConnectionHandler) -> BoshState {
    let state = BoshState {
        handler,
        context_handler: None,
        sessions: Arc::new(Mutex::new(BTreeMap::new())),
        requests: Arc::new(tokio::sync::Semaphore::new(256)),
    };
    let weak = Arc::downgrade(&state.sessions);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let Some(map) = weak.upgrade() else { break };
            map.lock()
                .await
                .retain(|_, s| s.last.lock().unwrap().elapsed() < Duration::from_secs(120));
        }
    });
    state
}
pub fn bosh_router(handler: ConnectionHandler) -> Router {
    let state = new_bosh_state(handler);
    let route = post(bosh).options(|| async { preflight("POST, OPTIONS") });
    Router::new()
        .route("/http-bind", route.clone())
        .route("/http-bind/", route)
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}
fn bosh_reply(xml: String) -> Response {
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/xml; charset=utf-8"),
            (
                axum::http::HeaderName::from_static("access-control-allow-origin"),
                "*",
            ),
        ],
        xml,
    )
        .into_response()
}
fn terminate(condition: &str) -> Response {
    bosh_reply(format!(
        "<body xmlns='{BOSH}' type='terminate' condition='{condition}'/>"
    ))
}
async fn bosh(State(state): State<BoshState>, bytes: Bytes) -> Response {
    bosh_with_context(state, bytes, None).await
}
async fn bosh_with_context(
    state: BoshState,
    bytes: Bytes,
    context: Option<crate::http_proxy::RequestContext>,
) -> Response {
    // A disconnected HTTP client must not cancel stanza processing or leave a
    // pending RID without its cached response. A retry uses that same response.
    let Ok(permit) = state.requests.clone().try_acquire_owned() else {
        return terminate("resource-constraint");
    };
    match tokio::spawn(async move {
        let _permit = permit;
        bosh_request(state, bytes, context).await
    })
    .await
    {
        Ok(response) => response,
        Err(_) => terminate("remote-connection-failed"),
    }
}
async fn bosh_request(
    state: BoshState,
    bytes: Bytes,
    context: Option<crate::http_proxy::RequestContext>,
) -> Response {
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return terminate("bad-request");
    };
    let Ok(doc) = roxmltree::Document::parse(text) else {
        return terminate("bad-request");
    };
    let body = doc.root_element();
    if body.tag_name().name() != "body" || body.tag_name().namespace() != Some(BOSH) {
        return terminate("bad-request");
    };
    let Some(rid) = body
        .attribute("rid")
        .and_then(|r| r.parse::<u64>().ok())
        .filter(|r| *r < 9_007_199_254_740_991)
    else {
        return terminate("bad-request");
    };
    let initial = body.attribute("sid").is_none();
    let sid = body
        .attribute("sid")
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
    let session = if initial {
        let Some(domain) = body.attribute("to").filter(|v| !v.is_empty()) else {
            return terminate("improper-addressing");
        };
        if body
            .attribute("hold")
            .and_then(|h| h.parse::<u64>().ok())
            .unwrap_or(1)
            > 1
        {
            return terminate("policy-violation");
        }
        let wait = body
            .attribute("wait")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30)
            .clamp(1, 60);
        let (internal, external) = tokio::io::duplex(256 * 1024);
        let engine_done = Arc::new(Notify::new());
        let done = engine_done.clone();
        let handler = if let Some(handler) = &state.context_handler {
            handler(internal, context)
        } else {
            (state.handler)(internal)
        };
        let engine = tokio::spawn(async move {
            handler.await;
            done.notify_one();
        });
        let (mut read, write) = tokio::io::split(external);
        let (tx, rx) = mpsc::channel(128);
        let pump = tokio::spawn(async move {
            let mut framer = Framer::default();
            while let Ok(frame) = framer.next(&mut read).await {
                if frame.starts_with("<?xml") || frame.starts_with("<stream:stream ") {
                    continue;
                }
                if frame == "</stream:stream>" {
                    break;
                }
                let Ok(Some(xml)) = to_websocket(&frame) else {
                    break;
                };
                if tx.send(xml).await.is_err() {
                    break;
                }
            }
        });
        let session = Arc::new(BoshSession {
            domain: domain.into(),
            wait,
            sequence: Mutex::new(Sequence {
                next: rid,
                pending: HashSet::new(),
                responses: BTreeMap::new(),
            }),
            changed: Notify::new(),
            poll_wakeup: Notify::new(),
            writer: Mutex::new(write),
            output: Mutex::new(rx),
            last: std::sync::Mutex::new(Instant::now()),
            tasks: vec![engine, pump],
            engine_done,
        });
        let mut map = state.sessions.lock().await;
        if map.len() >= 4096 {
            return terminate("resource-constraint");
        }
        map.insert(sid.clone(), session.clone());
        session
    } else {
        let map = state.sessions.lock().await;
        let Some(session) = map.get(&sid) else {
            return terminate("item-not-found");
        };
        session.clone()
    };
    *session.last.lock().unwrap() = Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(90),
        process_bosh_request(&state, body, rid, initial, &sid, &session),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => {
            state.sessions.lock().await.remove(&sid);
            for task in &session.tasks {
                task.abort();
            }
            terminate("remote-connection-failed")
        }
    }
}
async fn process_bosh_request(
    state: &BoshState,
    body: roxmltree::Node<'_, '_>,
    rid: u64,
    initial: bool,
    sid: &str,
    session: &BoshSession,
) -> Response {
    // A cached RID must never replay its stanzas. Two outstanding requests are allowed.
    let reorder_deadline = Instant::now() + Duration::from_secs(5);
    let mut seq = loop {
        let seq = session.sequence.lock().await;
        if rid <= seq.next {
            break seq;
        }
        if rid > seq.next.saturating_add(1) || Instant::now() >= reorder_deadline {
            return terminate("item-not-found");
        }
        drop(seq);
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    if let Some(cached) = seq.responses.get(&rid) {
        return bosh_reply(cached.clone());
    }
    if seq.pending.contains(&rid) {
        drop(seq);
        let deadline = Instant::now() + Duration::from_secs(session.wait + 5);
        loop {
            let notified = session.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(cached) = session.sequence.lock().await.responses.get(&rid).cloned() {
                return bosh_reply(cached);
            }
            if tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), notified)
                .await
                .is_err()
            {
                return terminate("remote-connection-failed");
            }
        }
    }
    if rid != seq.next || seq.pending.len() >= 2 {
        return terminate("item-not-found");
    };
    seq.pending.insert(rid);
    if seq.pending.len() > 1 {
        session.poll_wakeup.notify_one();
    }
    seq.next += 1;
    let mut writer = session.writer.lock().await;
    drop(seq);
    let mut input = String::new();
    if initial || body.attribute(("urn:xmpp:xbosh", "restart")) == Some("true") {
        input.push_str(&format!("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='{}' version='1.0'>",escape(&session.domain)));
    }
    for node in body.children().filter(|n| n.is_element()) {
        input.push_str(&crate::protocol::xml(node));
    }
    let closing = body.attribute("type") == Some("terminate");
    if closing {
        input.push_str("</stream:stream>");
    }
    if writer.write_all(input.as_bytes()).await.is_err() {
        state.sessions.lock().await.remove(sid);
        return terminate("remote-connection-failed");
    }
    drop(writer);
    let mut payload = String::new();
    if closing {
        // Let the engine consume the stream close and run graceful cleanup before
        // removing the session: dropping it aborts the engine task. In particular,
        // a reconnect must not race with the old resource remaining registered.
        let mut rx = session.output.lock().await;
        let _ = tokio::time::timeout(Duration::from_secs(session.wait), async {
            while let Some(frame) = rx.recv().await {
                payload.push_str(&frame);
            }
            session.engine_done.notified().await;
        })
        .await;
    } else {
        let mut rx = session.output.lock().await;
        match tokio::select! { v=tokio::time::timeout(Duration::from_secs(session.wait), rx.recv())=>v, _=session.poll_wakeup.notified()=>Ok(Some(String::new())) }
        {
            Ok(Some(first)) => {
                payload.push_str(&first);
                while let Ok(next) = rx.try_recv() {
                    payload.push_str(&next);
                }
            }
            Ok(None) => {
                state.sessions.lock().await.remove(sid);
                return terminate("remote-stream-error");
            }
            Err(_) => {}
        }
    }
    let extra = if initial {
        format!(
            " sid='{sid}' wait='{}' hold='1' requests='2' inactivity='120' polling='1' ver='1.11' from='{}' xmlns:xmpp='urn:xmpp:xbosh' xmpp:version='1.0'",
            session.wait,
            escape(&session.domain)
        )
    } else if closing {
        " type='terminate'".into()
    } else {
        String::new()
    };
    let result = format!("<body xmlns='{BOSH}'{extra}>{payload}</body>");
    let mut seq = session.sequence.lock().await;
    seq.pending.remove(&rid);
    seq.responses.insert(rid, result.clone());
    while seq.responses.len() > 4 {
        seq.responses.pop_first();
    }
    drop(seq);
    session.changed.notify_waiters();
    if closing {
        state.sessions.lock().await.remove(sid);
    }
    bosh_reply(result)
}
/// Apply the exact configured origin allowlist; requests without Origin remain usable by native clients.
pub fn with_origins(router: Router, origins: Vec<String>) -> Router {
    let origins = Arc::new(origins);
    router.layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let origins = origins.clone();
            async move {
                let origin = req.headers().get(axum::http::header::ORIGIN).cloned();
                if let Some(origin) = &origin
                    && !origin
                        .to_str()
                        .ok()
                        .is_some_and(|o| origins.iter().any(|a| a == o || a == "*"))
                {
                    return StatusCode::FORBIDDEN.into_response();
                }
                let mut response = next.run(req).await;
                response
                    .headers_mut()
                    .remove(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN);
                if let Some(origin) = origin {
                    response
                        .headers_mut()
                        .insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                    response.headers_mut().append(
                        axum::http::header::VARY,
                        axum::http::HeaderValue::from_static("Origin"),
                    );
                }
                response
            }
        },
    ))
}
