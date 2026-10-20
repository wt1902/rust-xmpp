use rust_xmpp::{
    http_service::serve_router,
    http_transport::{ConnectionHandler, bosh_router, websocket_router},
    wire::Framer,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
fn handler(count: Arc<AtomicUsize>) -> ConnectionHandler {
    Arc::new(move |mut stream| {
        let count = count.clone();
        Box::pin(async move {
            let mut f = Framer::default();
            while let Ok(xml) = f.next(&mut stream).await {
                if xml.starts_with("<stream:stream") {
                    stream.write_all(b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='example.test' id='123' version='1.0'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>").await.unwrap();
                } else if xml == "</stream:stream>" {
                    break;
                } else {
                    count.fetch_add(1, Ordering::SeqCst);
                    stream.write_all(xml.as_bytes()).await.unwrap();
                }
            }
        })
    })
}
async fn http(addr: std::net::SocketAddr, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /http-bind HTTP/1.1\r\nHost: example.test\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut bytes = vec![];
    stream.read_to_end(&mut bytes).await.unwrap();
    String::from_utf8(bytes)
        .unwrap()
        .split_once("\r\n\r\n")
        .unwrap()
        .1
        .into()
}
#[tokio::test]
async fn bosh_session_retries_restart_termination() {
    let count = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = bosh_router(handler(count.clone()));
    let task = tokio::spawn(serve_router(listener, None, app));
    let initial=http(addr,"<body xmlns='http://jabber.org/protocol/httpbind' to='example.test' rid='100' wait='1' hold='1'/>").await;
    let doc = roxmltree::Document::parse(&initial).unwrap();
    let sid = doc.root_element().attribute("sid").unwrap().to_string();
    assert!(initial.contains("mechanisms"));
    let msg = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' sid='{sid}' rid='101'><message xmlns='jabber:client'><body>hello</body></message></body>"
    );
    let response = http(addr, &msg).await;
    assert!(response.contains("hello"));
    let replay = http(addr, &msg).await;
    assert_eq!(replay, response);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let restart=http(addr,&format!("<body xmlns='http://jabber.org/protocol/httpbind' xmlns:xmpp='urn:xmpp:xbosh' sid='{sid}' rid='102' xmpp:restart='true'/>")).await;
    assert!(restart.contains("mechanisms"));
    let end=http(addr,&format!("<body xmlns='http://jabber.org/protocol/httpbind' sid='{sid}' rid='103' type='terminate'/>")).await;
    assert!(end.contains("type='terminate'"));
    task.abort();
}
async fn ws_send(s: &mut TcpStream, text: &str) {
    let bytes = text.as_bytes();
    let mut frame = vec![0x81];
    if bytes.len() < 126 {
        frame.push(0x80 | bytes.len() as u8)
    } else {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    }
    frame.extend_from_slice(&[1, 2, 3, 4]);
    frame.extend(
        bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ [1, 2, 3, 4][i % 4]),
    );
    s.write_all(&frame).await.unwrap();
}
async fn ws_read(s: &mut TcpStream) -> String {
    let mut h = [0; 2];
    s.read_exact(&mut h).await.unwrap();
    assert_eq!(h[0], 0x81);
    let n = if h[1] == 126 {
        s.read_u16().await.unwrap() as usize
    } else {
        h[1] as usize
    };
    let mut b = vec![0; n];
    s.read_exact(&mut b).await.unwrap();
    String::from_utf8(b).unwrap()
}
#[tokio::test]
async fn websocket_frames_are_independent_xml() {
    let count = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = websocket_router(handler(count.clone()));
    let task = tokio::spawn(serve_router(listener, None, app));
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /xmpp-websocket HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: xmpp\r\n\r\n").await.unwrap();
    let mut header = vec![];
    loop {
        header.push(s.read_u8().await.unwrap());
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        String::from_utf8(header)
            .unwrap()
            .starts_with("HTTP/1.1 101")
    );
    ws_send(
        &mut s,
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test' version='1.0'/>",
    )
    .await;
    let open = ws_read(&mut s).await;
    assert!(open.contains("<open"));
    let features = ws_read(&mut s).await;
    assert!(roxmltree::Document::parse(&features).is_ok());
    ws_send(
        &mut s,
        "<message xmlns='jabber:client'><body>hi</body></message>",
    )
    .await;
    let message = ws_read(&mut s).await;
    assert!(message.contains("hi"));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    drop(s);
    task.abort();
}
#[tokio::test]
async fn configured_origin_is_enforced() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = rust_xmpp::http_transport::with_origins(
        bosh_router(handler(Arc::new(AtomicUsize::new(0)))),
        vec!["https://allowed.test".into()],
    );
    let task = tokio::spawn(serve_router(listener, None, router));
    for (origin, status) in [
        ("https://evil.test", "403"),
        ("https://allowed.test", "200"),
    ] {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "OPTIONS /http-bind HTTP/1.1\r\nHost: example.test\r\nOrigin: {origin}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut result = String::new();
        stream.read_to_string(&mut result).await.unwrap();
        assert!(
            result.starts_with(&format!("HTTP/1.1 {status}")),
            "{result}"
        );
        if status == "200" {
            assert!(result.contains("access-control-allow-origin: https://allowed.test"));
        }
    }
    task.abort();
}
#[tokio::test]
async fn bosh_reorders_two_requests_without_replaying_stanzas() {
    let count = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_router(
        listener,
        None,
        bosh_router(handler(count.clone())),
    ));
    let first = http(
        addr,
        "<body xmlns='http://jabber.org/protocol/httpbind' to='example.test' rid='1' wait='1'/>",
    )
    .await;
    let doc = roxmltree::Document::parse(&first).unwrap();
    let sid = doc.root_element().attribute("sid").unwrap();
    let newer = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' sid='{sid}' rid='3'><message xmlns='jabber:client'><body>three</body></message></body>"
    );
    let older = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' sid='{sid}' rid='2'><message xmlns='jabber:client'><body>two</body></message></body>"
    );
    let a = tokio::spawn(async move { http(addr, &newer).await });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let b = http(addr, &older).await;
    let a = a.await.unwrap();
    assert!(
        !a.contains("terminate") && !b.contains("terminate"),
        "{a} {b}"
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert!(format!("{b}{a}").contains("three"));
    task.abort();
}
#[tokio::test]
async fn bosh_preserves_namespace_inherited_from_body() {
    let count = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_router(
        listener,
        None,
        bosh_router(handler(count.clone())),
    ));
    let first = http(
        addr,
        "<body xmlns='http://jabber.org/protocol/httpbind' to='example.test' rid='1' wait='1'/>",
    )
    .await;
    let doc = roxmltree::Document::parse(&first).unwrap();
    let sid = doc.root_element().attribute("sid").unwrap();
    let reply=http(addr,&format!("<body xmlns='http://jabber.org/protocol/httpbind' xmlns:c='jabber:client' sid='{sid}' rid='2'><c:message><c:body>namespaced</c:body></c:message></body>")).await;
    let parsed = roxmltree::Document::parse(&reply).unwrap();
    assert!(
        parsed
            .descendants()
            .any(|n| n.tag_name().name() == "message"
                && n.tag_name().namespace() == Some("jabber:client")),
        "{reply}"
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    task.abort();
}

async fn raw_http(addr: std::net::SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut result = String::new();
    stream.read_to_string(&mut result).await.unwrap();
    result
}

#[tokio::test]
async fn transport_paths_and_cors_preflight_match_prosody() {
    use rust_xmpp::http_transport::with_origins;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = handler(Arc::new(AtomicUsize::new(0)));
    let app = with_origins(
        bosh_router(h.clone()).merge(websocket_router(h)),
        vec!["https://wthome.ru".into()],
    );
    let task = tokio::spawn(serve_router(listener, None, app));
    for path in [
        "/http-bind",
        "/http-bind/",
        "/xmpp-websocket",
        "/xmpp-websocket/",
    ] {
        let result = raw_http(addr, &format!(
            "OPTIONS {path} HTTP/1.1\r\nHost: example.test\r\nOrigin: https://wthome.ru\r\nAccess-Control-Request-Method: {}\r\nAccess-Control-Request-Headers: Content-Type\r\nConnection: close\r\n\r\n",
            if path.starts_with("/http-bind") { "POST" } else { "GET" }
        )).await;
        assert!(result.starts_with("HTTP/1.1 200"), "{path}: {result}");
        assert!(
            result.contains("access-control-allow-origin: https://wthome.ru"),
            "{result}"
        );
        assert!(
            result
                .to_ascii_lowercase()
                .contains("access-control-allow-headers: content-type"),
            "{result}"
        );
    }
    let body =
        "<body xmlns='http://jabber.org/protocol/httpbind' to='example.test' rid='100' wait='1'/>";
    let result = raw_http(addr, &format!(
        "POST /http-bind/ HTTP/1.1\r\nHost: example.test\r\nOrigin: https://wthome.ru\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
    )).await;
    assert!(
        result.starts_with("HTTP/1.1 200") && result.contains("mechanisms"),
        "{result}"
    );
    task.abort();
}

#[tokio::test]
async fn bosh_retry_survives_aborted_http_request_without_replaying_stanzas() {
    use tokio::sync::Notify;
    let seen = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let count = Arc::new(AtomicUsize::new(0));
    let h: ConnectionHandler = {
        let seen = seen.clone();
        let release = release.clone();
        let count = count.clone();
        Arc::new(move |mut stream| {
            let seen = seen.clone();
            let release = release.clone();
            let count = count.clone();
            Box::pin(async move {
                let mut f = Framer::default();
                while let Ok(xml) = f.next(&mut stream).await {
                    if xml.starts_with("<stream:stream") {
                        stream.write_all(b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='example.test' version='1.0'><stream:features/>").await.unwrap();
                    } else {
                        count.fetch_add(1, Ordering::SeqCst);
                        seen.notify_one();
                        release.notified().await;
                        stream.write_all(xml.as_bytes()).await.unwrap();
                    }
                }
            })
        })
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_router(listener, None, bosh_router(h)));
    let initial = http(
        addr,
        "<body xmlns='http://jabber.org/protocol/httpbind' to='example.test' rid='1' wait='1'/>",
    )
    .await;
    let doc = roxmltree::Document::parse(&initial).unwrap();
    let sid = doc.root_element().attribute("sid").unwrap();
    let body = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' sid='{sid}' rid='2'><message xmlns='jabber:client'><body>once</body></message></body>"
    );
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(format!("POST /http-bind HTTP/1.1\r\nHost: example.test\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), seen.notified())
        .await
        .unwrap();
    socket2::SockRef::from(&stream)
        .set_linger(Some(std::time::Duration::ZERO))
        .unwrap();
    drop(stream);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let retry_body = body.clone();
    let retry = tokio::spawn(async move { http(addr, &retry_body).await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    release.notify_one();
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), retry)
        .await
        .expect("retry must receive the original response even after HTTP disconnect")
        .unwrap();
    assert!(
        result.contains("once") && !result.contains("terminate"),
        "{result}"
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(http(addr, &body).await, result);
    task.abort();
}

#[tokio::test]
async fn bosh_termination_waits_for_graceful_cleanup_before_reconnect() {
    let cleaned = Arc::new(AtomicUsize::new(0));
    let h: ConnectionHandler = {
        let cleaned = cleaned.clone();
        Arc::new(move |mut stream| {
            let cleaned = cleaned.clone();
            Box::pin(async move {
                let mut framer = Framer::default();
                while let Ok(xml) = framer.next(&mut stream).await {
                    if xml.starts_with("<stream:stream") {
                        stream.write_all(b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='example.test' version='1.0'><stream:features/>").await.unwrap();
                    } else if xml == "</stream:stream>" {
                        stream.write_all(b"</stream:stream>").await.unwrap();
                        // The stream response can arrive before backend cleanup ends.
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        cleaned.fetch_add(1, Ordering::SeqCst);
                        break;
                    }
                }
            })
        })
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_router(listener, None, bosh_router(h)));
    let initial = http(
        addr,
        "<body xmlns='http://jabber.org/protocol/httpbind' to='example.test' rid='1' wait='1'/>",
    )
    .await;
    let doc = roxmltree::Document::parse(&initial).unwrap();
    let sid = doc.root_element().attribute("sid").unwrap();
    let end = http(addr, &format!("<body xmlns='http://jabber.org/protocol/httpbind' sid='{sid}' rid='2' type='terminate'/>")).await;
    assert!(end.contains("type='terminate'"), "{end}");
    assert_eq!(
        cleaned.load(Ordering::SeqCst),
        1,
        "termination must finish graceful backend cleanup before acknowledging the client"
    );
    let reconnected = http(
        addr,
        "<body xmlns='http://jabber.org/protocol/httpbind' to='example.test' rid='10' wait='1'/>",
    )
    .await;
    assert!(reconnected.contains("sid="), "{reconnected}");
    task.abort();
}

async fn websocket_cleanup(explicit_close: bool) {
    let cleaned = Arc::new(tokio::sync::Notify::new());
    let outcome = Arc::new(AtomicUsize::new(0));
    let h: ConnectionHandler = {
        let cleaned = cleaned.clone();
        let outcome = outcome.clone();
        Arc::new(move |mut stream| {
            let cleaned = cleaned.clone();
            let outcome = outcome.clone();
            Box::pin(async move {
                let mut graceful = false;
                let mut f = Framer::default();
                while let Ok(xml) = f.next(&mut stream).await {
                    if xml.starts_with("<stream:stream") {
                        stream.write_all(b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='example.test' version='1.0'><stream:features/>").await.unwrap();
                    } else if xml == "</stream:stream>" {
                        graceful = true;
                        break;
                    }
                }
                // Simulate cleanup that yields after receiving close or EOF.
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                outcome.store(if graceful { 1 } else { 2 }, Ordering::SeqCst);
                cleaned.notify_one();
            })
        })
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_router(listener, None, websocket_router(h)));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /xmpp-websocket HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: xmpp\r\n\r\n").await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(stream.read_u8().await.unwrap());
    }
    ws_send(
        &mut stream,
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test' version='1.0'/>",
    )
    .await;
    ws_read(&mut stream).await;
    ws_read(&mut stream).await;
    if explicit_close {
        ws_send(
            &mut stream,
            "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>",
        )
        .await;
        // Follow the XMPP close immediately with a masked WebSocket close frame.
        stream.write_all(&[0x88, 0x80, 0, 0, 0, 0]).await.unwrap();
    }
    drop(stream);
    tokio::time::timeout(std::time::Duration::from_secs(2), cleaned.notified())
        .await
        .expect("transport must let the engine finish cleanup");
    assert_eq!(
        outcome.load(Ordering::SeqCst),
        if explicit_close { 1 } else { 2 }
    );
    task.abort();
}

#[tokio::test]
async fn websocket_close_allows_graceful_engine_cleanup() {
    websocket_cleanup(true).await;
}

#[tokio::test]
async fn websocket_disconnect_delivers_eof_without_graceful_close() {
    websocket_cleanup(false).await;
}
