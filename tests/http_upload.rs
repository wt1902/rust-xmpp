use rust_xmpp::http_service::{UploadConfig, UploadService};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
async fn request(addr: std::net::SocketAddr, text: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(text.as_bytes()).await.unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).to_string()
}
#[tokio::test]
async fn upload_authorization_streaming_ranges_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = UploadConfig {
        root: temp.path().into(),
        host: "upload.example.test".into(),
        base_url: format!("http://{addr}/file_share"),
        size_limit: 10 * 1024 * 1024 * 1024,
        daily_quota: 100,
        global_quota: 100,
        expires_after: None,
        secret: Some("test-secret".into()),
        allowed_types: vec![],
    };
    let service = UploadService::new(cfg.clone()).unwrap();
    assert!(
        service
            .request_slot("a@example.test", "../secret", 5, "text/plain")
            .is_err()
    );
    assert!(
        service
            .request_slot("a@example.test", "foo\\bar", 5, "text/plain")
            .is_err()
    );
    let slot = service
        .request_slot("a@example.test", "hello.txt", 5, "text/plain")
        .unwrap();
    let path = slot
        .url
        .strip_prefix(&format!("http://{addr}"))
        .unwrap()
        .to_string();
    let serving = service.clone();
    let task = tokio::spawn(async move { serving.serve(listener, None).await.unwrap() });
    let unauthorized=request(addr,&format!("PUT {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")).await;
    assert!(unauthorized.starts_with("HTTP/1.1 403"), "{unauthorized}");
    let oversized=request(addr,&format!("PUT {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {}\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello!",slot.authorization)).await;
    assert!(oversized.starts_with("HTTP/1.1 413"));
    let oversized_chunked=request(addr,&format!("PUT {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nhello!\r\n0\r\n\r\n",slot.authorization)).await;
    assert!(oversized_chunked.starts_with("HTTP/1.1 413"));
    let short_chunked=request(addr,&format!("PUT {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nhell\r\n0\r\n\r\n",slot.authorization)).await;
    assert!(short_chunked.starts_with("HTTP/1.1 400"));
    let authorization = slot.authorization.replacen("Bearer ", "bEaReR ", 1);
    let uploaded=request(addr,&format!("PUT {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n",authorization)).await;
    assert!(uploaded.starts_with("HTTP/1.1 201"), "{uploaded}");
    let again=request(addr,&format!("PUT {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",slot.authorization)).await;
    assert!(again.starts_with("HTTP/1.1 409"));
    let get = request(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(
        get.starts_with("HTTP/1.1 200") && get.ends_with("hello"),
        "{get}"
    );
    let range = request(
        addr,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nRange: bytes=1-3\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(range.starts_with("HTTP/1.1 206") && range.ends_with("ell"));
    let beyond_eof = request(
        addr,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nRange: bytes=1-999\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(
        beyond_eof.starts_with("HTTP/1.1 206") && beyond_eof.ends_with("ello"),
        "{beyond_eof}"
    );
    assert!(beyond_eof.contains("content-range: bytes 1-4/5"));
    let unsatisfiable = request(
        addr,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nRange: bytes=5-999\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(unsatisfiable.starts_with("HTTP/1.1 416"));
    let traverse = request(
        addr,
        &format!("GET {path}/../../secret HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(traverse.starts_with("HTTP/1.1 404"));
    assert!(
        service
            .request_slot("a@example.test", "more", 96, "text/plain")
            .is_err()
    );
    task.abort();
    let _ = task.await;
    let restarted = UploadService::new(cfg).unwrap();
    let l = TcpListener::bind(addr).await.unwrap();
    let task = tokio::spawn(async move { restarted.serve(l, None).await.unwrap() });
    let get = request(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(get.ends_with("hello"));
    task.abort();
}
#[test]
fn expired_upload_releases_quota() {
    let temp = tempfile::tempdir().unwrap();
    let cfg = UploadConfig {
        root: temp.path().into(),
        host: "upload.example.test".into(),
        base_url: "https://example.test/file_share".into(),
        size_limit: 10,
        daily_quota: 10,
        global_quota: 10,
        expires_after: Some(0),
        secret: None,
        allowed_types: vec!["image/*".into()],
    };
    let s = UploadService::new(cfg).unwrap();
    assert!(
        s.request_slot("a@example.test", "x", 10, "text/plain")
            .is_err()
    );
    s.request_slot("a@example.test", "x", 10, "image/png")
        .unwrap();
    s.request_slot("a@example.test", "x", 10, "image/png")
        .unwrap();
}
#[tokio::test]
async fn persisted_prosody_archive_and_hs256_slot_survive_without_sidecar() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = UploadConfig {
        root: temp.path().into(),
        host: "upload.example.test".into(),
        base_url: format!("http://{addr}/file_share"),
        size_limit: 1024,
        daily_quota: 1024,
        global_quota: 1024,
        expires_after: None,
        secret: Some("shared-prosody-secret".into()),
        allowed_types: vec![],
    };
    let service = UploadService::new(config.clone()).unwrap();
    let slot = service
        .request_slot("a@example.test", "legacy.txt", 4, "text/plain")
        .unwrap();
    drop(service);
    std::fs::remove_file(
        temp.path()
            .join(rust_xmpp::storage::encode_name("upload.example.test"))
            .join("rust_uploads.json"),
    )
    .unwrap();
    let service = UploadService::new(config).unwrap();
    let task = tokio::spawn(async move { service.serve(listener, None).await.unwrap() });
    let path = slot.url.strip_prefix(&format!("http://{addr}")).unwrap();
    let result=request(addr,&format!("PUT {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {}\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",slot.authorization)).await;
    assert!(result.starts_with("HTTP/1.1 201"), "{result}");
    task.abort();
}
#[tokio::test]
async fn https_endpoint_uses_real_tls() {
    use std::io::BufReader;
    use tokio_rustls::{
        TlsAcceptor, TlsConnector,
        rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName},
    };
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("cert.pem");
    let key = temp.path().join("key.pem");
    let output = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .expect("openssl required for TLS integration test");
    assert!(output.status.success());
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(key).unwrap()))
        .unwrap()
        .unwrap();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = UploadConfig {
        root: temp.path().into(),
        host: "localhost".into(),
        base_url: format!("https://localhost:{}/file_share", addr.port()),
        size_limit: 1024,
        daily_quota: 1024,
        global_quota: 1024,
        expires_after: None,
        secret: None,
        allowed_types: vec![],
    };
    let s = UploadService::new(cfg).unwrap();
    let task = tokio::spawn(async move {
        s.serve(
            listener,
            Some(TlsAcceptor::from(std::sync::Arc::new(server))),
        )
        .await
        .unwrap()
    });
    let socket = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(std::sync::Arc::new(client))
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await
        .unwrap();
    tls.write_all(
        b"GET /file_share/missing/name HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut result = String::new();
    tls.read_to_string(&mut result).await.unwrap();
    assert!(result.starts_with("HTTP/1.1 404"));
    task.abort();
}
#[tokio::test]
async fn percent_escape_case_and_equivalent_url_spelling() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = UploadConfig {
        root: temp.path().into(),
        host: "upload.example.test".into(),
        base_url: format!("http://{addr}/file_share"),
        size_limit: 10,
        daily_quota: 100,
        global_quota: 100,
        expires_after: None,
        secret: None,
        allowed_types: vec![],
    };
    let service = UploadService::new(config).unwrap();
    let slot = service
        .request_slot("a@example.test", "фото+1.txt", 4, "text/plain")
        .unwrap();
    let path = slot
        .url
        .strip_prefix(&format!("http://{addr}"))
        .unwrap()
        .to_string();
    let task = tokio::spawn(async move { service.serve(listener, None).await.unwrap() });
    let authorization = slot.authorization.replacen("Bearer ", "bearer ", 1);
    let put=request(addr,&format!("PUT {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {}\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",authorization)).await;
    assert!(put.starts_with("HTTP/1.1 201"));
    let alternate = path.to_lowercase().replace("%2b", "+");
    let get = request(
        addr,
        &format!("GET {alternate} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(get.ends_with("data"), "{get}");
    task.abort();
}
