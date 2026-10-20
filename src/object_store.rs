//! Path-style S3-compatible storage with authenticated, bounded multipart writes.
use anyhow::{Result, ensure};
use axum::{
    body::{Body, Bytes},
    http::{Request, Response, Uri},
};
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full, Limited};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, pki_types::ServerName},
};

#[derive(Clone, Default)]
pub enum UploadBackendConfig {
    #[default]
    Local,
    S3(S3Config),
}
// Deliberately no Debug implementation: credentials must never enter diagnostics.
#[derive(Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub key_prefix: String,
}
#[derive(Clone)]
pub struct ObjectStore {
    config: S3Config,
    endpoint: Uri,
    tls: Option<Arc<ClientConfig>>,
    uploads: Arc<tokio::sync::Semaphore>,
}
trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
fn decode_key(value: &str) -> Result<String> {
    let mut bytes = value.bytes();
    let mut decoded = Vec::with_capacity(value.len());
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = bytes.next().and_then(|v| (v as char).to_digit(16));
            let low = bytes.next().and_then(|v| (v as char).to_digit(16));
            match (high, low) {
                (Some(h), Some(l)) => decoded.push((h * 16 + l) as u8),
                _ => anyhow::bail!("invalid S3 listing key encoding"),
            }
        } else {
            decoded.push(byte);
        }
    }
    Ok(String::from_utf8(decoded)?)
}
fn mac(key: &[u8], data: &str) -> Vec<u8> {
    let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
    h.update(data.as_bytes());
    h.finalize().into_bytes().to_vec()
}
impl ObjectStore {
    pub fn new(config: S3Config) -> Result<Self> {
        let endpoint: Uri = config
            .endpoint
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid S3 endpoint"))?;
        let scheme = endpoint.scheme_str().unwrap_or("");
        let host = endpoint.host().unwrap_or("").trim_matches(['[', ']']);
        ensure!(
            !host.is_empty()
                && endpoint.query().is_none()
                && crate::http_config::valid_authority(endpoint.authority().unwrap())
                && !config.endpoint.contains('#')
                && !endpoint.path().contains('%')
                && !endpoint.path().split('/').any(|p| p == "." || p == ".."),
            "invalid S3 endpoint"
        );
        ensure!(
            scheme == "https"
                || (scheme == "http"
                    && (host == "localhost"
                        || host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|a| a.is_loopback()))),
            "S3 endpoint requires HTTPS (HTTP is allowed only for loopback)"
        );
        ensure!(
            !config.bucket.is_empty()
                && config
                    .bucket
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
            "invalid S3 bucket"
        );
        ensure!(
            !config.region.is_empty()
                && !config.access_key.is_empty()
                && !config.secret_key.is_empty(),
            "S3 credentials and region are required"
        );
        let tls = if scheme == "https" {
            let roots = crate::federation::Federation::native_roots()?;
            Some(Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ))
        } else {
            None
        };
        Ok(Self {
            config,
            endpoint,
            tls,
            uploads: Arc::new(tokio::sync::Semaphore::new(8)),
        })
    }
    pub fn identity(&self) -> serde_json::Value {
        serde_json::json!({"backend":"s3", "endpoint":self.config.endpoint.trim_end_matches('/'), "bucket":self.config.bucket, "prefix":self.config.key_prefix.trim_matches('/')})
    }
    fn path(&self, id: &str) -> String {
        let key = [self.config.key_prefix.trim_matches('/'), id]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        format!(
            "{}/{}/{}",
            self.endpoint.path().trim_end_matches('/'),
            encode(&self.config.bucket),
            key.split('/').map(encode).collect::<Vec<_>>().join("/")
        )
    }
    async fn request(
        &self,
        method: &str,
        id: &str,
        query: &[(&str, &str)],
        body: Bytes,
        extra: &[(&str, &str)],
    ) -> Result<Response<hyper::body::Incoming>> {
        // A deadline includes DNS, TLS, request transmission and response headers.
        tokio::time::timeout(
            Duration::from_secs(120),
            self.request_inner(method, self.path(id), query, body, extra),
        )
        .await
        .map_err(|_| anyhow::anyhow!("S3 request timed out"))?
    }
    async fn request_inner(
        &self,
        method: &str,
        path: String,
        query: &[(&str, &str)],
        body: Bytes,
        extra: &[(&str, &str)],
    ) -> Result<Response<hyper::body::Incoming>> {
        let host = self.endpoint.host().unwrap().trim_matches(['[', ']']);
        let authority = self.endpoint.authority().unwrap().as_str();
        let port = self
            .endpoint
            .port_u16()
            .unwrap_or(if self.tls.is_some() { 443 } else { 80 });
        let mut query: Vec<_> = query.iter().map(|(k, v)| (encode(k), encode(v))).collect();
        query.sort();
        let query = query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let uri = if query.is_empty() {
            path.clone()
        } else {
            format!("{path}?{query}")
        };
        let date = chrono::Utc::now();
        let stamp = date.format("%Y%m%dT%H%M%SZ").to_string();
        let day = date.format("%Y%m%d").to_string();
        let hash = hex::encode(Sha256::digest(&body));
        let mut headers = BTreeMap::from([
            ("host".to_string(), authority.to_string()),
            ("x-amz-content-sha256".into(), hash.clone()),
            ("x-amz-date".into(), stamp.clone()),
        ]);
        if let Some(token) = &self.config.session_token {
            headers.insert("x-amz-security-token".into(), token.clone());
        }
        let signed = headers.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical_headers = headers
            .iter()
            .map(|(k, v)| {
                format!(
                    "{k}:{}\n",
                    v.split_whitespace().collect::<Vec<_>>().join(" ")
                )
            })
            .collect::<String>();
        let canonical = format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{hash}");
        let scope = format!("{day}/{}/s3/aws4_request", self.config.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let key = mac(format!("AWS4{}", self.config.secret_key).as_bytes(), &day);
        let key = mac(&key, &self.config.region);
        let key = mac(&key, "s3");
        let key = mac(&key, "aws4_request");
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
            self.config.access_key,
            hex::encode(mac(&key, &to_sign))
        );
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", auth)
            .header("content-length", body.len());
        for (k, v) in &headers {
            req = req.header(k, v);
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        let req = req.body(Full::new(body))?;
        let tcp = TcpStream::connect((host, port)).await?;
        let stream: Box<dyn Transport> = if let Some(tls) = &self.tls {
            Box::new(
                TlsConnector::from(tls.clone())
                    .connect(ServerName::try_from(host.to_string())?, tcp)
                    .await?,
            )
        } else {
            Box::new(tcp)
        };
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender.send_request(req).await?)
    }
    async fn xml(response: Response<hyper::body::Incoming>) -> Result<String> {
        ensure!(response.status().is_success(), "S3 operation failed");
        Self::xml_unchecked(response).await
    }
    async fn xml_unchecked(response: Response<hyper::body::Incoming>) -> Result<String> {
        let bytes = tokio::time::timeout(
            Duration::from_secs(120),
            Limited::new(response.into_body(), 1024 * 1024).collect(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("S3 response timed out"))?
        .map_err(|_| anyhow::anyhow!("invalid or oversized S3 response"))?
        .to_bytes();
        Ok(String::from_utf8(bytes.to_vec())?)
    }
    pub async fn begin(&self, id: &str, content_type: &str) -> Result<Multipart> {
        // Shield initiation: cancellation must still consume UploadId and abort it.
        let store = self.clone();
        let id = id.to_owned();
        let content_type = content_type.to_owned();
        tokio::spawn(async move { store.begin_inner(&id, &content_type).await }).await?
    }
    async fn begin_inner(&self, id: &str, content_type: &str) -> Result<Multipart> {
        let permit = self
            .uploads
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("S3 uploads busy"))?;
        let r = self
            .request(
                "POST",
                id,
                &[("uploads", "")],
                Bytes::new(),
                &[("content-type", content_type)],
            )
            .await?;
        let xml = Self::xml(r).await?;
        let doc = roxmltree::Document::parse(&xml)?;
        let upload_id = doc
            .descendants()
            .find(|n| n.has_tag_name("UploadId"))
            .and_then(|n| n.text())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("S3 upload identifier missing"))?
            .to_string();
        Ok(Multipart {
            store: self.clone(),
            id: id.into(),
            upload_id,
            etags: Vec::new(),
            finished: false,
            after_abort: None,
            _permit: permit,
        })
    }
    pub async fn read(&self, id: &str, head: bool, range: Option<&str>) -> Result<Response<Body>> {
        let extra: Vec<_> = range.map(|r| vec![("range", r)]).unwrap_or_default();
        let r = self
            .request(
                if head { "HEAD" } else { "GET" },
                id,
                &[],
                Bytes::new(),
                &extra,
            )
            .await?;
        let (parts, body) = r.into_parts();
        Ok(Response::from_parts(
            parts,
            if head { Body::empty() } else { Body::new(body) },
        ))
    }
    /// Abort only multiparts for an exclusively owned, durable slot key. The
    /// caller must exclude concurrent initiation for this key throughout recovery.
    /// Listing a prefix alone does not establish ownership: compare the full key.
    pub async fn abort_pending(&self, id: &str) -> Result<()> {
        let key = [self.config.key_prefix.trim_matches('/'), id]
            .into_iter()
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        let bucket_path = format!(
            "{}/{}",
            self.endpoint.path().trim_end_matches('/'),
            encode(&self.config.bucket)
        );
        let mut markers: Option<(String, String)> = None;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let mut query = vec![
                ("uploads", ""),
                ("prefix", key.as_str()),
                ("max-uploads", "1000"),
                ("encoding-type", "url"),
            ];
            if let Some((key_marker, upload_marker)) = &markers {
                query.push(("key-marker", key_marker));
                query.push(("upload-id-marker", upload_marker));
            }
            let response = tokio::time::timeout(
                Duration::from_secs(120),
                self.request_inner("GET", bucket_path.clone(), &query, Bytes::new(), &[]),
            )
            .await
            .map_err(|_| anyhow::anyhow!("S3 listing timed out"))??;
            let xml = Self::xml(response).await?;
            let doc = roxmltree::Document::parse(&xml)?;
            let root = doc.root_element();
            ensure!(
                root.has_tag_name("ListMultipartUploadsResult"),
                "invalid S3 multipart listing"
            );
            let field = |node: roxmltree::Node<'_, '_>, name: &str| {
                node.children()
                    .find(|n| n.has_tag_name(name))
                    .and_then(|n| n.text())
                    .map(str::to_owned)
            };
            for upload in root.children().filter(|n| n.has_tag_name("Upload")) {
                let listed_key = field(upload, "Key")
                    .ok_or_else(|| anyhow::anyhow!("S3 listing key missing"))?;
                let upload_id = field(upload, "UploadId")
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("S3 listing upload identifier missing"))?;
                if decode_key(&listed_key)? == key {
                    self.abort(id, &upload_id).await?;
                }
            }
            match field(root, "IsTruncated").as_deref() {
                Some("false") => break,
                Some("true") => {
                    let next = (
                        decode_key(
                            &field(root, "NextKeyMarker")
                                .ok_or_else(|| anyhow::anyhow!("S3 listing marker missing"))?,
                        )?,
                        field(root, "NextUploadIdMarker")
                            .ok_or_else(|| anyhow::anyhow!("S3 listing upload marker missing"))?,
                    );
                    ensure!(
                        !next.0.is_empty()
                            && !next.1.is_empty()
                            && markers.as_ref().is_none_or(|previous| &next > previous)
                            && seen.insert(next.clone()),
                        "S3 listing did not advance"
                    );
                    markers = Some(next);
                }
                _ => anyhow::bail!("invalid S3 listing truncation flag"),
            }
        }
        Ok(())
    }
    /// HEAD with an explicit distinction between absence and service errors.
    pub async fn stat(&self, id: &str) -> Result<Option<u64>> {
        let reply = self.read(id, true, None).await?;
        if reply.status() == 404 {
            return Ok(None);
        }
        ensure!(reply.status() == 200, "S3 stat failed");
        let size = reply
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("S3 object size missing"))?;
        Ok(Some(size))
    }
    /// Bounded-memory streaming upload. Callers journal ownership before calling
    /// this method and retain it until commit, allowing abort_pending after crash.
    pub async fn write_stream(
        &self,
        id: &str,
        content_type: &str,
        mut body: Body,
        expected_size: u64,
    ) -> Result<()> {
        let mut upload = self.begin(id, content_type).await?;
        let mut count = 0u64;
        let mut part = Vec::with_capacity(PART_SIZE);
        while let Some(frame) = tokio::time::timeout(Duration::from_secs(120), body.frame())
            .await
            .map_err(|_| anyhow::anyhow!("S3 source timed out"))?
        {
            let frame = frame.map_err(|_| anyhow::anyhow!("S3 source read failed"))?;
            if let Ok(bytes) = frame.into_data() {
                count = count
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| anyhow::anyhow!("S3 source too large"))?;
                ensure!(count <= expected_size, "S3 source too large");
                let mut bytes = bytes.as_ref();
                while !bytes.is_empty() {
                    let take = (PART_SIZE - part.len()).min(bytes.len());
                    part.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if part.len() == PART_SIZE {
                        upload
                            .part(std::mem::replace(&mut part, Vec::with_capacity(PART_SIZE)))
                            .await?;
                    }
                }
            }
        }
        ensure!(count == expected_size, "S3 source size mismatch");
        if !part.is_empty() || count == 0 {
            upload.part(part).await?;
        }
        upload.complete().await
    }
    pub async fn copy_from(
        &self,
        source: &ObjectStore,
        id: &str,
        content_type: &str,
        expected_size: u64,
    ) -> Result<()> {
        let reply = source.read(id, false, None).await?;
        ensure!(reply.status() == 200, "S3 copy source unavailable");
        self.write_stream(id, content_type, reply.into_body(), expected_size)
            .await
    }
    pub async fn abort(&self, id: &str, upload_id: &str) -> Result<()> {
        let r = self
            .request("DELETE", id, &[("uploadId", upload_id)], Bytes::new(), &[])
            .await?;
        ensure!(
            r.status().is_success() || r.status() == 404,
            "S3 multipart abort failed"
        );
        Ok(())
    }
    pub async fn delete(&self, id: &str) -> Result<()> {
        let r = self.request("DELETE", id, &[], Bytes::new(), &[]).await?;
        ensure!(
            r.status().is_success() || r.status() == 404,
            "S3 deletion failed"
        );
        Ok(())
    }
}
/// A well-formed terminal rejection from CompleteMultipartUpload. Transport,
/// timeout and malformed response errors deliberately do not carry this marker.
#[derive(Debug)]
pub struct CompletionRejected;
impl std::fmt::Display for CompletionRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S3 completion rejected")
    }
}
impl std::error::Error for CompletionRejected {}
pub const PART_SIZE: usize = 8 * 1024 * 1024;
pub struct Multipart {
    store: ObjectStore,
    id: String,
    upload_id: String,
    etags: Vec<String>,
    finished: bool,
    after_abort: Option<Box<dyn FnOnce() + Send>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl Multipart {
    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }
    pub fn after_abort(&mut self, callback: impl FnOnce() + Send + 'static) {
        self.after_abort = Some(Box::new(callback));
    }
    pub async fn part(&mut self, data: Vec<u8>) -> Result<()> {
        ensure!(self.etags.len() < 10000, "S3 part limit exceeded");
        let number = (self.etags.len() + 1).to_string();
        let r = self
            .store
            .request(
                "PUT",
                &self.id,
                &[("partNumber", &number), ("uploadId", &self.upload_id)],
                Bytes::from(data),
                &[],
            )
            .await?;
        ensure!(r.status().is_success(), "S3 part failed");
        let etag = r
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("S3 part ETag missing"))?
            .to_string();
        self.etags.push(etag);
        Ok(())
    }
    pub async fn complete(mut self) -> Result<()> {
        let mut xml = "<CompleteMultipartUpload>".to_string();
        for (i, etag) in self.etags.iter().enumerate() {
            xml.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
                i + 1,
                crate::wire::escape(etag)
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let r = self
            .store
            .request(
                "POST",
                &self.id,
                &[("uploadId", &self.upload_id)],
                Bytes::from(xml),
                &[("content-type", "application/xml"), ("if-none-match", "*")],
            )
            .await?;
        let successful = r.status().is_success();
        let xml = ObjectStore::xml_unchecked(r).await?;
        let doc = roxmltree::Document::parse(&xml)?;
        if doc.root_element().has_tag_name("Error") {
            return Err(CompletionRejected.into());
        }
        ensure!(successful, "S3 completion failed");
        ensure!(
            doc.root_element()
                .has_tag_name("CompleteMultipartUploadResult"),
            "S3 completion failed"
        );
        self.finished = true;
        Ok(())
    }
}
impl Drop for Multipart {
    fn drop(&mut self) {
        if !self.finished {
            let store = self.store.clone();
            let id = self.id.clone();
            let upload_id = self.upload_id.clone();
            let after_abort = self.after_abort.take();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    if store.abort(&id, &upload_id).await.is_ok()
                        && let Some(callback) = after_abort
                    {
                        callback();
                    }
                });
            }
        }
    }
}
