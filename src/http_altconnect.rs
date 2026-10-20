//! XEP-0156 host-meta discovery, matching the supplied mod_http_altconnect.
use crate::{config::Config, http_config::HttpConfig, http_transport::HttpRoute, wire::escape};
use anyhow::{Context, Result};
use axum::{
    Router,
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Link {
    pub rel: &'static str,
    pub href: String,
}
#[derive(Clone)]
struct Discovery {
    config: HttpConfig,
    xml_path: String,
    json_path: String,
    xml: String,
    json: String,
}
/// Configured values, never request Host or forwarded headers, define public URLs.
pub fn links(config: &Config, domain: &str, secure: bool, port: u16) -> Result<Vec<Link>> {
    let http = HttpConfig::for_host(config, domain)?;
    let modules = config.modules(domain)?;
    let mut links = Vec::new();
    for (module, option, rel) in [
        ("bosh", "advertise_bosh", "urn:xmpp:alt-connections:xbosh"),
        (
            "websocket",
            "advertise_websocket",
            "urn:xmpp:alt-connections:websocket",
        ),
    ] {
        let advertise = config
            .option(domain, option)
            .map(|v| {
                v.as_bool()
                    .with_context(|| format!("{option} must be boolean"))
            })
            .transpose()?
            .unwrap_or(true);
        if modules.contains(module) && advertise {
            let url = http.external_url(module, secure, port)?;
            let href = if module == "websocket" {
                url.replacen("http", "ws", 1)
            } else {
                url
            };
            links.push(Link { rel, href });
        }
    }
    Ok(links)
}
pub fn with_altconnect(
    router: Router,
    config: &Config,
    domain: &str,
    secure: bool,
    port: u16,
) -> Result<Router> {
    let http = HttpConfig::for_host(config, domain)?;
    let links = links(config, domain, secure, port)?;
    let mut xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>".to_owned();
    for link in &links {
        xml.push_str(&format!(
            "<Link rel='{}' href='{}'/>",
            link.rel,
            escape(&link.href)
        ));
    }
    xml.push_str("</XRD>");
    let state = Discovery {
        xml_path: format!("{}/host-meta", http.altconnect_path.trim_end_matches('/')),
        json_path: format!(
            "{}/host-meta.json",
            http.altconnect_path.trim_end_matches('/')
        ),
        config: http,
        xml,
        json: serde_json::to_string(&serde_json::json!({"links": links}))?,
    };
    Ok(router.layer(axum::middleware::from_fn_with_state(state, discovery)))
}
async fn discovery(State(state): State<Discovery>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path != state.xml_path && path != state.json_path {
        return next.run(req).await;
    }
    let mut response = if let Some(host) = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        if !state.config.accepts_host(host) {
            StatusCode::NOT_FOUND.into_response()
        } else if req.method() == Method::OPTIONS {
            (
                [
                    ("access-control-allow-origin", "*"),
                    ("access-control-allow-methods", "GET, HEAD, OPTIONS"),
                    ("access-control-allow-headers", "Content-Type"),
                ],
                "",
            )
                .into_response()
        } else if req.method() == Method::GET || req.method() == Method::HEAD {
            let (mime, body) = if path == state.xml_path {
                ("application/xrd+xml", state.xml)
            } else {
                ("application/json", state.json)
            };
            let len = body.len().to_string();
            (
                [
                    ("content-type", mime),
                    ("access-control-allow-origin", "*"),
                    ("content-length", len.as_str()),
                ],
                if req.method() == Method::HEAD {
                    String::new()
                } else {
                    body
                },
            )
                .into_response()
        } else {
            (
                StatusCode::METHOD_NOT_ALLOWED,
                [("allow", "GET, HEAD, OPTIONS")],
            )
                .into_response()
        }
    } else {
        StatusCode::BAD_REQUEST.into_response()
    };
    response.extensions_mut().insert(HttpRoute::Altconnect);
    response
}
