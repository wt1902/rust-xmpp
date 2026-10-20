//! Prosody-compatible HTTP app mount and advertised URL configuration.
use crate::config::{Config, Options};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct HttpConfig {
    pub host: String,
    pub default_host: Option<String>,
    pub websocket_path: String,
    pub bosh_path: String,
    pub file_share_path: String,
    pub altconnect_path: String,
    pub consider_websocket_secure: bool,
    pub consider_bosh_secure: bool,
    pub websocket_origins: Vec<String>,
    pub bosh_origins: Vec<String>,
    known_hosts: BTreeSet<String>,
    external: Option<String>,
}
fn string(options: &Options, key: &str) -> Result<Option<String>> {
    options
        .get(key)
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .with_context(|| format!("{key} must be a string"))
        })
        .transpose()
}
pub(crate) fn valid_authority(authority: &axum::http::uri::Authority) -> bool {
    let raw = authority.as_str();
    if raw.contains('@') {
        return false;
    }
    let suffix = if raw.starts_with('[') {
        let Some(end) = raw.find(']') else {
            return false;
        };
        &raw[end + 1..]
    } else {
        raw.find(':').map(|i| &raw[i..]).unwrap_or("")
    };
    if suffix.is_empty() {
        return true;
    }
    suffix.strip_prefix(':').is_some_and(|port| {
        !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) && port.parse::<u16>().is_ok()
    })
}
fn host(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty()
            && value.is_ascii()
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')),
        "invalid HTTP host: {value}"
    );
    Ok(value.to_ascii_lowercase())
}
/// Mount paths are literals, never axum route patterns. Reject ambiguous or unsafe forms.
pub fn normalize_path(value: &str) -> Result<String> {
    ensure!(
        value.is_ascii(),
        "HTTP paths must use percent encoding for non-ASCII characters"
    );
    // Validate pchars directly. No value is passed to a route-pattern parser.
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if byte == b'%' {
            ensure!(
                offset + 2 < bytes.len()
                    && bytes[offset + 1].is_ascii_hexdigit()
                    && bytes[offset + 2].is_ascii_hexdigit(),
                "malformed percent escape in HTTP path"
            );
            let byte = u8::from_str_radix(&value[offset + 1..offset + 3], 16)?;
            ensure!(
                byte != b'/' && byte != b'\\' && !byte.is_ascii_control(),
                "ambiguous percent escape in HTTP path"
            );
            decoded.push(byte);
            offset += 3;
        } else {
            ensure!(
                byte.is_ascii_alphanumeric() || b"/-._~!&'()*+,;=:@".contains(&byte),
                "HTTP path must contain only literal URL path characters"
            );
            decoded.push(byte);
            offset += 1;
        }
    }
    ensure!(
        !value.contains("//")
            && !decoded
                .split(|b| *b == b'/')
                .any(|s| s == b"." || s == b".."),
        "invalid HTTP path"
    );
    let value = if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    };
    let value = value.trim_end_matches('/');
    Ok(if value.is_empty() {
        "/".into()
    } else {
        value.to_owned()
    })
}

fn paths(options: &Options) -> Result<BTreeMap<String, String>> {
    let Some(value) = options.get("http_paths") else {
        return Ok(BTreeMap::new());
    };
    let table = value.as_object().context("http_paths must be a table")?;
    table
        .iter()
        .map(|(k, v)| {
            Ok((
                k.clone(),
                v.as_str()
                    .context("http_paths entries must be strings")?
                    .to_owned(),
            ))
        })
        .collect()
}
impl HttpConfig {
    pub fn for_host(config: &Config, domain: &str) -> Result<Self> {
        let local = &config
            .hosts
            .get(domain)
            .context("unknown HTTP virtual host")?
            .options;
        let global_paths = paths(&config.global)?;
        let local_paths = paths(local)?;
        let mount = |name: &str, default: &str| -> Result<String> {
            normalize_path(
                &local_paths
                    .get(name)
                    .or_else(|| global_paths.get(name))
                    .map(String::as_str)
                    .unwrap_or(default)
                    .replace("$host", domain),
            )
        };
        let effective_host = |name: &str| -> Result<String> {
            let h = &config.hosts.get(name).context("unknown HTTP host")?.options;
            host(
                &string(h, "http_host")?
                    .or(string(&config.global, "http_host")?)
                    .unwrap_or_else(|| name.into()),
            )
        };
        let mut known_hosts = BTreeSet::new();
        for name in config.hosts.keys() {
            known_hosts.insert(effective_host(name)?);
        }
        let default_host = string(&config.global, "http_default_host")?
            .map(|s| host(&s))
            .transpose()?;
        let origins = |module: &str| -> Result<Vec<String>> {
            let value = config
                .option(domain, "http_cors_override")
                .and_then(|v| v.get(module))
                .and_then(|v| v.get("origins"))
                .or_else(|| config.option(domain, "access_control_allow_origins"));
            match value {
                None => Ok(vec![]),
                Some(v) if v.as_object().is_some_and(|m| m.is_empty()) => Ok(vec![]),
                Some(v) if v.as_str() == Some("*") => Ok(vec!["*".into()]),
                Some(v) => v
                    .as_array()
                    .context("HTTP origins must be a list")?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .context("HTTP origins entries must be strings")
                    })
                    .collect(),
            }
        };
        let boolean = |key: &str| -> Result<bool> {
            config
                .option(domain, key)
                .map(|v| {
                    v.as_bool()
                        .with_context(|| format!("{key} must be boolean"))
                })
                .unwrap_or(Ok(false))
        };
        let external =
            string(local, "http_external_url")?.or(string(&config.global, "http_external_url")?);
        if let Some(url) = &external {
            parse_external(url)?;
        }
        Ok(Self {
            host: effective_host(domain)?,
            default_host,
            websocket_path: mount("websocket", "/xmpp-websocket")?,
            bosh_path: mount("bosh", "/http-bind")?,
            file_share_path: mount("file_share", "/file_share")?,
            altconnect_path: mount("altconnect", "/.well-known")?,
            consider_websocket_secure: boolean("consider_websocket_secure")?,
            consider_bosh_secure: boolean("consider_bosh_secure")?,
            websocket_origins: origins("websocket")?,
            bosh_origins: origins("bosh")?,
            known_hosts,
            external,
        })
    }
    pub fn accepts_host(&self, authority: &str) -> bool {
        let Ok(authority) = authority.parse::<axum::http::uri::Authority>() else {
            return false;
        };
        if !valid_authority(&authority) {
            return false;
        }
        let requested = authority.host().to_ascii_lowercase();
        requested == self.host
            || (!self.known_hosts.contains(&requested)
                && self.default_host.as_deref() == Some(self.host.as_str()))
    }
    /// External reverse-proxy prefixes affect discovery only, never local mounts.
    pub fn external_url(&self, app: &str, secure: bool, port: u16) -> Result<String> {
        let path = match app {
            "websocket" => &self.websocket_path,
            "bosh" => &self.bosh_path,
            "file_share" => &self.file_share_path,
            "altconnect" => &self.altconnect_path,
            _ => anyhow::bail!("unknown HTTP app"),
        };
        if let Some(external) = &self.external {
            let uri = parse_external(external)?;
            let scheme = uri.scheme_str().unwrap();
            let authority = uri.authority().unwrap();
            let authority =
                if authority.port_u16() == Some(if scheme == "https" { 443 } else { 80 }) {
                    authority.host().to_owned()
                } else {
                    authority.to_string()
                };
            return Ok(format!(
                "{scheme}://{authority}{}{path}",
                uri.path().trim_end_matches('/')
            ));
        }
        let scheme = if secure { "https" } else { "http" };
        let port = if port == if secure { 443 } else { 80 } {
            String::new()
        } else {
            format!(":{port}")
        };
        Ok(format!("{scheme}://{}{port}{path}", self.host))
    }
}
fn parse_external(value: &str) -> Result<axum::http::Uri> {
    let uri: axum::http::Uri = value.parse().context("invalid http_external_url")?;
    ensure!(
        matches!(uri.scheme_str(), Some("http" | "https"))
            && uri.authority().is_some()
            && !uri.authority().unwrap().as_str().contains('@')
            && uri.query().is_none()
            && !value.contains('#'),
        "http_external_url must be an absolute HTTP(S) URL without credentials, query or fragment"
    );
    ensure!(
        valid_authority(uri.authority().unwrap()),
        "http_external_url port must be in 0..65535"
    );
    Ok(uri)
}
pub fn validate(config: &Config) -> Result<()> {
    for options in std::iter::once(&config.global).chain(config.hosts.values().map(|h| &h.options))
    {
        for value in paths(options)?.values() {
            normalize_path(&value.replace("$host", "example.test"))?;
        }
    }
    for domain in config.hosts.keys() {
        let http = HttpConfig::for_host(config, domain)?;
        let modules = config.modules(domain)?;
        ensure!(
            !(modules.contains("websocket")
                && modules.contains("bosh")
                && http.websocket_path == http.bosh_path),
            "websocket and bosh HTTP paths conflict for {domain}"
        );
        if modules.contains("http_altconnect") {
            for suffix in ["host-meta", "host-meta.json"] {
                let path = format!("{}/{suffix}", http.altconnect_path.trim_end_matches('/'));
                ensure!(
                    !(modules.contains("websocket") && http.websocket_path == path
                        || modules.contains("bosh") && http.bosh_path == path),
                    "http_altconnect path conflicts with XMPP transport for {domain}"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(value: serde_json::Value) -> Config {
        serde_json::from_value(value).unwrap()
    }
    #[test]
    fn mounts_inherit_per_app_and_expand_virtual_host() {
        let c = config(
            serde_json::json!({"global":{"http_paths":{"websocket":"global/$host/","bosh":"bind/"}},"hosts":{"a.test":{"options":{"http_paths":{"websocket":"custom/$host"}}}}}),
        );
        let h = HttpConfig::for_host(&c, "a.test").unwrap();
        assert_eq!(h.websocket_path, "/custom/a.test");
        assert_eq!(h.bosh_path, "/bind");
    }
    #[test]
    fn routes_hosts_and_default_without_overriding_known_hosts() {
        let c = config(
            serde_json::json!({"global":{"http_default_host":"web.test"},"hosts":{"a.test":{"options":{"http_host":"web.test"}},"b.test":{"options":{}}}}),
        );
        let h = HttpConfig::for_host(&c, "a.test").unwrap();
        assert!(h.accepts_host("WEB.TEST:5280"));
        assert!(h.accepts_host("unknown.test"));
        assert!(!h.accepts_host("b.test"));
        assert!(!h.accepts_host("bad host"));
    }
    #[test]
    fn external_prefix_and_standard_port() {
        let c = config(
            serde_json::json!({"global":{"http_external_url":"https://proxy.test:443/prefix/"},"hosts":{"a.test":{"options":{}}}}),
        );
        assert_eq!(
            HttpConfig::for_host(&c, "a.test")
                .unwrap()
                .external_url("bosh", false, 5280)
                .unwrap(),
            "https://proxy.test/prefix/http-bind"
        );
    }
    #[test]
    fn literal_pchars_and_percent_encoding_are_supported() {
        for path in [
            "/chat/v1:ws",
            "/bind%20endpoint",
            "/a/*",
            "/a@b!&'()+,;=:_~-.%41",
        ] {
            assert_eq!(normalize_path(path).unwrap(), path);
        }
    }
    #[test]
    fn invalid_paths_types_urls_and_conflicts_are_errors() {
        for path in [
            "/a/{capture}",
            "/../b",
            "/a?x",
            "/a#b",
            "/a//b",
            "/$unknown",
            "/a%2fb",
            "/a%5cb",
            "/a%00b",
            "/%2e%2E/b",
            "/a%",
            "/a%xx",
            "/a b",
            "/a\\b",
        ] {
            assert!(normalize_path(path).is_err(), "{path}");
        }
        for global in [
            serde_json::json!({"http_paths":false}),
            serde_json::json!({"http_paths":{"bosh":false}}),
            serde_json::json!({"http_external_url":"https://u:p@a.test"}),
            serde_json::json!({"http_external_url":"relative/path"}),
            serde_json::json!({"modules_enabled":["websocket","bosh"],"http_paths":{"websocket":"same/","bosh":"/same"}}),
        ] {
            assert!(
                validate(&config(
                    serde_json::json!({"global":global,"hosts":{"a.test":{"options":{}}}})
                ))
                .is_err()
            );
        }
    }
}
