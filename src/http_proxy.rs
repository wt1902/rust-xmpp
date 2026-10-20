//! Trusted reverse-proxy connection metadata. Headers never authenticate a socket peer.
use crate::config::Options;
use anyhow::{Result, bail, ensure};
use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestContext {
    pub socket_peer: SocketAddr,
    pub peer_ip: IpAddr,
    pub secure: bool,
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    trusted: Vec<Network>,
    legacy: bool,
}
#[derive(Clone, Debug)]
struct Network {
    ip: IpAddr,
    prefix: u8,
}
impl Network {
    fn parse(value: &str) -> Result<Self> {
        let (ip, prefix) = match value.split_once('/') {
            Some((ip, prefix)) => (ip.parse::<IpAddr>()?, Some(prefix.parse::<u8>()?)),
            None => (value.parse::<IpAddr>()?, None),
        };
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(bits);
        ensure!(prefix <= bits, "invalid trusted_proxies network prefix");
        Ok(Self { ip, prefix })
    }
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}
impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            trusted: vec![
                Network::parse("127.0.0.1").unwrap(),
                Network::parse("::1").unwrap(),
            ],
            legacy: true,
        }
    }
}
impl ProxyConfig {
    pub fn from_options(options: &Options) -> Result<Self> {
        let mut config = Self::default();
        if let Some(value) = options.get("trusted_proxies") {
            // Empty native Lua tables are represented as empty JSON objects.
            let values: &[serde_json::Value] = if let Some(values) = value.as_array() {
                values
            } else if value.as_object().is_some_and(|table| table.is_empty()) {
                &[]
            } else {
                bail!("trusted_proxies must be an array of IP addresses or CIDR networks")
            };
            config.trusted = values
                .iter()
                .map(|value| {
                    let Some(value) = value.as_str() else {
                        bail!("trusted_proxies entries must be strings")
                    };
                    Network::parse(value).map_err(|_| {
                        anyhow::anyhow!("invalid trusted_proxies IP address or CIDR network")
                    })
                })
                .collect::<Result<_>>()?;
        }
        if let Some(value) = options.get("http_legacy_x_forwarded") {
            config.legacy = value
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("http_legacy_x_forwarded must be a boolean"))?;
        }
        Ok(config)
    }
    fn trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|network| network.contains(ip))
    }
    pub fn resolve(
        &self,
        socket_peer: SocketAddr,
        secure: bool,
        headers: &HeaderMap,
    ) -> RequestContext {
        let mut context = RequestContext {
            socket_peer,
            peer_ip: socket_peer.ip(),
            secure,
        };
        if !self.trusted(context.peer_ip) {
            return context;
        }
        if self.legacy {
            // Match Prosody: the rightmost non-proxy wins; all-proxy lists keep the socket IP.
            if let Some(value) = combined(headers, "x-forwarded-for") {
                for ip in value.split(',').filter_map(|v| parse_ip(v.trim())) {
                    if !self.trusted(ip) {
                        context.peer_ip = ip;
                    }
                }
            }
            context.secure |= combined(headers, "x-forwarded-proto").as_deref() == Some("https");
        } else if let Some(value) = combined(headers, "forwarded")
            && let Some(elements) = forwarded(&value)
        {
            let mut first_hop = true;
            for (ip, proto) in elements.into_iter().rev() {
                if !self.trusted(context.peer_ip) {
                    break;
                }
                context.peer_ip = ip;
                // The immediate trusted proxy may terminate TLS. Once that
                // assertion is accepted, every earlier consumed hop must
                // also report HTTPS; plaintext cannot be upgraded again.
                let hop_secure = proto.as_deref() == Some("https");
                context.secure = if first_hop {
                    hop_secure
                } else {
                    context.secure && hop_secure
                };
                first_hop = false;
            }
        }
        context
    }
}
fn combined(headers: &HeaderMap, name: &str) -> Option<String> {
    let values = headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str())
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    (!values.is_empty()).then(|| values.join(","))
}
fn parse_ip(value: &str) -> Option<IpAddr> {
    value
        .parse()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|v| v.ip()))
        .or_else(|| value.strip_prefix('[')?.strip_suffix(']')?.parse().ok())
}
// Quoted delimiters and escapes are handled before splitting Forwarded elements.
fn split_quoted(value: &str, delimiter: char) -> Option<Vec<&str>> {
    let (mut quote, mut escape, mut start) = (false, false, 0);
    let mut result = Vec::new();
    for (i, c) in value.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote && c == '\\' {
            escape = true;
            continue;
        }
        if c == '"' {
            quote = !quote;
        } else if c == delimiter && !quote {
            result.push(&value[start..i]);
            start = i + c.len_utf8();
        }
    }
    if quote || escape {
        return None;
    }
    result.push(&value[start..]);
    Some(result)
}
fn unquote(value: &str) -> Option<String> {
    if !value.starts_with('"') {
        return (!value.contains('"')).then(|| value.to_owned());
    }
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut chars = value.chars();
    let mut result = String::new();
    while let Some(c) = chars.next() {
        result.push(if c == '\\' { chars.next()? } else { c });
    }
    Some(result)
}
fn forwarded(value: &str) -> Option<Vec<(IpAddr, Option<String>)>> {
    split_quoted(value, ',')?
        .into_iter()
        .map(|element| {
            let (mut ip, mut proto) = (None, None);
            for pair in split_quoted(element, ';')? {
                let (name, value) = pair.trim().split_once('=')?;
                let value = unquote(value.trim())?;
                if name.eq_ignore_ascii_case("for") {
                    if ip.is_some() {
                        return None;
                    }
                    ip = Some(parse_ip(&value)?);
                } else if name.eq_ignore_ascii_case("proto") {
                    if proto.is_some() {
                        return None;
                    }
                    proto = Some(value);
                }
            }
            Some((ip?, proto))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(
        config: &ProxyConfig,
        peer: &str,
        secure: bool,
        values: &[(&str, &str)],
    ) -> RequestContext {
        let mut headers = HeaderMap::new();
        for (name, value) in values {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        config.resolve(peer.parse().unwrap(), secure, &headers)
    }
    #[test]
    fn untrusted_socket_ignores_spoofed_headers() {
        let c = context(
            &ProxyConfig::default(),
            "192.0.2.1:80",
            false,
            &[
                ("x-forwarded-for", "198.51.100.1"),
                ("x-forwarded-proto", "https"),
                ("forwarded", "for=198.51.100.2;proto=https"),
            ],
        );
        assert_eq!(c.peer_ip.to_string(), "192.0.2.1");
        assert!(!c.secure);
    }
    #[test]
    fn legacy_chain_uses_rightmost_untrusted_and_tls_is_preserved() {
        let config = ProxyConfig::from_options(
            &serde_json::from_value(
                serde_json::json!({"trusted_proxies":["127.0.0.0/8","2001:db8::/32"]}),
            )
            .unwrap(),
        )
        .unwrap();
        let c = context(
            &config,
            "127.0.0.1:80",
            false,
            &[
                (
                    "x-forwarded-for",
                    "198.51.100.1, 192.0.2.2, [2001:db8::1]:443",
                ),
                ("x-forwarded-proto", "https"),
            ],
        );
        assert_eq!(c.peer_ip.to_string(), "192.0.2.2");
        assert!(c.secure);
        let c = context(
            &config,
            "127.0.0.1:80",
            true,
            &[
                ("x-forwarded-for", "127.0.0.2"),
                ("x-forwarded-proto", "http"),
            ],
        );
        assert_eq!(c.peer_ip.to_string(), "127.0.0.1");
        assert!(c.secure);
    }
    #[test]
    fn forwarded_mode_stops_at_first_untrusted_hop() {
        let config = ProxyConfig::from_options(
            &serde_json::from_value(serde_json::json!({"http_legacy_x_forwarded":false})).unwrap(),
        )
        .unwrap();
        let c = context(
            &config,
            "127.0.0.1:80",
            true,
            &[
                (
                    "forwarded",
                    "for=198.51.100.1;proto=http, for=\"[2001:db8::2]:443\";proto=https",
                ),
                ("x-forwarded-proto", "http"),
            ],
        );
        assert_eq!(c.peer_ip.to_string(), "2001:db8::2");
        assert!(c.secure);
        assert!(
            context(
                &config,
                "127.0.0.1:80",
                false,
                &[("forwarded", "for=192.0.2.1;proto=https")]
            )
            .secure
        );
    }
    #[test]
    fn forwarded_tls_termination_cannot_upgrade_a_plaintext_chain_hop() {
        let config = ProxyConfig::from_options(
            &serde_json::from_value(serde_json::json!({"http_legacy_x_forwarded":false,"trusted_proxies":["127.0.0.0/8"]})).unwrap(),
        )
        .unwrap();
        for value in [
            "for=192.0.2.1;proto=http,for=127.0.0.2;proto=https",
            "for=192.0.2.1;proto=https,for=127.0.0.2;proto=http",
        ] {
            let c = context(&config, "127.0.0.1:80", false, &[("forwarded", value)]);
            assert_eq!(c.peer_ip.to_string(), "192.0.2.1");
            assert!(!c.secure);
        }
    }
    #[test]
    fn malformed_forwarded_and_unknown_identifiers_are_ignored() {
        let config = ProxyConfig::from_options(
            &serde_json::from_value(serde_json::json!({"http_legacy_x_forwarded":false})).unwrap(),
        )
        .unwrap();
        for value in [
            "for=unknown",
            "for=_hidden",
            "for=\"unfinished",
            "for=192.0.2.1;for=192.0.2.2",
        ] {
            assert_eq!(
                context(&config, "127.0.0.1:80", true, &[("forwarded", value)])
                    .peer_ip
                    .to_string(),
                "127.0.0.1"
            );
        }
    }
    #[test]
    fn empty_native_lua_table_disables_proxy_trust() {
        for value in [serde_json::json!({}), serde_json::json!([])] {
            let config = ProxyConfig::from_options(
                &serde_json::from_value(serde_json::json!({"trusted_proxies":value})).unwrap(),
            )
            .unwrap();
            let c = context(
                &config,
                "127.0.0.1:80",
                false,
                &[
                    ("x-forwarded-for", "192.0.2.1"),
                    ("x-forwarded-proto", "https"),
                ],
            );
            assert_eq!(c.peer_ip.to_string(), "127.0.0.1");
            assert!(!c.secure);
        }
    }
    #[test]
    fn config_validation_and_network_boundaries() {
        for value in [
            serde_json::json!({"trusted_proxies":["10.0.0.1/33"]}),
            serde_json::json!({"trusted_proxies":"*"}),
            serde_json::json!({"http_legacy_x_forwarded":"yes"}),
        ] {
            assert!(ProxyConfig::from_options(&serde_json::from_value(value).unwrap()).is_err());
        }
        assert!(
            Network::parse("0.0.0.0/0")
                .unwrap()
                .contains("192.0.2.1".parse().unwrap())
        );
        assert!(
            !Network::parse("127.0.0.0/8")
                .unwrap()
                .contains("128.0.0.1".parse().unwrap())
        );
        assert!(
            !Network::parse("::/0")
                .unwrap()
                .contains("192.0.2.1".parse().unwrap())
        );
    }
}
