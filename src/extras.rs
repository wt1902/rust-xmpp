use crate::{
    config::Config,
    protocol::{ModuleResult, iq_error, iq_result},
    wire::escape,
};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::Instant;
pub fn handle(
    config: &Config,
    domain: &str,
    iq: roxmltree::Node<'_, '_>,
    started: Instant,
) -> Result<Option<ModuleResult>> {
    let Some(q) = iq.first_element_child() else {
        return Ok(None);
    };
    let ns = q.tag_name().namespace().unwrap_or("");
    let name = q.tag_name().name();
    let modules = config.modules(domain)?;
    let payload = match (iq.attribute("type"), name, ns) {
        (Some("get"), "time", "urn:xmpp:time") if modules.contains("time") => Some(format!(
            "<time xmlns='urn:xmpp:time'><tzo>+00:00</tzo><utc>{}</utc></time>",
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )),
        (Some("get"), "query", "jabber:iq:last") if modules.contains("uptime") => Some(format!(
            "<query xmlns='jabber:iq:last' seconds='{}'/>",
            started.elapsed().as_secs()
        )),
        (
            Some("get"),
            "services" | "credentials",
            "urn:xmpp:extdisco:1" | "urn:xmpp:extdisco:2",
        ) if modules.contains("turn_external") => {
            let host = config
                .option(domain, "turn_external_host")
                .and_then(|v| v.as_str())
                .unwrap_or(domain);
            let secret = config
                .option(domain, "turn_external_secret")
                .and_then(|v| v.as_str())
                .context("TURN secret missing")?;
            let port = config
                .option(domain, "turn_external_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(3478);
            let ttl = config
                .option(domain, "turn_external_ttl")
                .and_then(|v| v.as_i64())
                .unwrap_or(86400);
            let expires = chrono::Utc::now() + chrono::Duration::seconds(ttl);
            let username = match config
                .option(domain, "turn_external_user")
                .and_then(|v| v.as_str())
            {
                Some(u) => format!("{}:{u}", expires.timestamp()),
                None => expires.timestamp().to_string(),
            };
            let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes())?;
            mac.update(username.as_bytes());
            let password = STANDARD.encode(mac.finalize().into_bytes());
            let tcp = config
                .option(domain, "turn_external_tcp")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut services = vec![("stun", "udp", port), ("turn", "udp", port)];
            if tcp {
                services.extend([("stun", "tcp", port), ("turn", "tcp", port)]);
            }
            if let Some(p) = config
                .option(domain, "turn_external_tls_port")
                .and_then(|v| v.as_u64())
            {
                services.push(("turns", "tcp", p));
            }
            let mut xml = format!("<{name} xmlns='{ns}'>");
            for (kind, transport, port) in services {
                if q.attribute("type").is_some_and(|t| t != kind) {
                    continue;
                }
                if name == "credentials"
                    && (kind == "stun"
                        || !q.children().any(|s| {
                            s.is_element()
                                && s.tag_name().name() == "service"
                                && s.attribute("host") == Some(host)
                                && s.attribute("type") == Some(kind)
                                && s.attribute("port").is_none_or(|p| p == port.to_string())
                        }))
                {
                    continue;
                }
                xml.push_str(&format!(
                    "<service type='{kind}' transport='{transport}' host='{}' port='{port}'",
                    escape(host)
                ));
                if kind != "stun" {
                    xml.push_str(&format!(
                        " username='{}' password='{}' restricted='1' expires='{}'",
                        escape(&username),
                        password,
                        expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                    ));
                }
                xml.push_str("/>");
            }
            xml.push_str(&format!("</{name}>"));
            Some(xml)
        }
        (
            Some("get"),
            "catalog",
            "urn:xmpp:sec-label:catalog:2" | "urn:xmpp:sec-label:catalog:0",
        ) if modules.contains("seclabels") => {
            let configured_labels = config.option(domain, "security_labels");
            let compatibility_labels;
            let labels = if let Some(value) = configured_labels.filter(|value| {
                value.get("policies").is_some() || value.get("default_policy").is_some()
            }) {
                compatibility_labels = match policy_catalog_labels(value) {
                    Ok(labels) => labels,
                    Err(_) => {
                        return Ok(Some(ModuleResult::reply(iq_error(iq, "not-acceptable"))));
                    }
                };
                Some(&compatibility_labels)
            } else {
                configured_labels
            };
            let title = config
                .option(domain, "security_catalog_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Default");
            let desc = config
                .option(domain, "security_catalog_desc")
                .and_then(|v| v.as_str())
                .unwrap_or("My labels");
            let target = q
                .attribute("to")
                .map(|to| format!(" to='{}'", escape(to)))
                .unwrap_or_default();
            let mut xml = format!(
                "<catalog xmlns='{ns}'{target} name='{}' desc='{}'>",
                escape(title),
                escape(desc)
            );
            if let Some(value) = labels {
                labels_xml(value, "", None, ns, &mut xml)?;
            } else {
                labels_xml(
                    &serde_json::json!([{"name":"Unclassified","label":true,"default":true}]),
                    "",
                    None,
                    ns,
                    &mut xml,
                )?;
            }
            xml.push_str("</catalog>");
            Some(xml)
        }
        _ => None,
    };
    Ok(payload.map(|p| ModuleResult::reply(iq_result(iq, &p))))
}
/// Catalog-only compatibility for the example configuration's policy schema.
/// Selects `default_policy` and exposes its classifications as ordinary labels.
/// Policy names confer no authorization, membership, ACL, or message enforcement.
/// Unknown fields are rejected rather than silently implying policy support.
fn policy_catalog_labels(value: &serde_json::Value) -> Result<serde_json::Value> {
    use anyhow::ensure;
    use serde_json::Value;

    let root = value
        .as_object()
        .context("security labels must be an object")?;
    ensure!(
        root.keys()
            .all(|key| matches!(key.as_str(), "default_policy" | "policies")),
        "unknown policy catalog option"
    );
    let selected = root
        .get("default_policy")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .context("default policy missing")?;
    let policies = root
        .get("policies")
        .and_then(Value::as_object)
        .context("policies must be an object")?;
    ensure!(policies.contains_key(selected), "default policy not found");
    let mut selected_labels = None;
    for (name, policy) in policies {
        ensure!(!name.trim().is_empty(), "empty policy name");
        let policy = policy.as_object().context("policy must be an object")?;
        ensure!(
            policy.keys().all(|key| key == "classifications"),
            "unknown policy option"
        );
        let classifications = policy
            .get("classifications")
            .and_then(Value::as_array)
            .context("classifications must be an array")?;
        let mut labels = Vec::with_capacity(classifications.len());
        for classification in classifications {
            let mut label = classification
                .as_object()
                .context("classification must be an object")?
                .clone();
            ensure!(
                label.keys().all(|key| matches!(
                    key.as_str(),
                    "name" | "label" | "display" | "color" | "bgcolor" | "default"
                )),
                "unknown classification option"
            );
            ensure!(
                label
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| !name.trim().is_empty()),
                "classification name missing"
            );
            for key in ["display", "color", "bgcolor"] {
                ensure!(
                    label.get(key).is_none_or(Value::is_string),
                    "classification display option must be a string"
                );
            }
            ensure!(
                label.get("default").is_none_or(Value::is_boolean),
                "classification default must be a boolean"
            );
            match label.entry("label").or_insert(Value::Bool(true)) {
                Value::Bool(true) => {}
                Value::String(text) => {
                    if text.starts_with('<') {
                        roxmltree::Document::parse(text)?;
                    }
                }
                _ => anyhow::bail!("classification label must be true or a string"),
            }
            labels.push(Value::Object(label));
        }
        if name == selected {
            selected_labels = Some(Value::Array(labels));
        }
    }
    selected_labels.context("default policy not found")
}

fn labels_xml(
    v: &serde_json::Value,
    prefix: &str,
    key: Option<&str>,
    ns: &str,
    out: &mut String,
) -> Result<()> {
    if let Some(label) = v
        .get("label")
        .filter(|v| !v.is_null() && v != &&serde_json::Value::Bool(false))
    {
        let name = key
            .or_else(|| v.get("name").and_then(|v| v.as_str()))
            .context("security label name missing")?;
        let selector = escape(&format!("{prefix}{name}"));
        let default = if v.get("default") == Some(&serde_json::Value::Bool(true)) {
            " default='true'"
        } else {
            ""
        };
        if ns.ends_with(":2") {
            out.push_str(&format!(
                "<item selector='{selector}'{default}><securitylabel xmlns='urn:xmpp:sec-label:0'>"
            ));
        } else {
            out.push_str(&format!(
                "<securitylabel xmlns='urn:xmpp:sec-label:0' selector='{selector}'{default}>"
            ));
        }
        if v.get("display").is_some() || v.get("color").is_some() || v.get("bgcolor").is_some() {
            out.push_str("<displaymarking");
            for (k, a) in [("color", "fgcolor"), ("bgcolor", "bgcolor")] {
                if let Some(s) = v.get(k).and_then(|v| v.as_str()) {
                    out.push_str(&format!(" {a}='{}'", escape(s)));
                }
            }
            out.push_str(&format!(
                ">{}</displaymarking>",
                escape(v.get("display").and_then(|v| v.as_str()).unwrap_or(name))
            ));
        }
        let text = if label == &serde_json::Value::Bool(true) {
            escape(name)
        } else if let Some(s) = label.as_str() {
            if s.starts_with('<') {
                roxmltree::Document::parse(s)?;
                s.to_owned()
            } else {
                escape(s)
            }
        } else {
            anyhow::bail!("unsupported security label")
        };
        out.push_str(&format!("<label>{text}</label></securitylabel>"));
        if ns.ends_with(":2") {
            out.push_str("</item>");
        }
    } else if let Some(a) = v.as_array() {
        for child in a {
            labels_xml(child, prefix, None, ns, out)?;
        }
    } else if let Some(m) = v.as_object() {
        let next = key.map(|k| format!("{prefix}{k}|"));
        for (k, child) in m {
            labels_xml(child, next.as_deref().unwrap_or(prefix), Some(k), ns, out)?;
        }
    }
    Ok(())
}
