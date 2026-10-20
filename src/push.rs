//! XEP-0357 registrations and notifications in Prosody's cloud_notify store.
use crate::{
    config::Config,
    protocol::{self, ModuleResult},
    storage::{self, LuaValue as V},
    wire::escape,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, Instant},
};
fn text(v: Option<&V>) -> Option<String> {
    match v {
        Some(V::String(b)) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}
fn s(v: &str) -> V {
    V::String(v.as_bytes().to_vec())
}
// Prosody get_child_text() selects direct children in the stanza's namespace
// and rejects elements containing child tags, rather than flattening extensions.
fn stanza_child_text(stanza: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    let child = stanza.children().find(|n| {
        n.is_element()
            && n.tag_name().name() == name
            && n.tag_name().namespace() == stanza.tag_name().namespace()
    })?;
    if child.children().any(|n| n.is_element()) {
        return None;
    }
    Some(
        child
            .children()
            .filter(|n| n.is_text())
            .filter_map(|n| n.text())
            .collect(),
    )
}
#[derive(Default)]
pub struct Push {
    pending: BTreeMap<String, (String, String, String, Instant)>,
    errors: BTreeMap<(String, String), u64>,
    removed: Vec<(String, String)>,
}
impl Push {
    /// Registration removals which must be reflected in live SM session watchdogs.
    pub fn take_removed(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.removed)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn notify_queue(
        &mut self,
        root: &Path,
        domain: &str,
        user: &str,
        messages: &[String],
        config: &Config,
        identifier: &str,
    ) -> Result<QueueNotification> {
        let mut result = QueueNotification::default();
        let mut sent = [false; 2];
        let equal = config.option(domain, "push_notification_important_body")
            == Some(&serde_json::Value::Bool(false));
        for xml in messages {
            let Ok(doc) = roxmltree::Document::parse(xml) else {
                continue;
            };
            let stanza = doc.root_element();
            let important = is_important(stanza);
            let index = usize::from(important && !equal);
            if sent[index] {
                continue;
            }
            let deliveries =
                self.notify_for_identifier(root, domain, user, stanza, config, Some(identifier))?;
            if !deliveries.is_empty() {
                sent[index] = true;
                result.reset_watchdog |= important || equal;
                result.deliveries.extend(deliveries);
            }
            if sent[0] && sent[1] {
                break;
            }
        }
        Ok(result)
    }

    pub fn handle(
        &mut self,
        root: &Path,
        domain: &str,
        jid: &str,
        iq: roxmltree::Node<'_, '_>,
        max_devices: usize,
    ) -> Result<Option<ModuleResult>> {
        self.handle_with_client(root, domain, jid, iq, max_devices, None)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn handle_with_client(
        &mut self,
        root: &Path,
        domain: &str,
        jid: &str,
        iq: roxmltree::Node<'_, '_>,
        max_devices: usize,
        client_id: Option<&str>,
    ) -> Result<Option<ModuleResult>> {
        let Some(q) = iq.first_element_child() else {
            return Ok(None);
        };
        if q.tag_name().namespace() != Some("urn:xmpp:push:0") {
            return Ok(None);
        }
        let owner = protocol::bare(jid);
        let (user, h) = owner.split_once('@').context("invalid account")?;
        if h != domain
            || iq.attribute("type") != Some("set")
            || iq
                .attribute("to")
                .is_some_and(|to| to != domain && protocol::bare(to) != owner)
        {
            return Ok(Some(ModuleResult::reply(protocol::iq_error(
                iq,
                "forbidden",
            ))));
        }
        let Some(service) = q.attribute("jid").filter(|v| !v.is_empty() && *v != jid) else {
            return Ok(Some(ModuleResult::reply(protocol::iq_error(
                iq,
                "bad-request",
            ))));
        };
        let node = q.attribute("node");
        if !matches!(q.tag_name().name(), "enable" | "disable") {
            return Ok(Some(ModuleResult::reply(protocol::iq_error(
                iq,
                "bad-request",
            ))));
        }
        storage::update(root, domain, Some(user), "cloud_notify", |table| {
            if q.tag_name().name() == "enable" {
                let key = format!("{service}<{}", node.unwrap_or(""));
                let mut record = V::default();
                record.set("jid", s(service));
                if let Some(node) = node {
                    record.set("node", s(node));
                }
                if let Some(p) = q.attribute("include_payload") {
                    record.set("include_payload", s(p));
                }
                record.set("timestamp", V::Integer(chrono::Utc::now().timestamp()));
                if let Some(client_id) = client_id {
                    record.set("client_id", s(client_id));
                } else {
                    record.set(
                        "resource",
                        s(jid.split_once('/').map(|(_, r)| r).unwrap_or("")),
                    );
                }
                if let Some(language) =
                    iq.attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
                {
                    record.set("language", s(language));
                }
                if let Some(options) = q
                    .children()
                    .find(|n| n.is_element() && n.tag_name().namespace() == Some("jabber:x:data"))
                {
                    record.set("options", storage::stanza_value(options));
                }
                table.set(&key, record);
                if let V::Table(entries) = table {
                    while entries.len() > max_devices.max(1) {
                        let i = entries
                            .iter()
                            .enumerate()
                            .min_by_key(|(_, (_, v))| match v.get("timestamp") {
                                Some(V::Integer(n)) => *n,
                                _ => 0,
                            })
                            .map(|(i, _)| i)
                            .unwrap();
                        entries.remove(i);
                    }
                }
            } else if let V::Table(entries) = table {
                entries.retain(|(_, v)| {
                    !(text(v.get("jid")).as_deref() == Some(service)
                        && node.is_none_or(|n| text(v.get("node")).as_deref() == Some(n)))
                });
            }
            Ok(())
        })?;
        // A fresh registration must not inherit failures or responses for its previous incarnation.
        self.pending.retain(|_, (pending_user, key, _, _)| {
            !(pending_user == user
                && (key == &format!("{service}<{}", node.unwrap_or(""))
                    || (q.tag_name().name() == "disable"
                        && node.is_none()
                        && key.split_once('<').is_some_and(|(s, _)| s == service))))
        });
        self.errors.retain(|(pending_user, key), _| {
            !(pending_user == user
                && (key == &format!("{service}<{}", node.unwrap_or(""))
                    || (q.tag_name().name() == "disable"
                        && node.is_none()
                        && key.split_once('<').is_some_and(|(s, _)| s == service))))
        });
        Ok(Some(ModuleResult::reply(protocol::iq_result(iq, ""))))
    }
    pub fn notify(
        &mut self,
        root: &Path,
        domain: &str,
        user: &str,
        message: roxmltree::Node<'_, '_>,
        config: &Config,
    ) -> Result<Vec<(String, String)>> {
        self.notify_for_identifier(root, domain, user, message, config, None)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn notify_for_identifier(
        &mut self,
        root: &Path,
        domain: &str,
        user: &str,
        message: roxmltree::Node<'_, '_>,
        config: &Config,
        only: Option<&str>,
    ) -> Result<Vec<(String, String)>> {
        self.pending
            .retain(|_, (_, _, _, at)| at.elapsed() < Duration::from_secs(120));
        ensure!(self.pending.len() < 8192, "too many pending pushes");
        let table = storage::load(root, domain, Some(user), "cloud_notify")?.unwrap_or_default();
        let V::Table(entries) = table else {
            return Ok(vec![]);
        };
        let body = stanza_child_text(message, "body");
        let include_body = config
            .option(domain, "push_notification_with_body")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let include_sender = config
            .option(domain, "push_notification_with_sender")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut outputs = vec![];
        for (key, record) in entries {
            let Some(service) = text(record.get("jid")) else {
                continue;
            };
            let node = text(record.get("node"));
            let Some(identifier) = text(Some(&key)) else {
                continue;
            };
            if only.is_some_and(|only| only != identifier) {
                continue;
            }
            let id = uuid::Uuid::new_v4().to_string();
            let mut form="<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:push:summary</value></field><field var='message-count'><value>1</value></field>".to_owned();
            if include_sender {
                form.push_str(&format!(
                    "<field var='last-message-sender'><value>{}</value></field>",
                    escape(message.attribute("from").unwrap_or(""))
                ));
            }
            let summary = if include_body {
                body.as_deref()
            } else if is_important(message) {
                match config.option(domain, "push_notification_important_body") {
                    Some(serde_json::Value::Bool(false)) => None,
                    Some(serde_json::Value::String(s)) => Some(s.as_str()),
                    _ => Some("New Message!"),
                }
            } else {
                None
            };
            if let Some(body) = summary {
                form.push_str(&format!(
                    "<field var='last-message-body'><value>{}</value></field>",
                    escape(body)
                ));
            }
            form.push_str("</x>");
            let node_attr = node
                .map(|n| format!(" node='{}'", escape(&n)))
                .unwrap_or_default();
            let mut payload = format!(
                "<iq xmlns='jabber:client' type='set' from='{}' to='{}' id='{id}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish{node_attr}><item><notification xmlns='urn:xmpp:push:0'>{form}</notification></item></publish>",
                escape(domain),
                escape(&service)
            );
            if let Some(options) = record.get("options") {
                payload.push_str(&format!(
                    "<publish-options>{}</publish-options>",
                    storage::stanza_xml(options)?
                ));
            }
            payload.push_str("</pubsub></iq>");
            self.pending.insert(
                id,
                (user.into(), identifier, service.clone(), Instant::now()),
            );
            outputs.push((service, payload));
        }
        Ok(outputs)
    }
    pub fn result(
        &mut self,
        root: &Path,
        domain: &str,
        iq: roxmltree::Node<'_, '_>,
        max_errors: u64,
    ) -> Result<bool> {
        let Some((user, key, service, sent_at)) =
            self.pending.get(iq.attribute("id").unwrap_or("")).cloned()
        else {
            return Ok(false);
        };
        if sent_at.elapsed() >= Duration::from_secs(120) {
            self.pending.remove(iq.attribute("id").unwrap_or(""));
            return Ok(false);
        }
        if iq.attribute("from") != Some(service.as_str()) {
            return Ok(false);
        }
        if !matches!(iq.attribute("type"), Some("result" | "error")) {
            return Ok(false);
        }
        self.pending.remove(iq.attribute("id").unwrap_or(""));
        let error_key = (user.clone(), key.clone());
        if iq.attribute("type") == Some("result") {
            self.errors.remove(&error_key);
            return Ok(true);
        }
        if iq.attribute("type") == Some("error")
            && !iq.children().any(|n| {
                n.is_element()
                    && n.tag_name().name() == "error"
                    && n.attribute("type") == Some("wait")
            })
        {
            let count = self.errors.entry(error_key.clone()).or_default();
            *count += 1;
            if *count >= max_errors {
                storage::update(root, domain, Some(&user), "cloud_notify", |table| {
                    table.set(&key, V::Nil);
                    Ok(())
                })?;
                self.errors.remove(&error_key);
                self.removed.push((user.clone(), key.clone()));
            }
        }
        Ok(true)
    }
}

/// Locate the most recent registration for a stable client identity or a legacy resource.
/// A resource match never overrides a stored stable identity belonging to another device.
pub fn client_device(
    root: &Path,
    domain: &str,
    user: &str,
    client_id: Option<&str>,
    resource: &str,
) -> Result<Option<String>> {
    let table = storage::load(root, domain, Some(user), "cloud_notify")?.unwrap_or_default();
    let V::Table(entries) = table else {
        return Ok(None);
    };
    Ok(entries
        .into_iter()
        .filter_map(|(key, record)| {
            let matches = match text(record.get("client_id")) {
                Some(stored) => client_id == Some(stored.as_str()),
                None => text(record.get("resource")).as_deref() == Some(resource),
            };
            if !matches || text(record.get("jid")).is_none() {
                return None;
            }
            let timestamp = match record.get("timestamp") {
                Some(V::Integer(n)) => *n,
                _ => 0,
            };
            text(Some(&key)).map(|key| (timestamp, key))
        })
        .max()
        .map(|(_, key)| key))
}

#[derive(Default, Debug)]
pub struct QueueNotification {
    pub deliveries: Vec<(String, String)>,
    pub reset_watchdog: bool,
}
/// Prosody cloud_notify importance classification, including incoming carbon wrappers.
pub fn is_important(message: roxmltree::Node<'_, '_>) -> bool {
    if message.tag_name().name() != "message" {
        return false;
    }
    let mut inner = message;
    if let Some(carbon) = message.children().find(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some("urn:xmpp:carbons:2")
            && matches!(n.tag_name().name(), "sent" | "received")
    }) {
        if carbon.tag_name().name() == "sent" {
            return false;
        }
        if let Some(stanza) = carbon
            .children()
            .find(|n| n.has_tag_name(("urn:xmpp:forward:0", "forwarded")))
            .and_then(|f| {
                f.children()
                    .find(|n| n.has_tag_name(("jabber:client", "message")))
            })
        {
            inner = stanza;
        }
    }
    if inner.attribute("type") == Some("headline") {
        return false;
    }
    if inner.children().any(|n| {
        matches!(
            (n.tag_name().namespace(), n.tag_name().name()),
            (
                Some("eu.siacs.conversations.axolotl" | "urn:xmpp:omemo:0" | "urn:xmpp:omemo:2"),
                "encrypted"
            ) | (Some("jabber:x:encrypted"), "x")
                | (Some("urn:xmpp:openpgp:0"), "openpgp")
                | (Some("urn:xmpp:jingle-message:0"), "propose")
        )
    }) {
        return true;
    }
    if inner.attribute("type") == Some("groupchat") && stanza_child_text(inner, "subject").is_some()
    {
        return false;
    }
    stanza_child_text(inner, "body").is_some_and(|body| !body.is_empty())
}
/// Native first-important-push rule; caller invokes only after a push was emitted.
pub fn resets_watchdog(message: roxmltree::Node<'_, '_>, config: &Config, domain: &str) -> bool {
    is_important(message)
        || config.option(domain, "push_notification_important_body")
            == Some(&serde_json::Value::Bool(false))
}
