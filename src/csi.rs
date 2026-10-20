//! Write buffering matching the supplied Prosody mod_csi_simple importance policy.
use crate::{protocol, wire::escape};
use std::time::{Duration, Instant};
#[derive(Clone, Debug, Default)]
pub struct Buffer {
    inactive: bool,
    flushing_until: Option<Instant>,
    queue: Vec<String>,
    bytes: usize,
    pub limit: usize,
    pub resume_delay: Duration,
    pub important_payloads: Vec<String>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct DurableBuffer {
    inactive: bool,
    queue: Vec<String>,
    limit: usize,
    resume_delay_ms: u64,
    important_payloads: Vec<String>,
}
impl Buffer {
    pub(crate) fn durable(&self) -> DurableBuffer {
        DurableBuffer {
            inactive: self.inactive,
            queue: self.queue.clone(),
            limit: self.limit,
            resume_delay_ms: self.resume_delay.as_millis().min(u64::MAX as u128) as u64,
            important_payloads: self.important_payloads.clone(),
        }
    }
    pub(crate) fn from_durable(value: DurableBuffer) -> Self {
        Self {
            inactive: value.inactive,
            flushing_until: None,
            bytes: value.queue.iter().map(String::len).sum(),
            queue: value.queue,
            limit: value.limit,
            resume_delay: Duration::from_millis(value.resume_delay_ms),
            important_payloads: value.important_payloads,
        }
    }

    pub fn configure(&mut self, limit: usize, delay: Duration, payloads: Vec<String>) {
        self.limit = limit.max(1);
        self.resume_delay = delay;
        self.important_payloads = payloads;
    }
    pub fn set_inactive(&mut self, inactive: bool) -> Vec<String> {
        self.inactive = inactive;
        self.flushing_until = None;
        if inactive { Vec::new() } else { self.drain() }
    }
    pub fn reset(&mut self) {
        self.inactive = false;
        self.flushing_until = None;
        self.queue.clear();
        self.bytes = 0;
    }
    fn drain(&mut self) -> Vec<String> {
        self.bytes = 0;
        std::mem::take(&mut self.queue)
    }
    /// Client input flushes held output without declaring the client active.
    pub fn activity(&mut self, now: Instant) -> Vec<String> {
        if self.inactive && !self.queue.is_empty() {
            self.flushing_until = Some(now + self.resume_delay);
            self.drain()
        } else {
            Vec::new()
        }
    }
    pub fn output(&mut self, xml: String, owner: &str, now: Instant) -> Vec<String> {
        if !self.inactive || self.flushing_until.is_some_and(|until| now < until) {
            return vec![xml];
        }
        self.flushing_until = None;
        if self.queue.len() >= self.limit.max(1)
            || self.bytes.saturating_add(xml.len()) > 4 * 1024 * 1024
            || important(&xml, &self.important_payloads)
        {
            self.flushing_until = Some(now + self.resume_delay);
            let mut output = self.drain();
            output.push(xml);
            output
        } else {
            let xml = delayed(&xml, owner);
            self.bytes += xml.len();
            self.queue.push(xml);
            Vec::new()
        }
    }
}
fn has(n: roxmltree::Node<'_, '_>, ns: &str, name: &str) -> bool {
    n.children().any(|c| c.has_tag_name((ns, name)))
}
fn matches_path(n: roxmltree::Node<'_, '_>, path: &str) -> bool {
    let (namespace, rest) = if let Some(p) = path.strip_prefix('{') {
        let Some((ns, rest)) = p.split_once('}') else {
            return false;
        };
        (ns, rest)
    } else {
        (n.tag_name().namespace().unwrap_or("jabber:client"), path)
    };
    let (name, next) = rest
        .split_once('/')
        .map_or((rest, None), |(name, rest)| (name, Some(rest)));
    n.children().filter(|c| c.is_element()).any(|c| {
        (name == "*" || c.tag_name().name() == name)
            && c.tag_name().namespace().unwrap_or("jabber:client") == namespace
            && next.is_none_or(|p| matches_path(c, p))
    })
}
pub fn important(xml: &str, payloads: &[String]) -> bool {
    let wrapped = format!("<root xmlns='jabber:client'>{xml}</root>");
    let Ok(d) = roxmltree::Document::parse(&wrapped) else {
        return true;
    };
    let Some(mut n) = d.root_element().first_element_child() else {
        return true;
    };
    if n.tag_name().namespace() != Some("jabber:client") {
        return true;
    }
    match n.tag_name().name() {
        "presence" => !matches!(n.attribute("type"), None | Some("unavailable" | "error")),
        "iq" => true,
        "message" => {
            if n.attribute("type") == Some("headline") {
                return false;
            }
            if n.attribute("type") == Some("error") || has(n, "urn:xmpp:carbons:2", "sent") {
                return true;
            }
            if let Some(inner) = n
                .children()
                .find(|c| c.has_tag_name(("urn:xmpp:carbons:2", "received")))
                .and_then(|c| {
                    c.children()
                        .find(|c| c.has_tag_name(("urn:xmpp:forward:0", "forwarded")))
                })
                .and_then(|c| {
                    c.children()
                        .find(|c| c.has_tag_name(("jabber:client", "message")))
                })
            {
                n = inner;
            }
            has(n, "jabber:client", "body")
                || has(n, "jabber:client", "subject")
                || has(n, "urn:xmpp:eme:0", "encryption")
                || has(n, "jabber:x:conference", "x")
                || n.children().any(|c| {
                    c.has_tag_name(("http://jabber.org/protocol/muc#user", "x"))
                        && c.children().any(|c| c.tag_name().name() == "invite")
                })
                || n.children().any(|c| {
                    c.is_element()
                        && matches!(
                            c.tag_name().namespace(),
                            Some("urn:xmpp:jingle-message:0" | "urn:xmpp:jingle-message:1")
                        )
                })
                || payloads.iter().any(|p| matches_path(n, p))
        }
        _ => false,
    }
}
fn delayed(xml: &str, owner: &str) -> String {
    let wrapped = format!("<root xmlns='jabber:client'>{xml}</root>");
    let Ok(d) = roxmltree::Document::parse(&wrapped) else {
        return xml.into();
    };
    let Some(n) = d.root_element().first_element_child() else {
        return xml.into();
    };
    if n.tag_name().namespace() != Some("jabber:client") || n.tag_name().name() == "iq" {
        return xml.into();
    }
    let mut output = protocol::xml(n);
    if let Some(at) = output.rfind("</") {
        output.insert_str(
            at,
            &format!(
                "<delay xmlns='urn:xmpp:delay' from='{}' stamp='{}'/>",
                escape(owner),
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ),
        );
    } else if output.ends_with("/>") {
        output.truncate(output.len() - 2);
        output.push_str(&format!(
            "><delay xmlns='urn:xmpp:delay' from='{}' stamp='{}'/></{}>",
            escape(owner),
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            n.tag_name().name()
        ));
    }
    output
}
