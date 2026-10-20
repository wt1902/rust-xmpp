//! Bounded, live XEP-0045 discussion history, independent of archive storage.
use std::collections::VecDeque;

const MUC: &str = "http://jabber.org/protocol/muc";

/// Constraints apply together; an explicit constraint overrides the default count.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HistoryRequest {
    pub maxchars: Option<usize>,
    pub maxstanzas: Option<usize>,
    pub since: Option<f64>,
}
impl HistoryRequest {
    pub fn parse(presence: &str, now: i64) -> Self {
        let Ok(doc) = roxmltree::Document::parse(presence) else {
            return Self::default();
        };
        let history = doc
            .root_element()
            .children()
            .find(|n| n.has_tag_name((MUC, "x")))
            .and_then(|x| x.children().find(|n| n.has_tag_name((MUC, "history"))));
        let Some(history) = history else {
            return Self::default();
        };
        let number = |name| {
            history
                .attribute(name)
                .and_then(|v| v.parse::<f64>().ok())
                .filter(|n| n.is_finite())
        };
        // Native tonumber accepts fractional/negative values: limits below one
        // select no stanzas, and a fractional count is effectively rounded down.
        let count = |name| number(name).map(|n| n.max(0.0).min(usize::MAX as f64) as usize);
        let mut since = history
            .attribute("since")
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|t| t.timestamp() as f64 + f64::from(t.timestamp_subsec_nanos()) / 1e9);
        if let Some(seconds) = number("seconds") {
            let cutoff = now as f64 - seconds;
            since = Some(since.map_or(cutoff, |old| old.max(cutoff)));
        }
        Self {
            maxchars: count("maxchars"),
            maxstanzas: count("maxstanzas"),
            since,
        }
    }
    pub fn has_constraints(&self) -> bool {
        self.maxchars.is_some() || self.maxstanzas.is_some() || self.since.is_some()
    }
}

#[derive(Clone, Debug)]
struct Entry {
    stanza: String,
    timestamp: i64,
}

#[derive(Clone, Debug)]
pub struct RoomHistory {
    capacity: usize,
    default_messages: usize,
    entries: VecDeque<Entry>,
}
impl RoomHistory {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.min(4096),
            default_messages: 20,
            entries: VecDeque::new(),
        }
    }
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.min(4096);
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
    }
    pub fn set_default_messages(&mut self, count: usize) {
        self.default_messages = count;
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add one room broadcast, before per-recipient routing. Subject-only changes
    /// are sent separately on join and do not consume discussion history slots.
    pub fn push(&mut self, stanza: &str, timestamp: i64) {
        if self.capacity == 0 || stanza.len() > 16 * 1024 {
            return;
        }
        let Ok(doc) = roxmltree::Document::parse(stanza) else {
            return;
        };
        let root = doc.root_element();
        if !is_historic(root) {
            return;
        }
        let from = root.attribute("from").unwrap_or("");
        let room = from.split('/').next().unwrap_or(from);
        let Some(time) = chrono::DateTime::from_timestamp(timestamp, 0) else {
            return;
        };
        let stamp = time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut packet = crate::protocol::address(root, from, "");
        let Some(end) = packet.rfind("</") else {
            return;
        };
        packet.insert_str(
            end,
            &format!(
                "<delay xmlns='urn:xmpp:delay' from='{}' stamp='{stamp}'/>",
                crate::wire::escape(room)
            ),
        );
        self.entries.push_back(Entry {
            stanza: packet,
            timestamp,
        });
        self.set_capacity(self.capacity);
    }

    /// The live snapshot keeps only the last message, matching native MUC state.
    pub fn last_message(&self) -> Option<(&str, i64)> {
        self.entries
            .back()
            .map(|entry| (entry.stanza.as_str(), entry.timestamp))
    }
    /// Restore a snapshot stanza that already carries its original delay.
    pub fn restore_last_message(&mut self, stanza: &str, timestamp: i64) {
        if self.capacity == 0 || stanza.len() > 16 * 1024 {
            return;
        }
        let Ok(doc) = roxmltree::Document::parse(stanza) else {
            return;
        };
        if !is_historic(doc.root_element()) {
            return;
        }
        self.entries.clear();
        self.entries.push_back(Entry {
            stanza: stanza.into(),
            timestamp,
        });
    }

    /// Lossless bounded crash snapshot, including original delay stamps.
    pub fn checkpoint(&self) -> crate::storage::LuaValue {
        use crate::storage::LuaValue as V;
        let mut value = V::table();
        for (i, entry) in self.entries.iter().enumerate() {
            let mut item = V::table();
            item.set("stanza", entry.stanza.clone().into());
            item.set("timestamp", V::Integer(entry.timestamp));
            value.set_key(V::Integer(i as i64 + 1), item);
        }
        value
    }
    pub fn restore_checkpoint(&mut self, value: &crate::storage::LuaValue) {
        self.entries.clear();
        // Lua pairs iteration is not sequence order, including numeric keys.
        let mut ordered = value
            .entries()
            .iter()
            .filter_map(|(key, item)| {
                key.as_i64()
                    .filter(|index| *index > 0)
                    .map(|index| (index, item))
            })
            .collect::<Vec<_>>();
        ordered.sort_by_key(|(index, _)| *index);
        for (_, item) in ordered.into_iter().take(4096) {
            let Some(stanza) = item
                .get("stanza")
                .and_then(crate::storage::LuaValue::as_str)
            else {
                continue;
            };
            let Some(timestamp) = item
                .get("timestamp")
                .and_then(crate::storage::LuaValue::as_i64)
            else {
                continue;
            };
            if stanza.len() > 16 * 1024 {
                continue;
            }
            let Ok(doc) = roxmltree::Document::parse(stanza) else {
                continue;
            };
            if is_historic(doc.root_element()) {
                self.entries.push_back(Entry {
                    stanza: stanza.into(),
                    timestamp,
                });
            }
        }
        self.set_capacity(self.capacity);
    }

    pub fn replay(&self, _room: &str, to: &str, presence: &str, now: i64) -> Vec<String> {
        let request = HistoryRequest::parse(presence, now);
        let max = request.maxstanzas.unwrap_or_else(|| {
            if request.has_constraints() {
                self.entries.len()
            } else {
                self.default_messages
            }
        });
        let mut packets = Vec::new();
        let mut chars = 0usize;
        for entry in self.entries.iter().rev().take(max) {
            if request
                .since
                .is_some_and(|since| (entry.timestamp as f64) < since)
            {
                break;
            }
            let Ok(doc) = roxmltree::Document::parse(&entry.stanza) else {
                continue;
            };
            let root = doc.root_element();
            let packet = crate::protocol::address(root, root.attribute("from").unwrap_or(""), to);
            chars = chars.saturating_add(packet.len());
            if request.maxchars.is_some_and(|limit| chars > limit) {
                break;
            }
            packets.push(packet);
        }
        packets.reverse();
        packets
    }
}

fn is_historic(stanza: roxmltree::Node<'_, '_>) -> bool {
    if stanza.tag_name().name() != "message" || stanza.attribute("type") != Some("groupchat") {
        return false;
    }
    let has =
        |name: &str, namespace: &str| stanza.children().any(|n| n.has_tag_name((namespace, name)));
    if has("no-store", "urn:xmpp:hints") || has("no-permanent-store", "urn:xmpp:hints") {
        return false;
    }
    has("store", "urn:xmpp:hints")
        || stanza.children().any(|n| {
            n.is_element()
                && n.tag_name().name() == "body"
                && matches!(n.tag_name().namespace(), None | Some("jabber:client"))
        })
        || has("encryption", "urn:xmpp:eme:0")
        || stanza
            .children()
            .any(|n| n.is_element() && n.tag_name().namespace() == Some("urn:xmpp:chat-markers:0"))
}
