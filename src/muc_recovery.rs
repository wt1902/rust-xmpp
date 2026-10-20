//! Bounded native Prosody MUC occupant checkpoints.
//!
//! A checkpoint describes prior membership, never a live transport. Callers must
//! keep recovered occupants out of routing until authenticated rejoin and current
//! room admission checks succeed. Saved roles are hints, not authorization.
use crate::{
    protocol::bare,
    storage::{self, LuaValue as V},
};
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, path::Path};

pub const MAX_OCCUPANTS: usize = 4096;
const MAX_FIELD: usize = 3072;
const MAX_PRESENCE: usize = 16 * 1024;
pub const RECOVERY_SECONDS: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccupantSnapshot {
    pub jid: String,
    pub nick: String,
    pub role: String,
    /// Only show/status/priority are retained. Passwords and extension payloads
    /// are intentionally excluded, including when reading native snapshots.
    pub presence_payload: String,
}
fn valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_FIELD && !s.chars().any(char::is_control)
}
fn room_node<'a>(room: &'a str, domain: &str) -> Result<&'a str> {
    let (node, host) = room.split_once('@').unwrap_or(("", ""));
    ensure!(
        valid(node) && host == domain && !room.contains('/'),
        "invalid recovery room"
    );
    Ok(node)
}
fn field<'a>(v: &'a V, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}
fn scalar_stanza(name: &str, text: &str) -> V {
    let mut v = V::table();
    v.set("name", name.into());
    v.set("attr", V::table());
    v.set_key(V::Integer(1), text.into());
    v
}
fn safe_payload(v: &V) -> String {
    let mut out = String::new();
    for (_, child) in v.entries() {
        let Some(name) = field(child, "name") else {
            continue;
        };
        if !matches!(name, "show" | "status" | "priority") {
            continue;
        }
        if child
            .get("attr")
            .and_then(|a| field(a, "xmlns"))
            .is_some_and(|ns| ns != "jabber:client")
        {
            continue;
        }
        let text = child
            .get_key(&V::Integer(1))
            .and_then(V::as_str)
            .unwrap_or("");
        if text.len() <= MAX_FIELD && out.len() + text.len() + 64 <= MAX_PRESENCE {
            out.push_str(&format!("<{name}>{}</{name}>", crate::wire::escape(text)));
        }
    }
    out
}
/// Decode Prosody's state store (and old frozen room maps) without trusting roles,
/// primary-session pointers, or unvalidated stanza extensions.
pub fn decode_room(room: &str, value: &V) -> Result<Vec<OccupantSnapshot>> {
    ensure!(valid(room) && !room.contains('/'), "invalid recovery room");
    ensure!(
        value.entries().len() <= MAX_OCCUPANTS * 2 + 16,
        "occupant recovery limit"
    );
    let prefix = format!("{room}/");
    let mut out = BTreeMap::new();
    for (key, presence) in value.entries() {
        let Some(jid) = key.as_str() else { continue };
        if !valid(jid)
            || !jid.contains('/')
            || jid.starts_with(&prefix)
            || field(presence, "name") != Some("presence")
        {
            continue;
        }
        let Some(attr) = presence.get("attr") else {
            continue;
        };
        if field(attr, "type").is_some() {
            continue;
        }
        let Some(occupant_jid) = field(attr, "from") else {
            continue;
        };
        let Some(nick) = occupant_jid.strip_prefix(&prefix).filter(|s| valid(s)) else {
            continue;
        };
        let Some(meta) = value.get(occupant_jid) else {
            continue;
        };
        if field(meta, "bare_jid") != Some(bare(jid)) {
            continue;
        }
        let Some(role) =
            field(meta, "role").filter(|r| matches!(*r, "visitor" | "participant" | "moderator"))
        else {
            continue;
        };
        out.insert(
            jid.to_owned(),
            OccupantSnapshot {
                jid: jid.into(),
                nick: nick.into(),
                role: role.into(),
                presence_payload: safe_payload(presence),
            },
        );
        ensure!(out.len() <= MAX_OCCUPANTS, "occupant recovery limit");
    }
    Ok(out.into_values().collect())
}

pub fn load_room(root: &Path, domain: &str, room: &str) -> Result<Vec<OccupantSnapshot>> {
    let node = room_node(room, domain)?;
    match storage::load(root, domain, Some(node), "state")? {
        Some(value) => decode_room(room, &value),
        None => Ok(Vec::new()),
    }
}
/// Write a Prosody-compatible state map atomically. Empty membership removes it.
pub fn save_room(
    root: &Path,
    domain: &str,
    room: &str,
    occupants: &[OccupantSnapshot],
) -> Result<()> {
    save_room_with_fingerprint(root, domain, room, occupants, None)
}

/// The optional digest binds automatic password-room recovery to its saved config.
pub fn save_room_with_fingerprint(
    root: &Path,
    domain: &str,
    room: &str,
    occupants: &[OccupantSnapshot],
    fingerprint: Option<&str>,
) -> Result<()> {
    let saved_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    save_room_checkpoint(root, domain, room, occupants, fingerprint, saved_at)
}

pub fn save_room_checkpoint(
    root: &Path,
    domain: &str,
    room: &str,
    occupants: &[OccupantSnapshot],
    fingerprint: Option<&str>,
    saved_at: u64,
) -> Result<()> {
    let node = room_node(room, domain)?;
    ensure!(saved_at <= i64::MAX as u64, "invalid checkpoint timestamp");
    ensure!(occupants.len() <= MAX_OCCUPANTS, "occupant recovery limit");
    let mut state = V::table();
    for o in occupants {
        ensure!(
            valid(&o.jid) && o.jid.contains('/') && valid(&o.nick),
            "invalid occupant recovery identity"
        );
        ensure!(
            matches!(o.role.as_str(), "visitor" | "participant" | "moderator"),
            "invalid recovery role"
        );
        let occupant_jid = format!("{room}/{}", o.nick);
        let mut meta = V::table();
        meta.set("bare_jid", bare(&o.jid).into());
        meta.set("jid", o.jid.clone().into());
        meta.set("role", o.role.clone().into());
        if let Some(previous) = state.get(&occupant_jid) {
            ensure!(
                field(previous, "bare_jid") == Some(bare(&o.jid)),
                "duplicate occupant nickname"
            );
        }
        state.set(&occupant_jid, meta);
        let mut presence = V::table();
        presence.set("name", "presence".into());
        let mut attr = V::table();
        attr.set("from", occupant_jid.into());
        attr.set("to", o.jid.clone().into());
        presence.set("attr", attr);
        // Status text is optional checkpoint data. Large or unparseable
        // client payloads must never prevent saving room membership at shutdown.
        if o.presence_payload.len() <= MAX_PRESENCE {
            let wrapped = format!("<presence>{}</presence>", o.presence_payload);
            if let Ok(doc) = roxmltree::Document::parse(&wrapped) {
                let mut index = 0;
                for child in doc.root_element().children().filter(|c| c.is_element()) {
                    let name = child.tag_name().name();
                    if !matches!(name, "show" | "status" | "priority")
                        || !matches!(child.tag_name().namespace(), None | Some("jabber:client"))
                    {
                        continue;
                    }
                    let text = child.text().unwrap_or("");
                    if text.len() > MAX_FIELD {
                        continue;
                    }
                    index += 1;
                    presence.set_key(V::Integer(index), scalar_stanza(name, text));
                }
            }
        }
        state.set(&o.jid, presence);
    }
    if !occupants.is_empty() {
        state.set("_rust_xmpp_saved_at", V::Integer(saved_at as i64));
        if let Some(fingerprint) = fingerprint {
            ensure!(
                fingerprint.len() == 64 && fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid recovery fingerprint"
            );
            state.set("_rust_xmpp_config_hash", fingerprint.into());
        }
    }
    storage::save(root, domain, Some(node), "state", &state)
}

/// Dormant claims have a fixed restart deadline; probes never extend it.
#[derive(Default)]
pub struct PendingOccupants {
    rooms: BTreeMap<String, (u64, Vec<OccupantSnapshot>)>,
}
impl PendingOccupants {
    pub fn insert(
        &mut self,
        room: String,
        occupants: Vec<OccupantSnapshot>,
        now: u64,
    ) -> Result<()> {
        ensure!(
            occupants.len() <= MAX_OCCUPANTS
                && self.rooms.values().map(|(_, v)| v.len()).sum::<usize>() + occupants.len()
                    <= MAX_OCCUPANTS,
            "pending recovery limit"
        );
        self.rooms
            .insert(room, (now.saturating_add(RECOVERY_SECONDS), occupants));
        Ok(())
    }
    /// Preserve a checkpoint's original deadline over repeated process restarts.
    pub fn insert_checkpoint(
        &mut self,
        room: String,
        occupants: Vec<OccupantSnapshot>,
        saved_at: u64,
        now: u64,
    ) -> Result<()> {
        if saved_at > now || saved_at.saturating_add(RECOVERY_SECONDS) <= now {
            return Ok(());
        }
        self.insert(room, occupants, saved_at)
    }
    /// Call only after authenticating the account and checking current room ACLs.
    /// Resource names alone never establish ownership, and old privilege must be
    /// recomputed by the caller rather than copied from the returned snapshot.
    pub fn claim(
        &mut self,
        room: &str,
        authenticated_jid: &str,
        nick: &str,
        now: u64,
    ) -> Option<OccupantSnapshot> {
        self.expire(now);
        let (_, occupants) = self.rooms.get_mut(room)?;
        let i = occupants
            .iter()
            .position(|o| o.jid == authenticated_jid && o.nick == nick)?;
        let mut claim = occupants.remove(i);
        claim.jid = authenticated_jid.into();
        Some(claim)
    }
    /// Candidate snapshots are still dormant. The caller rechecks admission
    /// before claim, and must not route to these identities beforehand.
    pub fn candidates(
        &mut self,
        authenticated_jid: &str,
        now: u64,
    ) -> Vec<(String, OccupantSnapshot)> {
        self.expire(now);
        self.rooms
            .iter()
            .flat_map(|(room, (_, occupants))| {
                occupants
                    .iter()
                    .filter(|o| o.jid == authenticated_jid)
                    .map(|o| (room.clone(), o.clone()))
            })
            .collect()
    }
    pub fn room_snapshot(&mut self, room: &str, now: u64) -> Option<(u64, Vec<OccupantSnapshot>)> {
        self.expire(now);
        self.rooms.get(room).map(|(deadline, occupants)| {
            (deadline.saturating_sub(RECOVERY_SECONDS), occupants.clone())
        })
    }
    /// Read-only membership probe; deadline-sensitive callers use contains_room.
    pub fn has_room(&self, room: &str) -> bool {
        self.rooms
            .get(room)
            .is_some_and(|(_, occupants)| !occupants.is_empty())
    }
    /// Live dormant identities for bounded admission accounting.
    pub fn identities(&self, now: u64) -> Vec<(String, String)> {
        self.rooms
            .iter()
            .filter(|(_, (deadline, _))| *deadline > now)
            .flat_map(|(room, (_, occupants))| {
                occupants.iter().map(|o| (room.clone(), o.jid.clone()))
            })
            .collect()
    }
    /// A dormant nickname remains owned by its authenticated bare account until
    /// claim expiry; a reused resource belonging to another account cannot take it.
    pub fn reserved_by(&self, room: &str, nick: &str, now: u64) -> Option<String> {
        let (deadline, occupants) = self.rooms.get(room)?;
        if *deadline <= now {
            return None;
        }
        occupants
            .iter()
            .find(|o| o.nick == nick)
            .map(|o| bare(&o.jid).to_owned())
    }
    pub fn contains_room(&mut self, room: &str, now: u64) -> bool {
        self.expire(now);
        self.rooms
            .get(room)
            .is_some_and(|(_, occupants)| !occupants.is_empty())
    }
    pub fn expire(&mut self, now: u64) -> usize {
        let mut removed = 0;
        self.rooms.retain(|_, (deadline, occupants)| {
            if *deadline <= now {
                removed += occupants.len();
                false
            } else {
                true
            }
        });
        removed
    }
    pub fn len(&self) -> usize {
        self.rooms.values().map(|(_, v)| v.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Hash canonical room contents. Lua table iteration order is not stable across
/// VM instances, so storage serialization order cannot be an authorization proof.
pub fn configuration_fingerprint(config: &V) -> Result<String> {
    use sha2::{Digest, Sha256};
    fn canonical(value: &V, depth: usize) -> Result<V> {
        ensure!(depth < 64, "configuration fingerprint depth limit");
        if let V::Table(entries) = value {
            let mut sorted = entries
                .iter()
                .map(|(key, value)| {
                    Ok((
                        storage::serialize(key)?,
                        key.clone(),
                        canonical(value, depth + 1)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(V::Table(
                sorted
                    .into_iter()
                    .map(|(_, key, value)| (key, value))
                    .collect(),
            ))
        } else {
            Ok(value.clone())
        }
    }
    Ok(hex::encode(Sha256::digest(
        storage::serialize(&canonical(config, 0)?)?.as_bytes(),
    )))
}

pub fn load_fingerprint(root: &Path, domain: &str, room: &str) -> Result<Option<String>> {
    let node = room_node(room, domain)?;
    Ok(storage::load(root, domain, Some(node), "state")?
        .and_then(|v| field(&v, "_rust_xmpp_config_hash").map(str::to_owned)))
}

/// Native snapshots have no timestamp; callers should stamp them once before
/// placing them in dormant recovery so subsequent restarts retain the deadline.
pub fn load_checkpoint_time(root: &Path, domain: &str, room: &str) -> Result<Option<u64>> {
    let node = room_node(room, domain)?;
    Ok(storage::load(root, domain, Some(node), "state")?
        .and_then(|v| v.get("_rust_xmpp_saved_at").and_then(V::as_i64))
        .and_then(|time| u64::try_from(time).ok()))
}

fn validate_last_message(room: &str, stanza: &str) -> Result<()> {
    ensure!(stanza.len() <= MAX_PRESENCE, "recovery last message limit");
    let doc = roxmltree::Document::parse(stanza)?;
    let root = doc.root_element();
    ensure!(
        root.tag_name().name() == "message"
            && matches!(
                root.tag_name().namespace(),
                None | Some("") | Some("jabber:client")
            ),
        "invalid recovery message namespace"
    );
    ensure!(
        root.attribute("type") == Some("groupchat"),
        "invalid recovery message type"
    );
    let from = root.attribute("from").unwrap_or("");
    ensure!(
        from == room
            || from
                .strip_prefix(room)
                .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1),
        "recovery message belongs to another room"
    );
    Ok(())
}

/// Preserve native Prosody's final history entry while keeping occupant state.
/// Call after saving the room checkpoint, which replaces the state map.
pub fn set_last_message(
    root: &Path,
    domain: &str,
    room: &str,
    message: Option<(&str, i64)>,
) -> Result<()> {
    let node = room_node(room, domain)?;
    let encoded = if let Some((stanza, timestamp)) = message {
        ensure!(timestamp >= 0, "invalid recovery message timestamp");
        validate_last_message(room, stanza)?;
        let doc = roxmltree::Document::parse(stanza)?;
        Some((storage::stanza_value(doc.root_element()), timestamp))
    } else {
        None
    };
    storage::update(root, domain, Some(node), "state", |state| {
        state.set(
            "_last_message",
            encoded.as_ref().map(|(v, _)| v.clone()).unwrap_or(V::Nil),
        );
        state.set(
            "_last_message_at",
            encoded
                .as_ref()
                .map(|(_, time)| V::Integer(*time))
                .unwrap_or(V::Nil),
        );
        Ok(())
    })?;
    Ok(())
}

pub fn load_last_message(root: &Path, domain: &str, room: &str) -> Result<Option<(String, i64)>> {
    let node = room_node(room, domain)?;
    let Some(state) = storage::load(root, domain, Some(node), "state")? else {
        return Ok(None);
    };
    let (Some(message), Some(timestamp)) =
        (state.get("_last_message"), state.get("_last_message_at"))
    else {
        return Ok(None);
    };
    let timestamp = match timestamp {
        V::Integer(value) if *value >= 0 => *value,
        V::Number(value) if value.is_finite() && *value >= 0.0 && *value < i64::MAX as f64 => {
            *value as i64
        }
        _ => return Ok(None),
    };
    ensure!(
        storage::serialize(message)?.len() <= MAX_PRESENCE * 2,
        "recovery last message limit"
    );
    let stanza = storage::stanza_xml(message)?;
    validate_last_message(room, &stanza)?;
    Ok(Some((stanza, timestamp)))
}
