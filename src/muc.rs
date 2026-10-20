//! Stateful XEP-0045 component. Room configuration uses Prosody's frozen-room layout.
use crate::{
    protocol::{ModuleResult, bare, iq_error, iq_result, xml},
    wire::escape,
};
use anyhow::Result;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf};
const MUC: &str = "http://jabber.org/protocol/muc";
const USER: &str = "http://jabber.org/protocol/muc#user";
const OWNER: &str = "http://jabber.org/protocol/muc#owner";
const ADMIN: &str = "http://jabber.org/protocol/muc#admin";
#[derive(Clone)]
struct Occupant {
    jid: String,
    nick: String,
    role: String,
    presence_payload: String,
}
struct Room {
    frozen: Value,
    original: crate::storage::LuaValue,
    occupants: BTreeMap<String, Occupant>,
    locked: bool,
    hats_compat: bool,
    force_archiving: bool,
    occupant_id_enabled: bool,
    history: crate::muc_history::RoomHistory,
}
impl Room {
    fn data(&self, k: &str) -> &Value {
        &self.frozen["_data"][k]
    }
    fn affiliation(&self, jid: &str) -> String {
        let affiliations = self.frozen.get("_affiliations").unwrap_or(&self.frozen);
        let jid = bare(jid);
        let host = jid.rsplit_once('@').map_or(jid, |(_, host)| host);
        affiliations
            .get(jid)
            .and_then(Value::as_str)
            .or_else(|| {
                (affiliations.get(host).and_then(Value::as_str) == Some("outcast"))
                    .then_some("outcast")
            })
            .unwrap_or("none")
            .into()
    }
    fn reserved_by(&self, nick: &str) -> Option<&str> {
        self.frozen
            .get("_affiliation_data")
            .and_then(Value::as_object)
            .and_then(|map| {
                map.iter()
                    .find(|(_, v)| v["reserved_nickname"].as_str() == Some(nick))
                    .map(|(k, _)| k.as_str())
            })
    }
    fn clear_data(&mut self, key: &str) {
        if let Some(data) = self.frozen.get_mut("_data").and_then(Value::as_object_mut) {
            data.remove(key);
        }
        let mut raw = self.original.get("_data").cloned().unwrap_or_default();
        raw.set(key, crate::storage::LuaValue::Nil);
        self.original.set("_data", raw);
    }
    fn occupant_id(&self, jid: &str) -> String {
        if !self.occupant_id_enabled {
            return String::new();
        }
        use base64::Engine;
        use hmac::{Hmac, Mac};
        // Prosody salts can contain arbitrary bytes, which the JSON view cannot
        // represent. Keep using the original bytes rather than replacing them.
        let raw_salt = self
            .original
            .get("_data")
            .and_then(|d| d.get("occupant_id_salt"));
        let salt = match raw_salt {
            Some(crate::storage::LuaValue::String(bytes)) => bytes.as_slice(),
            _ => self
                .data("occupant_id_salt")
                .as_str()
                .unwrap_or("")
                .as_bytes(),
        };
        let mut h = Hmac::<sha2::Sha256>::new_from_slice(bare(jid).as_bytes())
            .expect("HMAC accepts arbitrary keys");
        h.update(salt);
        format!(
            "<occupant-id xmlns='urn:xmpp:occupant-id:0' id='{}'/>",
            base64::engine::general_purpose::STANDARD.encode(h.finalize().into_bytes())
        )
    }
    fn privileged(&self, jid: &str) -> bool {
        matches!(self.affiliation(jid).as_str(), "owner" | "admin")
    }
    fn set_affiliation(&mut self, jid: &str, value: &str) {
        if value == "none" {
            if let Some(map) = self
                .frozen
                .get_mut("_affiliation_data")
                .and_then(Value::as_object_mut)
            {
                map.remove(jid);
            }
            let mut data = self
                .original
                .get("_affiliation_data")
                .cloned()
                .unwrap_or_default();
            data.set(jid, crate::storage::LuaValue::Nil);
            self.original.set("_affiliation_data", data);
            if let Some(map) = self
                .frozen
                .get_mut("_affiliations")
                .and_then(Value::as_object_mut)
            {
                map.remove(jid);
                let mut old = self
                    .original
                    .get("_affiliations")
                    .cloned()
                    .unwrap_or_default();
                old.set(jid, crate::storage::LuaValue::Nil);
                self.original.set("_affiliations", old);
            } else {
                if let Some(map) = self.frozen.as_object_mut() {
                    map.remove(jid);
                }
                self.original.set(jid, crate::storage::LuaValue::Nil);
            }
            return;
        }
        if self.frozen.get("_affiliations").is_some() {
            self.frozen["_affiliations"][jid] = json!(value);
        } else {
            self.frozen[jid] = json!(value);
        }
    }
    fn archiving(&self) -> bool {
        self.force_archiving || self.data("archiving").as_bool() == Some(true)
    }
    fn broadcasts(&self, role: &str) -> bool {
        match self.data("presence_broadcast").as_object() {
            Some(roles) => roles.get(role).and_then(Value::as_bool) == Some(true),
            None => role != "none",
        }
    }
    fn offline_affiliates(&self, room: &str, to: &Occupant) -> Vec<String> {
        if !self.broadcasts("none") {
            return Vec::new();
        }
        let public = self.data("whois").as_str() == Some("anyone") || to.role == "moderator";
        let affiliations = self.frozen.get("_affiliations").unwrap_or(&self.frozen);
        affiliations.as_object().into_iter().flatten().filter_map(|(jid,affiliation)| {
            let affiliation=affiliation.as_str()?;
            if bare(&to.jid)==jid || jid.starts_with('_') || !matches!(affiliation,"owner"|"admin"|"member"|"outcast") || self.occupants.values().any(|o|bare(&o.jid)==jid) {return None;}
            let nick=self.frozen["_affiliation_data"][jid]["reserved_nickname"].as_str();
            if nick.is_none() && !public {return None;}
            let from=nick.map(|nick|format!("{room}/{nick}")).unwrap_or_else(||room.into());
            let attrs=format!("{}{}",nick.map(|n|format!(" nick='{}'",escape(n))).unwrap_or_default(),if public {format!(" jid='{}'",escape(jid))}else{String::new()});
            Some(format!("<presence xmlns='jabber:client' from='{}' to='{}' type='unavailable'><x xmlns='{USER}'><item affiliation='{}' role='none'{attrs}/></x></presence>",escape(&from),escape(&to.jid),escape(affiliation)))
        }).collect()
    }
    fn hats(&self, jid: &str) -> String {
        let mut items = String::new();
        if let Some(hats) = self.frozen["_affiliation_data"][bare(jid)]["hats"].as_object() {
            for (uri, hat) in hats {
                if hat["active"].as_bool() == Some(true) {
                    items.push_str(&format!(
                        "<hat uri='{}'{} />",
                        escape(uri),
                        hat["title"]
                            .as_str()
                            .map(|v| format!(" title='{}'", escape(v)))
                            .unwrap_or_default()
                    ));
                }
            }
        }
        if items.is_empty() {
            return items;
        }
        let mut out = format!("<hats xmlns='urn:xmpp:hats:0'>{items}</hats>");
        if self.hats_compat {
            out.push_str(&format!(
                "<hats xmlns='xmpp:prosody.im/protocol/hats:1'>{items}</hats>"
            ));
        }
        out
    }
    fn allow_pm(&self) -> &str {
        match self.data("allow_pm").as_str().unwrap_or("visitor") {
            "everyone" | "anyone" => "visitor",
            "participants" => "participant",
            "moderators" => "moderator",
            "members" => "affiliated",
            v @ ("visitor" | "participant" | "moderator" | "affiliated" | "none") => v,
            _ => "visitor",
        }
    }
    fn pm_permitted(&self, from: &Occupant, to: &Occupant) -> bool {
        if bare(&from.jid) == bare(&to.jid) {
            return true;
        }
        if self.data("allow_modpm").as_bool() == Some(true)
            && (from.role == "moderator" || to.role == "moderator")
        {
            return true;
        }
        match self.allow_pm() {
            "visitor" => true,
            "participant" => matches!(from.role.as_str(), "participant" | "moderator"),
            "moderator" => from.role == "moderator",
            "affiliated" => self.affiliation(&from.jid) != "none",
            _ => false,
        }
    }
    fn presence(
        &self,
        room: &str,
        o: &Occupant,
        to: &Occupant,
        unavailable: bool,
        code: &str,
    ) -> String {
        if bare(&o.jid) != bare(&to.jid) && !self.broadcasts(&o.role) {
            return String::new();
        }
        self.presence_force(room, o, to, unavailable, code)
    }
    fn presence_force(
        &self,
        room: &str,
        o: &Occupant,
        to: &Occupant,
        unavailable: bool,
        code: &str,
    ) -> String {
        let show_jid = self.data("whois").as_str() == Some("anyone")
            || to.role == "moderator"
            || bare(&o.jid) == bare(&to.jid);
        let real = if show_jid {
            format!(" jid='{}'", escape(&o.jid))
        } else {
            String::new()
        };
        let role = if unavailable && code != "303" {
            "none"
        } else {
            &o.role
        };
        let mut status = String::new();
        if o.nick == to.nick && bare(&o.jid) == bare(&to.jid) {
            status.push_str("<status code='110'/>");
        }
        if !code.is_empty() {
            status.push_str(&format!("<status code='{code}'/>"));
        }
        format!(
            "<presence xmlns='jabber:client' from='{}/{}' to='{}'{}>{}<x xmlns='{USER}'><item affiliation='{}' role='{role}'{real}/>{status}</x>{}</presence>",
            escape(room),
            escape(&o.nick),
            escape(&to.jid),
            if unavailable {
                " type='unavailable'"
            } else {
                ""
            },
            o.presence_payload,
            self.affiliation(&o.jid),
            format_args!("{}{}", self.occupant_id(&o.jid), self.hats(&o.jid))
        )
    }
}
pub struct Muc {
    root: PathBuf,
    pub domain: String,
    rooms: BTreeMap<String, Room>,
    defaults: Value,
    pending_occupants: crate::muc_recovery::PendingOccupants,
    recovering_role: Option<String>,
    local_domain: Option<String>,
    tombstones: bool,
    room_locking: bool,
    log_all_rooms: bool,
    log_presences: bool,
    max_history_messages: usize,
    log_include_total: bool,
    occupant_id_enabled: bool,
    vcard_enabled: bool,
    hats_compat: bool,
    lock_timeout: f64,
    retention_seconds: Option<f64>,
    pending_iq: BTreeMap<String, (String, String, String, String, String, std::time::Instant)>,
}
impl Muc {
    pub fn new(root: PathBuf, domain: String) -> Self {
        Self {
            root,
            domain,
            rooms: BTreeMap::new(),
            local_domain: None,
            tombstones: true,
            room_locking: true,
            log_all_rooms: false,
            log_presences: false,
            max_history_messages: 100,
            log_include_total: true,
            occupant_id_enabled: true,
            vcard_enabled: true,
            hats_compat: false,
            lock_timeout: 300.0,
            retention_seconds: None,
            pending_iq: BTreeMap::new(),
            pending_occupants: Default::default(),
            recovering_role: None,
            defaults: json!({"hidden":true,"persistent":false,"whois":"moderators"}),
        }
    }
    /// Component options (already merged with global options), not a frozen room.
    pub fn set_component_options(&mut self, options: Value, mam_enabled: bool) {
        let flag = |name: &str, default: bool| {
            options
                .get(name)
                .and_then(Value::as_bool)
                .unwrap_or(default)
        };
        self.max_history_messages = options
            .get("max_history_messages")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .min(4096) as usize;
        self.occupant_id_enabled = flag("muc_occupant_id", true);
        self.vcard_enabled = flag("muc_vcard", true);
        self.log_all_rooms = mam_enabled && flag("muc_log_all_rooms", false);
        self.log_presences = mam_enabled && flag("muc_log_presences", false);
        self.log_include_total = flag("muc_log_include_total", true);
        self.hats_compat = flag("muc_hats_compat", false);
        self.room_locking = flag("muc_room_locking", true);
        self.lock_timeout = options
            .get("muc_room_lock_timeout")
            .and_then(Value::as_f64)
            .unwrap_or(300.0);
        self.defaults = json!({
            "language":options.get("muc_room_default_language").and_then(Value::as_str),
            "presence_broadcast":options.get("muc_room_default_presence_broadcast").cloned().unwrap_or(Value::Null),
            "allow_pm":options.get("muc_room_default_allow_pm").and_then(Value::as_str).unwrap_or("visitor"),
            "allow_modpm":flag("muc_room_default_always_allow_moderator_pms",false),
            "hidden":!flag("muc_room_default_public",false),
            "persistent":flag("muc_room_default_persistent",false),
            "members_only":flag("muc_room_default_members_only",false),
            "moderated":flag("muc_room_default_moderated",false),
            "changesubject":flag("muc_room_default_change_subject",false),
            "allow_member_invites":flag("muc_room_default_allow_member_invites",false),
            "whois":if flag("muc_room_default_public_jids",false){"anyone"}else{"moderators"},
            "archiving":mam_enabled&&flag("muc_log_by_default",true),
            "history_length":options.get("muc_room_default_history_length").and_then(Value::as_u64).unwrap_or(20).min(options.get("max_history_messages").and_then(Value::as_u64).unwrap_or(100).min(4096)),
        });
        if let Some(max) = options
            .get("muc_room_default_max_occupants")
            .and_then(Value::as_u64)
        {
            self.defaults["max_occupants"] = json!(max);
        }
    }
    fn frozen_room(room: &Room) -> crate::storage::LuaValue {
        let mut value = room.original.clone();
        merge_value(&mut value, &room.frozen);
        value
    }
    /// Read dormant native checkpoints without activating any routing targets.
    pub fn prepare_recovery(&mut self) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        if let Some(index) = crate::storage::load(&self.root, &self.domain, None, "persistent")? {
            for (key, _) in index.entries() {
                let Some(name) = key
                    .as_str()
                    .filter(|r| r.ends_with(&format!("@{}", self.domain)))
                else {
                    continue;
                };
                self.load(name)?;
                let Some(room) = self.rooms.get(name) else {
                    continue;
                };
                if room.data("destroyed").as_bool() == Some(true) {
                    continue;
                }
                let fingerprint =
                    crate::muc_recovery::configuration_fingerprint(&Self::frozen_room(room))?;
                if crate::muc_recovery::load_fingerprint(&self.root, &self.domain, name)?.as_deref()
                    != Some(fingerprint.as_str())
                {
                    continue;
                }
                let saved_at =
                    crate::muc_recovery::load_checkpoint_time(&self.root, &self.domain, name)?
                        .unwrap_or(0);
                if now.saturating_sub(saved_at) >= crate::muc_recovery::RECOVERY_SECONDS {
                    continue;
                }
                let occupants = crate::muc_recovery::load_room(&self.root, &self.domain, name)?;
                self.pending_occupants
                    .insert_checkpoint(name.into(), occupants, saved_at, now)?;
            }
        }
        Ok(())
    }
    /// Freeze room metadata and live occupants before transport teardown.
    pub fn checkpoint_live(&mut self) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        for (name, room) in &self.rooms {
            if room.data("destroyed").as_bool() == Some(true) {
                continue;
            }
            let config = Self::frozen_room(room);
            crate::storage::atomic_write(
                &self.path(name),
                crate::storage::serialize(&config)?.as_bytes(),
            )?;
            crate::storage::update(&self.root, &self.domain, None, "persistent", |v| {
                v.set(name, crate::storage::LuaValue::Bool(true));
                Ok(())
            })?;
            let fingerprint = crate::muc_recovery::configuration_fingerprint(&config)?;
            let mut occupants = room
                .occupants
                .values()
                .map(|o| crate::muc_recovery::OccupantSnapshot {
                    jid: o.jid.clone(),
                    nick: o.nick.clone(),
                    role: o.role.clone(),
                    presence_payload: o.presence_payload.clone(),
                })
                .collect::<Vec<_>>();
            let mut saved_at = now;
            if crate::muc_recovery::load_fingerprint(&self.root, &self.domain, name)?.as_deref()
                == Some(fingerprint.as_str())
                && let Some((pending_at, pending)) = self.pending_occupants.room_snapshot(name, now)
            {
                if !pending.is_empty() {
                    saved_at = pending_at;
                }
                for snapshot in pending {
                    if occupants.len() < crate::muc_recovery::MAX_OCCUPANTS
                        && !occupants.iter().any(|o| o.jid == snapshot.jid)
                    {
                        occupants.push(snapshot);
                    }
                }
            }
            crate::muc_recovery::save_room_checkpoint(
                &self.root,
                &self.domain,
                name,
                &occupants,
                Some(&fingerprint),
                saved_at,
            )?;
            crate::muc_recovery::set_last_message(
                &self.root,
                &self.domain,
                name,
                room.history
                    .last_message()
                    .filter(|(packet, _)| packet.len() <= 16 * 1024),
            )?;
        }
        Ok(())
    }
    fn consume_recovery_checkpoint(&self, room: &str, jid: &str) -> Result<()> {
        let mut remaining = crate::muc_recovery::load_room(&self.root, &self.domain, room)?;
        remaining.retain(|o| o.jid != jid);
        let fingerprint = crate::muc_recovery::load_fingerprint(&self.root, &self.domain, room)?;
        let saved_at =
            crate::muc_recovery::load_checkpoint_time(&self.root, &self.domain, room)?.unwrap_or(0);
        let last = crate::muc_recovery::load_last_message(&self.root, &self.domain, room)?;
        crate::muc_recovery::save_room_checkpoint(
            &self.root,
            &self.domain,
            room,
            &remaining,
            fingerprint.as_deref(),
            saved_at,
        )?;
        crate::muc_recovery::set_last_message(
            &self.root,
            &self.domain,
            room,
            last.as_ref().map(|(xml, when)| (xml.as_str(), *when)),
        )?;
        Ok(())
    }
    /// Called only for an authenticated full JID's initial available presence.
    pub fn restore_for_session(&mut self, jid: &str) -> Result<ModuleResult> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let mut out = ModuleResult::default();
        for (name, snapshot) in self.pending_occupants.candidates(jid, now) {
            let Some(room) = self.rooms.get(&name) else {
                continue;
            };
            let fingerprint =
                crate::muc_recovery::configuration_fingerprint(&Self::frozen_room(room))?;
            if crate::muc_recovery::load_fingerprint(&self.root, &self.domain, &name)?.as_deref()
                != Some(fingerprint.as_str())
            {
                continue;
            }
            if room.occupants.contains_key(jid) {
                self.consume_recovery_checkpoint(&name, jid)?;
                self.pending_occupants
                    .claim(&name, jid, &snapshot.nick, now);
                continue;
            }
            let password = room
                .data("password")
                .as_str()
                .filter(|p| !p.is_empty())
                .map(|p| format!("<x xmlns='{MUC}'><password>{}</password></x>", escape(p)))
                .unwrap_or_default();
            let packet = format!(
                "<presence to='{}/{}'>{}{password}</presence>",
                escape(&name),
                escape(&snapshot.nick),
                snapshot.presence_payload
            );
            let doc = roxmltree::Document::parse(&packet)?;
            self.recovering_role = Some(snapshot.role.clone());
            let restored = self.handle(jid, doc.root_element());
            self.recovering_role = None;
            if let Some(mut restored) = restored? {
                let joined = self.rooms.get(&name).is_some_and(|room| {
                    room.occupants
                        .get(jid)
                        .is_some_and(|o| o.nick == snapshot.nick)
                });
                if joined {
                    if let Err(error) = self.consume_recovery_checkpoint(&name, jid) {
                        if let Some(room) = self.rooms.get_mut(&name) {
                            room.occupants.remove(jid);
                        }
                        return Err(error);
                    }
                    self.pending_occupants
                        .claim(&name, jid, &snapshot.nick, now);
                    out.replies.append(&mut restored.replies);
                    out.deliveries.append(&mut restored.deliveries);
                }
            }
        }
        Ok(out)
    }
    pub fn set_tombstones(&mut self, enabled: bool) {
        self.tombstones = enabled;
    }
    pub fn set_archive_retention(&mut self, seconds: Option<f64>) {
        self.retention_seconds = seconds;
    }
    pub fn set_local_domain(&mut self, domain: String) {
        self.local_domain = Some(domain);
    }
    pub fn set_defaults(&mut self, defaults: Value) {
        self.defaults = defaults;
    }
    fn path(&self, room: &str) -> PathBuf {
        self.root
            .join(crate::storage::encode_name(&self.domain))
            .join("config")
            .join(format!(
                "{}.dat",
                crate::storage::encode_name(room.split('@').next().unwrap_or(room))
            ))
    }
    fn load(&mut self, room: &str) -> Result<()> {
        if self.rooms.contains_key(room) {
            return Ok(());
        }
        let p = self.path(room);
        if p.exists() {
            let original = crate::storage::parse(&std::fs::read(&p)?)?;
            let mut value = view_value(&original);
            if value["_data"]["archiving"].is_null() {
                value["_data"]["archiving"] = self.defaults["archiving"].clone();
            }
            if !matches!(
                original
                    .get("_data")
                    .and_then(|d| d.get("occupant_id_salt")),
                Some(crate::storage::LuaValue::String(_))
            ) {
                value["_data"]["occupant_id_salt"] = json!(uuid::Uuid::new_v4().to_string());
            }
            let mut history = crate::muc_history::RoomHistory::new(
                value["_data"]["history_length"].as_u64().unwrap_or(20) as usize,
            );
            if let Some((packet, when)) =
                crate::muc_recovery::load_last_message(&self.root, &self.domain, room)?
            {
                history.restore_last_message(&packet, when);
            }
            self.rooms.insert(
                room.into(),
                Room {
                    frozen: value.clone(),
                    original,
                    occupants: BTreeMap::new(),
                    history,
                    occupant_id_enabled: self.occupant_id_enabled,
                    force_archiving: self.log_all_rooms,
                    hats_compat: self.hats_compat,
                    locked: value["_data"]["locked"].as_bool() == Some(true)
                        || value["_data"]["locked"].as_f64().is_some_and(|v| {
                            v > std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs_f64()
                        }),
                },
            );
        }
        Ok(())
    }
    fn save(&self, room: &str) -> Result<()> {
        if self.recovering_role.is_some() {
            return Ok(());
        }
        let r = &self.rooms[room];
        if r.data("persistent").as_bool() == Some(true) || self.pending_occupants.has_room(room) {
            let mut merged = r.original.clone();
            merge_value(&mut merged, &r.frozen);
            crate::storage::atomic_write(
                &self.path(room),
                crate::storage::serialize(&merged)?.as_bytes(),
            )?;
            let path = self
                .root
                .join(crate::storage::encode_name(&self.domain))
                .join("persistent.dat");
            let mut index = if path.exists() {
                read_value(&path)?
            } else {
                json!({})
            };
            index[room] = json!(true);
            write_value(&path, &index)?;
        } else if self.path(room).exists() {
            std::fs::remove_file(self.path(room))?;
            crate::storage::update(&self.root, &self.domain, None, "persistent", |v| {
                v.set(room, crate::storage::LuaValue::Nil);
                Ok(())
            })?;
        }
        Ok(())
    }
    fn delete_saved_room(&self, room: &str) -> Result<()> {
        let node = room.split('@').next().unwrap();
        for store in ["config", "state"] {
            let path = crate::storage::path(&self.root, &self.domain, Some(node), store);
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        if crate::storage::path(&self.root, &self.domain, None, "persistent").exists() {
            crate::storage::update(&self.root, &self.domain, None, "persistent", |v| {
                v.set(room, crate::storage::LuaValue::Nil);
                Ok(())
            })?;
        }
        Ok(())
    }
    /// Periodic maintenance, including rooms which have not received traffic.
    /// Caller may invoke once a minute; `now` is UTC Unix seconds.
    pub fn maintenance(&mut self, now: f64) -> Result<()> {
        anyhow::ensure!(
            now.is_finite() && now >= 0.0,
            "invalid maintenance timestamp"
        );
        if let Some(index) = crate::storage::load(&self.root, &self.domain, None, "persistent")? {
            for (k, _) in index.entries() {
                if let Some(room) = k
                    .as_str()
                    .filter(|r| r.ends_with(&format!("@{}", self.domain)))
                {
                    self.load(room)?;
                }
            }
        }
        let names = self.rooms.keys().cloned().collect::<Vec<_>>();
        self.pending_occupants.expire(now as u64);
        for name in names {
            if self.rooms[&name].occupants.is_empty()
                && self.rooms[&name].data("persistent").as_bool() != Some(true)
                && !self.pending_occupants.contains_room(&name, now as u64)
            {
                self.delete_saved_room(&name)?;
                self.rooms.remove(&name);
                continue;
            }
            let room = &self.rooms[&name];
            if room.data("destroyed").as_bool() == Some(true)
                && room
                    .data("locked")
                    .as_f64()
                    .is_some_and(|until| until <= now)
            {
                self.delete_saved_room(&name)?;
                self.rooms.remove(&name);
                continue;
            }
            if let Some(seconds) = self.retention_seconds {
                crate::archive::expire_before(
                    &self.root,
                    &self.domain,
                    Some(name.split('@').next().unwrap()),
                    "muc_log",
                    now - seconds,
                )?;
            }
            let room = self.rooms.get_mut(&name).unwrap();
            if room.locked
                && room
                    .data("locked")
                    .as_f64()
                    .is_some_and(|until| until <= now)
            {
                room.locked = false;
                room.clear_data("locked");
                self.save(&name)?;
            }
        }
        Ok(())
    }
    pub fn disconnect(&mut self, jid: &str) -> ModuleResult {
        let mut out = ModuleResult::default();
        for (name, r) in &mut self.rooms {
            if let Some(o) = r.occupants.remove(jid) {
                if r.occupants.values().any(|other| other.nick == o.nick) {
                    continue;
                }
                if self.log_presences
                    && r.archiving()
                    && let Err(e) = archive_presence(&self.root, &self.domain, name, &o.nick, true)
                {
                    eprintln!("MUC presence archive failed: {e}");
                }
                for target in r.occupants.values() {
                    out.deliveries
                        .push((target.jid.clone(), r.presence(name, &o, target, true, "")));
                }
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expired = self
            .rooms
            .iter()
            .filter(|(name, r)| {
                r.occupants.is_empty()
                    && r.data("persistent").as_bool() != Some(true)
                    && !self.pending_occupants.contains_room(name, now)
            })
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for name in expired {
            match self.delete_saved_room(&name) {
                Ok(()) => {
                    self.rooms.remove(&name);
                }
                Err(e) => eprintln!("MUC temporary room cleanup failed: {e}"),
            }
        }
        out.deliveries.retain(|(_, p)| !p.is_empty());
        out
    }
    pub fn handle(&mut self, jid: &str, stanza: roxmltree::Node) -> Result<Option<ModuleResult>> {
        let target = bare(stanza.attribute("to").unwrap_or(""));
        let was_occupant = self
            .rooms
            .get(target)
            .is_some_and(|r| r.occupants.contains_key(jid));
        let mut result = self.handle_inner(jid, stanza)?;
        if self.recovering_role.is_none()
            && stanza.tag_name().name() == "presence"
            && !matches!(stanza.attribute("type"), Some("unavailable" | "error"))
            && self
                .rooms
                .get(target)
                .is_some_and(|r| r.occupants.contains_key(jid))
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            if let Some((_, snapshot)) = self
                .pending_occupants
                .candidates(jid, now)
                .into_iter()
                .find(|(room, _)| room == target)
            {
                if let Err(error) = self.consume_recovery_checkpoint(target, jid) {
                    if !was_occupant && let Some(room) = self.rooms.get_mut(target) {
                        room.occupants.remove(jid);
                    }
                    return Err(error);
                }
                self.pending_occupants
                    .claim(target, jid, &snapshot.nick, now);
            }
        }
        if let Some(out) = &mut result {
            for reply in &mut out.replies {
                if !self.occupant_id_enabled {
                    *reply = reply.replace("<feature var='urn:xmpp:occupant-id:0'/>", "");
                }
                if !self.vcard_enabled {
                    *reply = reply.replace("<feature var='vcard-temp'/>", "");
                }
            }
            out.replies.retain(|p| !p.is_empty());
            out.deliveries.retain(|(_, p)| !p.is_empty());
        }
        Ok(result)
    }
    fn handle_inner(&mut self, jid: &str, stanza: roxmltree::Node) -> Result<Option<ModuleResult>> {
        let to = stanza.attribute("to").unwrap_or("");
        let room = bare(to);
        if room != self.domain && !room.ends_with(&format!("@{}", self.domain)) {
            return Ok(None);
        }
        let kind = stanza.tag_name().name();
        let typ = stanza.attribute("type").unwrap_or("");
        let mut out = ModuleResult::default();
        if kind == "message" && typ == "error"
            || kind == "iq" && matches!(typ, "result" | "error") && !to.contains('/')
        {
            return Ok(Some(out));
        }
        if room == self.domain {
            if let Some(index) = crate::storage::load(&self.root, &self.domain, None, "persistent")?
            {
                for (k, _) in index.entries() {
                    if let Some(room) = k.as_str()
                        && room.ends_with(&format!("@{}", self.domain))
                    {
                        self.load(room)?;
                    }
                }
            }
            if kind == "iq" && typ == "get" {
                let query = stanza.children().find(|n| n.is_element());
                if let Some(q) = query {
                    if q.has_tag_name(("http://jabber.org/protocol/muc#unique", "unique")) {
                        return Ok(Some(ModuleResult::reply(iq_result(
                            stanza,
                            &format!(
                                "<unique xmlns='http://jabber.org/protocol/muc#unique'>{}</unique>",
                                uuid::Uuid::new_v4()
                            ),
                        ))));
                    }
                    match q.tag_name().namespace().unwrap_or("") {"http://jabber.org/protocol/disco#info"=>out.replies.push(iq_result(stanza,&format!("<query xmlns='http://jabber.org/protocol/disco#info'><identity category='conference' type='text' name='Chatrooms'/><feature var='{MUC}'/><feature var='urn:xmpp:occupant-id:0'/></query>"))),"http://jabber.org/protocol/disco#items"=>{let mut items=String::new();for (n,r) in &self.rooms {if r.data("hidden").as_bool()!=Some(true){items.push_str(&format!("<item jid='{}' name='{}'/>",escape(n),escape(r.data("name").as_str().unwrap_or(n))));}}out.replies.push(iq_result(stanza,&format!("<query xmlns='http://jabber.org/protocol/disco#items'>{items}</query>")));},_=>out.replies.push(iq_error(stanza,"feature-not-implemented"))}
                }
            } else {
                out.replies.push(error(stanza, "service-unavailable"));
            }
            return Ok(Some(out));
        }
        self.load(room)?;
        if let Some(r) = self.rooms.get(room)
            && r.data("destroyed").as_bool() == Some(true)
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs_f64();
            if r.data("locked").as_f64().is_none_or(|expiry| now < expiry) {
                return Ok(Some(ModuleResult::reply(error(stanza, "gone"))));
            }
            self.delete_saved_room(room)?;
            self.rooms.remove(room);
        }
        if let Some(r) = self.rooms.get_mut(room)
            && r.locked
            && r.data("locked").as_f64().is_some_and(|until| {
                until
                    <= std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64()
            })
        {
            r.locked = false;
            r.clear_data("locked");
        }
        if kind == "presence" && typ != "unavailable" && typ != "error" {
            let nick_owned = to
                .split_once('/')
                .map(|(_, n)| n.to_owned())
                .or_else(|| {
                    self.rooms
                        .get(room)
                        .and_then(|r| r.occupants.get(jid))
                        .map(|o| o.nick.clone())
                })
                .unwrap_or_default();
            let nick = nick_owned.as_str();
            if nick.is_empty() {
                out.replies.push(error(stanza, "jid-malformed"));
                return Ok(Some(out));
            }
            let prepared = match stringprep::resourceprep(nick) {
                Ok(v) => v,
                Err(_) => return Ok(Some(ModuleResult::reply(error(stanza, "jid-malformed")))),
            };
            let nick = prepared.as_ref();
            let created = !self.rooms.contains_key(room);
            if created
                && self
                    .local_domain
                    .as_ref()
                    .is_some_and(|d| bare(jid).split_once('@').map(|(_, h)| h) != Some(d.as_str()))
            {
                return Ok(Some(ModuleResult::reply(error(stanza, "forbidden"))));
            }
            if created {
                let mut frozen =
                    json!({"_jid":room,"_data":self.defaults.clone(),"_affiliation_data":{}});
                frozen[jid.split('/').next().unwrap_or(jid)] = json!("owner");
                frozen["_data"]["occupant_id_salt"] = json!(uuid::Uuid::new_v4().to_string());
                let locked =
                    self.room_locking && stanza.children().any(|n| n.has_tag_name((MUC, "x")));
                if locked {
                    frozen["_data"]["locked"] = json!(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs_f64()
                            + self.lock_timeout
                    );
                }
                self.rooms.insert(
                    room.into(),
                    Room {
                        history: crate::muc_history::RoomHistory::new(
                            frozen["_data"]["history_length"].as_u64().unwrap_or(20) as usize,
                        ),
                        frozen,
                        original: crate::storage::LuaValue::table(),
                        occupants: BTreeMap::new(),
                        locked,
                        occupant_id_enabled: self.occupant_id_enabled,
                        force_archiving: self.log_all_rooms,
                        hats_compat: self.hats_compat,
                    },
                );
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let mut identities = self
                .rooms
                .iter()
                .flat_map(|(name, r)| {
                    r.occupants
                        .keys()
                        .map(move |jid| (name.clone(), jid.clone()))
                })
                .collect::<std::collections::BTreeSet<_>>();
            identities.extend(self.pending_occupants.identities(now));
            if !identities.contains(&(room.to_string(), jid.to_string()))
                && identities.len() >= crate::muc_recovery::MAX_OCCUPANTS
            {
                return Ok(Some(ModuleResult::reply(error(
                    stanza,
                    "service-unavailable",
                ))));
            }
            if self
                .pending_occupants
                .reserved_by(room, nick, now)
                .is_some_and(|owner| owner != bare(jid))
            {
                return Ok(Some(ModuleResult::reply(error(stanza, "conflict"))));
            }
            let r = self.rooms.get_mut(room).unwrap();
            let aff = r.affiliation(jid);
            if r.reserved_by(nick).is_some_and(|owner| owner != bare(jid)) {
                return Ok(Some(ModuleResult::reply(error(stanza, "conflict"))));
            }
            let fail = if aff == "outcast" {
                Some("forbidden")
            } else if r.locked && aff != "owner" {
                Some("item-not-found")
            } else if r.data("members_only").as_bool() == Some(true) && aff == "none" {
                Some("registration-required")
            } else if r
                .occupants
                .values()
                .any(|o| o.nick == nick && bare(&o.jid) != bare(jid))
            {
                Some("conflict")
            } else {
                None
            };
            if let Some(f) = fail {
                out.replies.push(error(stanza, f));
                return Ok(Some(out));
            }
            if !r.occupants.contains_key(jid)
                && !r.occupants.values().any(|o| o.nick == nick)
                && let Some(max) = r.data("max_occupants").as_u64()
            {
                let count = r
                    .occupants
                    .values()
                    .map(|o| o.nick.as_str())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();
                if count >= max as usize && !r.privileged(jid) {
                    return Ok(Some(ModuleResult::reply(error(
                        stanza,
                        "service-unavailable",
                    ))));
                }
            }
            if let Some(password) = r.data("password").as_str().filter(|p| !p.is_empty()) {
                let supplied = stanza
                    .descendants()
                    .find(|n| {
                        n.is_element()
                            && n.tag_name().name() == "password"
                            && n.tag_name().namespace() == Some(MUC)
                    })
                    .and_then(|n| n.text());
                if supplied != Some(password) && !r.occupants.contains_key(jid) {
                    out.replies.push(error(stanza, "not-authorized"));
                    return Ok(Some(out));
                }
            }
            if let Some(old) = r.occupants.get(jid)
                && old.nick != nick
            {
                let remains = r
                    .occupants
                    .values()
                    .any(|other| other.nick == old.nick && other.jid != jid);
                for target in r.occupants.values() {
                    if remains && target.jid != jid {
                        continue;
                    }
                    let p = r
                        .presence(room, old, target, true, "303")
                        .replace("<item ", &format!("<item nick='{}' ", escape(nick)));
                    if target.jid == jid {
                        out.replies.push(p);
                    } else {
                        out.deliveries.push((target.jid.clone(), p));
                    }
                }
            }
            let role = if let Some(old) = r.occupants.get(jid).or_else(|| {
                r.occupants
                    .values()
                    .find(|o| o.nick == nick && bare(&o.jid) == bare(jid))
            }) {
                old.role.as_str()
            } else if let Some(role) = self.recovering_role.as_deref() {
                role
            } else if r.privileged(jid) {
                "moderator"
            } else if r.data("moderated").as_bool() == Some(true) && aff == "none" {
                "visitor"
            } else {
                "participant"
            };
            let o = Occupant {
                jid: jid.into(),
                nick: nick.into(),
                role: role.into(),
                presence_payload: stanza
                    .children()
                    .filter(|n| {
                        n.is_element()
                            && matches!(n.tag_name().namespace(), None | Some("jabber:client"))
                            && matches!(n.tag_name().name(), "show" | "status" | "priority")
                    })
                    .map(xml)
                    .collect(),
            };
            let new_occupant = !r.occupants.values().any(|o| o.nick == nick);
            let first_join = !r.occupants.contains_key(jid);
            if first_join {
                let mut seen = std::collections::BTreeSet::new();
                for existing in r.occupants.values() {
                    if existing.nick == nick || !seen.insert(existing.nick.clone()) {
                        continue;
                    }
                    out.replies.push(r.presence(room, existing, &o, false, ""));
                }
            }
            if first_join {
                out.replies.extend(r.offline_affiliates(room, &o));
            }
            r.occupants.insert(jid.into(), o.clone());
            for target in r.occupants.values() {
                let p = r.presence(
                    room,
                    &o,
                    target,
                    false,
                    if created && target.jid == jid {
                        "201"
                    } else {
                        ""
                    },
                );
                if target.jid == jid {
                    out.replies.push(p);
                } else {
                    out.deliveries.push((target.jid.clone(), p));
                }
            }
            if first_join && !r.archiving() {
                let capacity = r
                    .data("history_length")
                    .as_u64()
                    .unwrap_or(20)
                    .min(self.max_history_messages as u64) as usize;
                let default_messages =
                    r.data("default_history_messages").as_u64().unwrap_or(20) as usize;
                r.history.set_capacity(capacity);
                r.history.set_default_messages(default_messages);
                out.replies.extend(
                    r.history.replay(
                        room,
                        jid,
                        &xml(stanza),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs() as i64,
                    ),
                );
            }
            if first_join && r.archiving() {
                let history = stanza
                    .descendants()
                    .find(|n| n.has_tag_name((MUC, "history")));
                let max = history
                    .and_then(|h| h.attribute("maxstanzas"))
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(r.data("history_length").as_u64().unwrap_or(20) as usize)
                    .min(self.max_history_messages);
                let seconds = history
                    .and_then(|h| h.attribute("seconds"))
                    .and_then(|v| v.parse::<u64>().ok());
                let oldest = seconds.map(|v| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64()
                        - v as f64
                });
                let since = history
                    .and_then(|h| h.attribute("since"))
                    .and_then(|v| crate::archive::parse_time(v).ok());
                let cutoff = self.retention_seconds.map(|s| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64()
                        - s
                });
                let mut recent = std::collections::VecDeque::with_capacity(max);
                if max > 0 {
                    crate::archive::scan_store(
                        &self.root,
                        &self.domain,
                        Some(room.split('@').next().unwrap()),
                        "muc_log",
                        |entry| {
                            if entry.peer == "message<groupchat"
                                && since.is_none_or(|t| entry.when >= t)
                                && oldest.is_none_or(|t| entry.when >= t)
                                && cutoff.is_none_or(|t| entry.when >= t)
                            {
                                if recent.len() == max {
                                    recent.pop_front();
                                }
                                recent.push_back(entry);
                            }
                            Ok(())
                        },
                    )?;
                }
                let maxchars = history
                    .and_then(|h| h.attribute("maxchars"))
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(usize::MAX);
                let mut chars = 0usize;
                let selected = recent
                    .iter()
                    .rev()
                    .take(max)
                    .take_while(|e| {
                        chars = chars.saturating_add(e.xml.chars().count());
                        chars <= maxchars
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                for e in selected.into_iter().rev() {
                    let archived =
                        sanitize_archived(&e.xml, r.data("whois").as_str() == Some("anyone"))?;
                    let delay = format!(
                        "<delay xmlns='urn:xmpp:delay' from='{}' stamp='{}'/>",
                        escape(room),
                        crate::archive::timestamp(e.when)?
                    );
                    let packet = archived
                        .rsplit_once("</message>")
                        .map(|(start, _)| format!("{start}{delay}</message>"))
                        .unwrap_or_else(|| archived.clone());
                    out.replies.push(packet);
                }
            }
            out.replies.push(format!("<message xmlns='jabber:client' from='{}' type='groupchat'><subject>{}</subject></message>",escape(room),escape(r.data("subject").as_str().unwrap_or(""))));
            if self.vcard_enabled
                && first_join
                && let Some(hash) = avatar_hash(&self.root, &self.domain, room)?
            {
                out.replies.push(format!("<presence xmlns='jabber:client' from='{}'><x xmlns='vcard-temp:x:update'><photo>{hash}</photo></x></presence>",escape(room)));
            }
            if new_occupant && self.log_presences && r.archiving() {
                archive_presence(&self.root, &self.domain, room, nick, false)?;
            }
            self.save(room)?;
            return Ok(Some(out));
        }
        let Some(r) = self.rooms.get_mut(room) else {
            out.replies.push(error(stanza, "item-not-found"));
            return Ok(Some(out));
        };
        if kind == "presence" && (typ == "unavailable" || typ == "error") {
            if let Some(o) = r.occupants.remove(jid) {
                out.replies.push(r.presence(room, &o, &o, true, ""));
                let remains = r.occupants.values().any(|other| other.nick == o.nick);
                if !remains && self.log_presences && r.archiving() {
                    archive_presence(&self.root, &self.domain, room, &o.nick, true)?;
                }
                for target in r.occupants.values() {
                    if remains {
                        continue;
                    }
                    out.deliveries
                        .push((target.jid.clone(), r.presence(room, &o, target, true, "")));
                }
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let remove = r.occupants.is_empty()
                && r.data("persistent").as_bool() != Some(true)
                && !self.pending_occupants.contains_room(room, now);
            if remove {
                self.delete_saved_room(room)?;
                self.rooms.remove(room);
            }
            return Ok(Some(out));
        }
        if kind == "message" {
            if let Some(x) = stanza.children().find(|n| n.has_tag_name((USER, "x"))) {
                if let Some(decline) = x.children().find(|n| n.tag_name().name() == "decline") {
                    let Some(target) = decline
                        .attribute("to")
                        .filter(|s| !s.is_empty() && !s.contains(char::is_whitespace))
                    else {
                        return Ok(Some(ModuleResult::reply(error(stanza, "jid-malformed"))));
                    };
                    let reason = decline
                        .children()
                        .find(|n| n.tag_name().name() == "reason")
                        .and_then(|n| n.text())
                        .unwrap_or("");
                    let destinations = if bare(target) == room {
                        let nick = target.split_once('/').map(|(_, n)| n).unwrap_or("");
                        r.occupants
                            .values()
                            .filter(|o| o.nick == nick)
                            .map(|o| o.jid.clone())
                            .collect::<Vec<_>>()
                    } else {
                        vec![target.to_owned()]
                    };
                    for dest in destinations {
                        out.deliveries.push((dest.clone(),format!("<message xmlns='jabber:client' from='{}' to='{}'><x xmlns='{USER}'><decline from='{}'><reason>{}</reason></decline></x></message>",escape(room),escape(&dest),escape(jid),escape(reason))));
                    }
                    return Ok(Some(out));
                }
                if let Some(invite) = x.children().find(|n| n.tag_name().name() == "invite") {
                    if !r
                        .occupants
                        .get(jid)
                        .is_some_and(|o| o.role == "participant" || o.role == "moderator")
                        || (r.data("members_only").as_bool() == Some(true)
                            && !r.privileged(jid)
                            && r.data("allow_member_invites").as_bool() != Some(true))
                    {
                        return Ok(Some(ModuleResult::reply(error(stanza, "forbidden"))));
                    }
                    let Some(target) = invite
                        .attribute("to")
                        .filter(|s| !s.is_empty() && !s.contains(char::is_whitespace))
                    else {
                        return Ok(Some(ModuleResult::reply(error(stanza, "jid-malformed"))));
                    };
                    if r.data("members_only").as_bool() == Some(true)
                        && r.affiliation(target) == "none"
                    {
                        r.set_affiliation(bare(target), "member");
                    }
                    let reason = invite
                        .children()
                        .find(|n| n.tag_name().name() == "reason")
                        .map(xml)
                        .unwrap_or_default();
                    let password = r
                        .data("password")
                        .as_str()
                        .map(|p| format!("<password>{}</password>", escape(p)))
                        .unwrap_or_default();
                    out.deliveries.push((target.into(),format!("<message xmlns='jabber:client' from='{}' to='{}'><x xmlns='{USER}'><invite from='{}'>{reason}</invite>{password}</x></message>",escape(room),escape(target),escape(jid))));
                    self.save(room)?;
                    return Ok(Some(out));
                }
            }
            let Some(o) = r.occupants.get(jid).cloned() else {
                out.replies.push(error(stanza, "not-acceptable"));
                return Ok(Some(out));
            };
            if let Some(result) = voice_request(r, room, jid, stanza) {
                return Ok(Some(result));
            }
            if typ == "groupchat" {
                if to.contains('/') {
                    out.replies.push(error(stanza, "bad-request"));
                } else if o.role == "visitor" || r.locked {
                    out.replies.push(error(stanza, "forbidden"));
                } else {
                    let subject = stanza
                        .children()
                        .find(|n| n.is_element() && n.tag_name().name() == "subject");
                    if let Some(s) = subject {
                        if o.role != "moderator" && r.data("changesubject").as_bool() != Some(true)
                        {
                            out.replies.push(error(stanza, "forbidden"));
                            return Ok(Some(out));
                        }
                        r.frozen["_data"]["subject"] = json!(s.text().unwrap_or(""));
                    }
                    let payload = stanza
                        .children()
                        .filter(|n| {
                            n.is_element()
                                && !(n.tag_name().namespace() == Some("urn:xmpp:sid:0")
                                    && n.tag_name().name() == "stanza-id")
                                && !matches!(
                                    n.tag_name().namespace(),
                                    Some(
                                        "urn:xmpp:occupant-id:0"
                                            | "urn:xmpp:hats:0"
                                            | "xmpp:prosody.im/protocol/hats:1"
                                            | MUC
                                            | USER
                                    )
                                )
                        })
                        .map(xml)
                        .collect::<String>();
                    let payload = format!("{payload}{}", r.occupant_id(jid));
                    let archive_id = uuid::Uuid::new_v4().to_string();
                    let payload = if r.archiving() {
                        let payload = format!(
                            "{payload}<stanza-id xmlns='urn:xmpp:sid:0' by='{}' id='{archive_id}'/>",
                            escape(room)
                        );
                        let stored_identity = if r.data("whois").as_str() == Some("anyone") {
                            format!(
                                "<x xmlns='{USER}'><item jid='{}' affiliation='{}' role='{}'/></x>",
                                escape(bare(jid)),
                                escape(&r.affiliation(jid)),
                                escape(&o.role)
                            )
                        } else {
                            String::new()
                        };
                        let archived = format!(
                            "<message xmlns='jabber:client' from='{}/{}' type='groupchat' id='{}'>{payload}{stored_identity}</message>",
                            escape(room),
                            escape(&o.nick),
                            escape(stanza.attribute("id").unwrap_or(""))
                        );
                        crate::archive::append_new(
                            &self.root,
                            &self.domain,
                            Some(room.split('@').next().unwrap()),
                            "muc_log",
                            crate::archive::Entry {
                                id: archive_id,
                                when: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)?
                                    .as_secs_f64(),
                                peer: "message<groupchat".into(),
                                xml: archived,
                            },
                        )?;
                        if let Some(seconds) = self.retention_seconds {
                            crate::archive::expire_before(
                                &self.root,
                                &self.domain,
                                Some(room.split('@').next().unwrap()),
                                "muc_log",
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)?
                                    .as_secs_f64()
                                    - seconds,
                            )?;
                        }
                        payload
                    } else {
                        payload
                    };
                    let history_packet = format!(
                        "<message xmlns='jabber:client' from='{}/{}' type='groupchat' id='{}'>{payload}</message>",
                        escape(room),
                        escape(&o.nick),
                        escape(stanza.attribute("id").unwrap_or(""))
                    );
                    r.history.set_capacity(
                        r.data("history_length")
                            .as_u64()
                            .unwrap_or(20)
                            .min(self.max_history_messages as u64) as usize,
                    );
                    r.history.push(
                        &history_packet,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs() as i64,
                    );
                    for target in r.occupants.values() {
                        out.deliveries.push((target.jid.clone(),format!("<message xmlns='jabber:client' from='{}/{}' to='{}' type='groupchat'  id='{}'>{payload}</message>",escape(room),escape(&o.nick),escape(&target.jid),escape(stanza.attribute("id").unwrap_or("")))));
                    }
                }
                self.save(room)?;
            } else if typ == "chat" {
                let nick = to.split_once('/').map(|(_, n)| n).unwrap_or("");
                let targets = r
                    .occupants
                    .values()
                    .filter(|o| o.nick == nick)
                    .collect::<Vec<_>>();
                if !targets.is_empty() {
                    if !r.pm_permitted(&o, targets[0]) {
                        out.replies.push(error(stanza, "policy-violation"));
                        return Ok(Some(out));
                    }
                    let payload = stanza
                        .children()
                        .filter(|n| {
                            !matches!(
                                n.tag_name().namespace(),
                                Some(
                                    "urn:xmpp:occupant-id:0"
                                        | "urn:xmpp:hats:0"
                                        | "xmpp:prosody.im/protocol/hats:1"
                                        | MUC
                                        | USER
                                )
                            )
                        })
                        .map(xml)
                        .collect::<String>();
                    let payload = format!("{payload}{}", r.occupant_id(jid));
                    for target in targets {
                        out.deliveries.push((target.jid.clone(),format!("<message xmlns='jabber:client' from='{}/{}' to='{}' type='chat'>{payload}<x xmlns='{USER}'/></message>",escape(room),escape(&o.nick),escape(&target.jid))));
                    }
                } else {
                    out.replies.push(error(stanza, "item-not-found"));
                }
            } else if typ != "error" {
                out.replies.push(error(stanza, "feature-not-implemented"));
            }
            return Ok(Some(out));
        }
        if kind == "iq" && to.contains('/') {
            self.pending_iq
                .retain(|_, v| v.5.elapsed() < std::time::Duration::from_secs(120));
            if matches!(typ, "result" | "error") {
                let id = stanza.attribute("id").unwrap_or("");
                let key = format!("{room}|{id}");
                if let Some((target, source, source_nick, target_nick, original_id, _)) =
                    self.pending_iq.get(&key).cloned()
                    && target == jid
                    && to == format!("{room}/{source_nick}")
                {
                    self.pending_iq.remove(&key);
                    let payload = stanza.children().map(xml).collect::<String>();
                    out.deliveries.push((source.clone(),format!("<iq xmlns='jabber:client' type='{typ}' id='{}' from='{}/{}' to='{}'>{payload}</iq>",escape(&original_id),escape(room),escape(&target_nick),escape(&source))));
                }
                return Ok(Some(out));
            }
            let Some(source) = r.occupants.get(jid) else {
                return Ok(Some(ModuleResult::reply(iq_error(
                    stanza,
                    "not-acceptable",
                ))));
            };
            let nick = to.split_once('/').unwrap().1;
            let Some(target) = r.occupants.values().find(|o| o.nick == nick) else {
                return Ok(Some(ModuleResult::reply(iq_error(
                    stanza,
                    "item-not-found",
                ))));
            };
            if !matches!(typ, "get" | "set") || self.pending_iq.len() >= 10000 {
                return Ok(Some(ModuleResult::reply(iq_error(
                    stanza,
                    "resource-constraint",
                ))));
            }
            let id = uuid::Uuid::new_v4().to_string();
            self.pending_iq.insert(
                format!("{room}|{id}"),
                (
                    target.jid.clone(),
                    jid.into(),
                    source.nick.clone(),
                    target.nick.clone(),
                    stanza.attribute("id").unwrap_or("").into(),
                    std::time::Instant::now(),
                ),
            );
            let payload = stanza.children().map(xml).collect::<String>();
            out.deliveries.push((target.jid.clone(),format!("<iq xmlns='jabber:client' type='{typ}' id='{id}' from='{}/{}' to='{}'>{payload}</iq>",escape(room),escape(&source.nick),escape(&target.jid))));
            return Ok(Some(out));
        }
        if kind == "iq" {
            let Some(q) = stanza.children().find(|n| n.is_element()) else {
                out.replies.push(iq_error(stanza, "bad-request"));
                return Ok(Some(out));
            };
            if q.has_tag_name(("vcard-temp", "vCard")) {
                if !self.vcard_enabled {
                    return Ok(Some(ModuleResult::reply(iq_error(
                        stanza,
                        "feature-not-implemented",
                    ))));
                }
                let user = room.split('@').next().unwrap();
                if typ == "set" {
                    if r.affiliation(jid) != "owner" {
                        return Ok(Some(ModuleResult::reply(iq_error(stanza, "forbidden"))));
                    }
                    let value = crate::storage::stanza_value(q);
                    crate::storage::save(&self.root, &self.domain, Some(user), "vcard", &value)?;
                    out.replies.push(iq_result(stanza, ""));
                    let hash = avatar_hash(&self.root, &self.domain, room)?.unwrap_or_default();
                    for o in r.occupants.values() {
                        out.deliveries.push((o.jid.clone(),format!("<presence xmlns='jabber:client' from='{}' to='{}'><x xmlns='vcard-temp:x:update'><photo>{hash}</photo></x></presence>",escape(room),escape(&o.jid))));
                        out.deliveries.push((o.jid.clone(),format!("<message xmlns='jabber:client' from='{}' to='{}' type='groupchat'><x xmlns='{USER}'><status code='104'/></x></message>",escape(room),escape(&o.jid))));
                    }
                } else if typ == "get" {
                    let payload =
                        crate::storage::load(&self.root, &self.domain, Some(user), "vcard")?
                            .map(|v| crate::storage::stanza_xml(&v))
                            .transpose()?
                            .unwrap_or_else(|| "<vCard xmlns='vcard-temp'/>".into());
                    out.replies.push(iq_result(stanza, &payload));
                } else {
                    out.replies.push(iq_error(stanza, "bad-request"));
                }
                return Ok(Some(out));
            }
            if q.tag_name().namespace() == Some("jabber:iq:register") {
                let affiliation = r.affiliation(jid);
                if affiliation == "outcast" {
                    return Ok(Some(ModuleResult::reply(iq_error(stanza, "forbidden"))));
                }
                if affiliation == "none" {
                    return Ok(Some(ModuleResult::reply(iq_error(
                        stanza,
                        "registration-required",
                    ))));
                }
                if typ == "get" {
                    let registered =
                        r.frozen["_affiliation_data"][bare(jid)]["reserved_nickname"].as_str();
                    let content=registered.map(|nick|format!("<registered/><username>{}</username>",escape(nick))).unwrap_or_else(||"<x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/muc#register</value></field><field var='muc#register_roomnick' type='text-single'><required/></field></x>".into());
                    return Ok(Some(ModuleResult::reply(iq_result(
                        stanza,
                        &format!("<query xmlns='jabber:iq:register'>{content}</query>"),
                    ))));
                }
                if typ != "set" {
                    return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
                }
                if q.children().any(|n| n.tag_name().name() == "remove") {
                    if affiliation == "member" {
                        r.set_affiliation(bare(jid), "none");
                        if r.data("members_only").as_bool() == Some(true) {
                            let affected = r
                                .occupants
                                .values()
                                .filter(|o| bare(&o.jid) == bare(jid))
                                .cloned()
                                .collect::<Vec<_>>();
                            for o in affected {
                                for target in r.occupants.values() {
                                    out.deliveries.push((
                                        target.jid.clone(),
                                        r.presence(room, &o, target, true, "321"),
                                    ));
                                }
                                r.occupants.remove(&o.jid);
                            }
                        }
                    }
                    if let Some(map) = r
                        .frozen
                        .get_mut("_affiliation_data")
                        .and_then(Value::as_object_mut)
                    {
                        map.remove(bare(jid));
                    }
                    let mut raw = r
                        .original
                        .get("_affiliation_data")
                        .cloned()
                        .unwrap_or_default();
                    raw.set(bare(jid), crate::storage::LuaValue::Nil);
                    r.original.set("_affiliation_data", raw);
                } else {
                    let Some(form) = q.children().find(|n| {
                        n.has_tag_name(("jabber:x:data", "x"))
                            && n.attribute("type") == Some("submit")
                    }) else {
                        return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
                    };
                    let field = |name: &str| {
                        form.children()
                            .find(|n| n.attribute("var") == Some(name))
                            .and_then(|n| n.children().find(|n| n.tag_name().name() == "value"))
                            .and_then(|n| n.text())
                    };
                    if field("FORM_TYPE") != Some("http://jabber.org/protocol/muc#register") {
                        return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
                    }
                    let Some(nick) = field("muc#register_roomnick").filter(|n| !n.is_empty())
                    else {
                        return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
                    };
                    let nick = match stringprep::resourceprep(nick) {
                        Ok(v) => v,
                        Err(_) => {
                            return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
                        }
                    };
                    if r.reserved_by(&nick).is_some_and(|owner| owner != bare(jid))
                        || r.occupants
                            .values()
                            .any(|o| o.nick == nick && bare(&o.jid) != bare(jid))
                    {
                        return Ok(Some(ModuleResult::reply(iq_error(stanza, "conflict"))));
                    }
                    r.frozen["_affiliation_data"][bare(jid)]["reserved_nickname"] =
                        json!(nick.as_ref());
                }
                self.save(room)?;
                out.replies.push(iq_result(stanza, ""));
                return Ok(Some(out));
            }
            if q.tag_name().namespace() == Some("http://jabber.org/protocol/disco#info")
                && q.attribute("node") == Some("x-roomuser-item")
                && typ == "get"
            {
                let content = r.frozen["_affiliation_data"][bare(jid)]["reserved_nickname"]
                    .as_str()
                    .map(|n| {
                        format!(
                            "<identity category='conference' type='text' name='{}'/>",
                            escape(n)
                        )
                    })
                    .unwrap_or_default();
                return Ok(Some(ModuleResult::reply(iq_result(
                    stanza,
                    &format!(
                        "<query xmlns='http://jabber.org/protocol/disco#info' node='x-roomuser-item'>{content}</query>"
                    ),
                ))));
            }
            if !self.vcard_enabled && q.tag_name().namespace() == Some("vcard-temp") {
                return Ok(Some(ModuleResult::reply(iq_error(
                    stanza,
                    "feature-not-implemented",
                ))));
            }
            if q.tag_name().namespace() == Some("urn:xmpp:mam:2") {
                if q.tag_name().name() != "query" {
                    return Ok(Some(ModuleResult::reply(iq_error(
                        stanza,
                        "feature-not-implemented",
                    ))));
                }
                if !r.archiving() {
                    return Ok(Some(ModuleResult::reply(iq_error(
                        stanza,
                        "feature-not-implemented",
                    ))));
                }
                if r.affiliation(jid) == "outcast"
                    || (r.data("members_only").as_bool() == Some(true)
                        && !matches!(r.affiliation(jid).as_str(), "owner" | "admin" | "member"))
                {
                    return Ok(Some(ModuleResult::reply(iq_error(stanza, "forbidden"))));
                }
                if let Some(seconds) = self.retention_seconds {
                    crate::archive::expire_before(
                        &self.root,
                        &self.domain,
                        Some(room.split('@').next().unwrap()),
                        "muc_log",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs_f64()
                            - seconds,
                    )?;
                }
                return match crate::mam::handle_archive_query_with_options(
                    &self.root,
                    &self.domain,
                    Some(room.split('@').next().unwrap()),
                    "muc_log",
                    room,
                    (stanza, q),
                    self.log_include_total,
                ) {
                    Ok(mut result) => {
                        for reply in &mut result.replies {
                            *reply = sanitize_archived(
                                reply,
                                r.data("whois").as_str() == Some("anyone"),
                            )?;
                        }
                        Ok(Some(result))
                    }
                    Err(e) => Ok(Some(ModuleResult::reply(iq_error(
                        stanza,
                        if e.to_string() == "item-not-found" {
                            "item-not-found"
                        } else {
                            "bad-request"
                        },
                    )))),
                };
            }
            if q.tag_name().namespace() == Some(OWNER)
                && typ == "set"
                && q.children().any(|n| n.tag_name().name() == "destroy")
            {
                if r.affiliation(jid) != "owner" {
                    return Ok(Some(ModuleResult::reply(iq_error(stanza, "forbidden"))));
                }
                let destroy = q
                    .children()
                    .find(|n| n.tag_name().name() == "destroy")
                    .unwrap();
                let reason = destroy
                    .children()
                    .find(|n| n.tag_name().name() == "reason")
                    .and_then(|n| n.text())
                    .unwrap_or("");
                let alternate = destroy
                    .attribute("jid")
                    .map(|v| format!(" jid='{}'", escape(v)))
                    .unwrap_or_default();
                crate::archive::expire_before(
                    &self.root,
                    &self.domain,
                    Some(room.split('@').next().unwrap()),
                    "muc_log",
                    f64::INFINITY,
                )?;
                let destroy_payload = format!(
                    "<destroy{alternate}><reason>{}</reason></destroy>",
                    escape(reason)
                );
                for o in r.occupants.values() {
                    out.deliveries.push((o.jid.clone(),format!("<presence xmlns='jabber:client' from='{}/{}' type='unavailable'><x xmlns='{USER}'><item affiliation='none' role='none'/>{destroy_payload}</x></presence>",escape(room),escape(&o.nick))));
                }
                let tombstone = self.tombstones && r.data("persistent").as_bool() == Some(true);
                if tombstone {
                    r.frozen = json!({"_jid":room,"_data":{"destroyed":true,"hidden":true,"persistent":true,"locked":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()+31*86400,"reason":destroy.children().find(|n|n.tag_name().name()=="reason").and_then(|n|n.text()).unwrap_or(""),"newjid":destroy.attribute("jid").unwrap_or("")}});
                    r.original = crate::storage::LuaValue::table();
                    r.occupants.clear();
                    self.save(room)?;
                    out.replies.push(iq_result(stanza, ""));
                    return Ok(Some(out));
                }
                self.delete_saved_room(room)?;
                self.rooms.remove(room);
                out.replies.push(iq_result(stanza, ""));
                return Ok(Some(out));
            }
            let avatar = if self.vcard_enabled
                && q.tag_name().namespace() == Some("http://jabber.org/protocol/disco#info")
            {
                avatar_hash(&self.root, &self.domain, room)?
            } else {
                None
            };
            match q.tag_name().namespace().unwrap_or("") {
   "http://jabber.org/protocol/disco#info" if typ=="get"=>out.replies.push(iq_result(stanza,&format!("<query xmlns='http://jabber.org/protocol/disco#info'><identity category='conference' type='text' name='{}'/><feature var='{MUC}'/><feature var='urn:xmpp:occupant-id:0'/><feature var='jabber:iq:register'/><feature var='vcard-temp'/><feature var='http://jabber.org/protocol/muc#request'/><feature var='urn:xmpp:hats:0'/>{}{}</query>",escape(r.data("name").as_str().unwrap_or(room)),if r.archiving(){"<feature var='urn:xmpp:mam:2'/><feature var='urn:xmpp:mam:2#extended'/><feature var='urn:xmpp:sid:0'/>"}else{""}, room_info(r,avatar.as_deref())))),
   "http://jabber.org/protocol/disco#items" if typ=="get"=>{if !r.occupants.contains_key(jid){out.replies.push(iq_error(stanza,"forbidden"));}else{let items=r.occupants.values().map(|o|format!("<item jid='{}/{}'/>",escape(room),escape(&o.nick))).collect::<String>();out.replies.push(iq_result(stanza,&format!("<query xmlns='http://jabber.org/protocol/disco#items'>{items}</query>")));}},
   OWNER=>{if r.affiliation(jid)!="owner"{out.replies.push(iq_error(stanza,"forbidden"));}else if typ=="get"{out.replies.push(iq_result(stanza,&format!("<query xmlns='{OWNER}'>{}</query>",config_form(r))));}else if typ=="set"{if let Some(form)=q.children().find(|n|n.tag_name().namespace()==Some("jabber:x:data")){if form.attribute("type")==Some("submit"){let mut next=r.frozen.clone();let mut valid=true;for f in form.children().filter(|n|n.tag_name().name()=="field"){let name=f.attribute("var").unwrap_or("");let value=f.children().find(|n|n.tag_name().name()=="value").and_then(|n|n.text()).unwrap_or("");if name=="FORM_TYPE" {continue;}
if name=="muc#roomconfig_presencebroadcast" {
 let mut roles=json!({});
 for value in f.children().filter(|n|n.tag_name().name()=="value") {
 let role=value.text().unwrap_or("");if !matches!(role,"none"|"visitor"|"participant"|"moderator"){valid=false;}else{roles[role]=json!(true);}}
 next["_data"]["presence_broadcast"]=roles;continue;
}
if let Some((_,key,boolean))=FIELDS.iter().find(|(n,_,_)|*n==name){
if matches!(*key,"history_length"|"default_history_messages") {if let Ok(number)=value.parse::<u64>() {if number<=self.max_history_messages as u64 {next["_data"][*key]=json!(number);}else{valid=false;}}else{valid=false;}continue;}
if *boolean {if !matches!(value,"0"|"1"|"true"|"false"){valid=false;}else{next["_data"][*key]=json!(if *key=="hidden"{value=="0"||value=="false"}else{value=="1"||value=="true"});}}else{if (*key=="whois"&&!matches!(value,"anyone"|"moderators")) || (*key=="allow_pm"&&!matches!(value,"visitor"|"participant"|"moderator"|"affiliated"|"none")){valid=false;}else{next["_data"][*key]=json!(value);}}}else{valid=false;}}
    if valid{
      let became_members_only=r.data("members_only").as_bool()!=Some(true)&&next["_data"]["members_only"].as_bool()==Some(true);
      let old_broadcast = ["none","visitor","participant","moderator"].map(|role| r.broadcasts(role));
      let changed = r.frozen != next;
      r.frozen=next;r.locked=false;r.clear_data("locked");
      if r.data("language").as_str()==Some("") {r.clear_data("language");}
      for (i,role) in ["none","visitor","participant","moderator"].iter().enumerate() {
        let enabled=r.broadcasts(role);
        if enabled!=old_broadcast[i] {for o in r.occupants.values().filter(|o|o.role==*role) {for target in r.occupants.values().filter(|t|t.nick!=o.nick) {out.deliveries.push((target.jid.clone(),r.presence_force(room,o,target,!enabled,"")));}}}
      }
      if changed {for target in r.occupants.values(){out.deliveries.push((target.jid.clone(),format!("<message xmlns='jabber:client' from='{}' to='{}' type='groupchat'><x xmlns='{USER}'><status code='104'/></x></message>",escape(room),escape(&target.jid))));}}
      if became_members_only {let kicked=r.occupants.values().filter(|o|r.affiliation(&o.jid)=="none").cloned().collect::<Vec<_>>();for o in kicked{for target in r.occupants.values(){out.deliveries.push((target.jid.clone(),r.presence(room,&o,target,true,"322")));}r.occupants.remove(&o.jid);}}
      out.replies.push(iq_result(stanza,""));self.save(room)?;
    }else{out.replies.push(iq_error(stanza,"not-acceptable"));}
   }else if form.attribute("type")==Some("cancel"){out.replies.push(iq_result(stanza,""));}else{out.replies.push(iq_error(stanza,"bad-request"));}}else{out.replies.push(iq_error(stanza,"feature-not-implemented"));}}else{out.replies.push(iq_error(stanza,"bad-request"));}},
   ADMIN=>{admin(r,room,jid,stanza,q,&mut out);self.save(room)?;},
   _=>out.replies.push(iq_error(stanza,"feature-not-implemented")),}
            return Ok(Some(out));
        }
        Ok(Some(out))
    }
}
const FIELDS: &[(&str, &str, bool)] = &[
    ("muc#roomconfig_roomname", "name", false),
    ("muc#roomconfig_roomdesc", "description", false),
    ("muc#roomconfig_lang", "language", false),
    ("muc#roomconfig_persistentroom", "persistent", true),
    ("muc#roomconfig_publicroom", "hidden", true),
    ("muc#roomconfig_roomsecret", "password", false),
    ("muc#roomconfig_membersonly", "members_only", true),
    ("muc#roomconfig_changesubject", "changesubject", true),
    ("muc#roomconfig_moderatedroom", "moderated", true),
    ("muc#roomconfig_whois", "whois", false),
    ("muc#roomconfig_historylength", "history_length", false),
    (
        "muc#roomconfig_defaulthistorymessages",
        "default_history_messages",
        false,
    ),
    ("muc#roomconfig_allowinvites", "allow_member_invites", true),
    ("muc#roomconfig_enablearchiving", "archiving", true),
    ("muc#roomconfig_allowpm", "allow_pm", false),
    ("{xmpp:prosody.im}muc#allow_modpm", "allow_modpm", true),
];
fn config_form(r: &Room) -> String {
    let mut fields="<field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/muc#roomconfig</value></field>".to_string();
    for (name, key, boolean) in FIELDS {
        let numeric_value = r.data(key).as_u64().map(|n| n.to_string());
        let section = match *key {
            "name" => Some("Room information"),
            "hidden" => Some("Access to the room"),
            "changesubject" => Some("Permissions in the room"),
            "history_length" => Some("Other options"),
            _ => None,
        };
        if let Some(section) = section {
            fields.push_str(&format!(
                "<field type='fixed'><value>{section}</value></field>"
            ));
        }
        let value = if *boolean {
            if (r.data(key).as_bool() == Some(true)) != (*key == "hidden") {
                "1"
            } else {
                "0"
            }
        } else if let Some(ref number) = numeric_value {
            number.as_str()
        } else {
            if *key == "allow_pm" {
                r.allow_pm()
            } else {
                r.data(key).as_str().unwrap_or("")
            }
        };
        fields.push_str(&format!(
            "<field var='{name}' type='{}'><value>{}</value>{}</field>",
            if *boolean {
                "boolean"
            } else if *key == "allow_pm" || *key == "whois" {
                "list-single"
            } else if *key == "password" {
                "text-private"
            } else {
                "text-single"
            },
            escape(value),
            match *key {
                "allow_pm" => ["visitor", "participant", "moderator", "affiliated", "none"]
                    .into_iter()
                    .map(|v| format!("<option><value>{v}</value></option>"))
                    .collect::<String>(),
                "whois" => ["moderators", "anyone"]
                    .into_iter()
                    .map(|v| format!("<option><value>{v}</value></option>"))
                    .collect::<String>(),
                _ => String::new(),
            }
        ));
    }
    fields.push_str("<field var='muc#roomconfig_presencebroadcast' type='list-multi'>");
    for role in ["none", "visitor", "participant", "moderator"] {
        if r.broadcasts(role) {
            fields.push_str(&format!("<value>{role}</value>"));
        }
        fields.push_str(&format!("<option><value>{role}</value></option>"));
    }
    fields.push_str("</field>");
    format!("<x xmlns='jabber:x:data' type='form'>{fields}</x>")
}
fn admin(
    r: &mut Room,
    room: &str,
    jid: &str,
    iq: roxmltree::Node,
    q: roxmltree::Node,
    out: &mut ModuleResult,
) {
    let moderator = r.occupants.get(jid).is_some_and(|o| o.role == "moderator");
    if !r.privileged(jid) && !moderator {
        out.replies.push(iq_error(iq, "forbidden"));
        return;
    }
    let items: Vec<_> = q
        .children()
        .filter(|n| n.tag_name().name() == "item")
        .collect();
    if items.len() != 1 {
        out.replies.push(iq_error(iq, "bad-request"));
        return;
    }
    let item = items[0];
    let aff = item.attribute("affiliation");
    if !r.privileged(jid) && (aff.is_some() || item.attribute("role") == Some("moderator")) {
        out.replies.push(iq_error(iq, "forbidden"));
        return;
    }
    if iq.attribute("type") == Some("get") {
        if let Some(aff) = aff {
            let map = r.frozen.get("_affiliations").unwrap_or(&r.frozen);
            let payload = map
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(k, v)| !k.starts_with('_') && v.as_str() == Some(aff))
                .map(|(k, _)| format!("<item jid='{}' affiliation='{}'/>", escape(k), escape(aff)))
                .collect::<String>();
            out.replies.push(iq_result(
                iq,
                &format!("<query xmlns='{ADMIN}'>{payload}</query>"),
            ));
        } else if let Some(role) = item.attribute("role") {
            let mut seen = std::collections::BTreeSet::new();
            let payload = r
                .occupants
                .values()
                .filter(|o| o.role == role && seen.insert(o.nick.clone()))
                .map(|o| {
                    format!(
                        "<item nick='{}' jid='{}' role='{}' affiliation='{}'/>",
                        escape(&o.nick),
                        escape(&o.jid),
                        escape(&o.role),
                        escape(&r.affiliation(&o.jid))
                    )
                })
                .collect::<String>();
            out.replies.push(iq_result(
                iq,
                &format!("<query xmlns='{ADMIN}'>{payload}</query>"),
            ));
        } else {
            out.replies.push(iq_error(iq, "bad-request"));
        }
        return;
    }
    if iq.attribute("type") != Some("set") {
        out.replies.push(iq_error(iq, "bad-request"));
        return;
    }
    if let Some(aff) = aff {
        let target = bare(item.attribute("jid").unwrap_or(""));
        if target.is_empty() || !matches!(aff, "owner" | "admin" | "member" | "outcast" | "none") {
            out.replies.push(iq_error(iq, "bad-request"));
            return;
        }
        let old = r.affiliation(target);
        if r.affiliation(jid) != "owner"
            && (matches!(old.as_str(), "owner" | "admin") || matches!(aff, "owner" | "admin"))
        {
            out.replies.push(iq_error(iq, "forbidden"));
            return;
        }
        if old == "owner" && aff != "owner" {
            let map = r.frozen.get("_affiliations").unwrap_or(&r.frozen);
            if map
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(_, v)| v.as_str() == Some("owner"))
                .count()
                <= 1
            {
                out.replies.push(iq_error(iq, "conflict"));
                return;
            }
        }
        r.set_affiliation(target, aff);
        let affected = r
            .occupants
            .values()
            .filter(|o| {
                bare(&o.jid) == target
                    || (aff == "outcast"
                        && !target.contains('@')
                        && bare(&o.jid).rsplit_once('@').map(|(_, host)| host) == Some(target))
            })
            .cloned()
            .collect::<Vec<_>>();
        for mut o in affected {
            let kick = aff == "outcast"
                || (aff == "none" && r.data("members_only").as_bool() == Some(true));
            o.role = if matches!(aff, "owner" | "admin") {
                "moderator"
            } else if r.data("moderated").as_bool() == Some(true) && aff == "none" {
                "visitor"
            } else {
                "participant"
            }
            .into();
            if !kick {
                r.occupants.insert(o.jid.clone(), o.clone());
            }
            for dest in r.occupants.values() {
                out.deliveries.push((
                    dest.jid.clone(),
                    r.presence(
                        room,
                        &o,
                        dest,
                        kick,
                        if kick {
                            if aff == "outcast" { "301" } else { "321" }
                        } else {
                            ""
                        },
                    ),
                ));
            }
            if kick {
                r.occupants.remove(&o.jid);
            }
        }
        out.replies.push(iq_result(iq, ""));
    } else if let Some(role) = item.attribute("role") {
        if !matches!(role, "none" | "visitor" | "participant" | "moderator") {
            out.replies.push(iq_error(iq, "bad-request"));
            return;
        }
        let nick = item.attribute("nick").unwrap_or("");
        let Some(mut o) = r.occupants.values().find(|o| o.nick == nick).cloned() else {
            out.replies.push(iq_error(iq, "item-not-found"));
            return;
        };
        if r.privileged(&o.jid) || (o.role == "moderator" && !r.privileged(jid)) {
            out.replies.push(iq_error(iq, "not-allowed"));
            return;
        }
        let was_visible = r.broadcasts(&o.role);
        o.role = role.into();
        let withdraw = was_visible && !r.broadcasts(role);
        for dest in r.occupants.values() {
            out.deliveries.push((
                dest.jid.clone(),
                if was_visible {
                    r.presence_force(
                        room,
                        &o,
                        dest,
                        role == "none" || withdraw,
                        if role == "none" { "307" } else { "" },
                    )
                } else {
                    r.presence(
                        room,
                        &o,
                        dest,
                        role == "none",
                        if role == "none" { "307" } else { "" },
                    )
                },
            ));
        }
        if role == "none" {
            r.occupants.retain(|_, other| other.nick != o.nick);
        } else {
            for other in r
                .occupants
                .values_mut()
                .filter(|other| other.nick == o.nick)
            {
                other.role = role.into();
            }
        }
        out.replies.push(iq_result(iq, ""));
    } else {
        out.replies.push(iq_error(iq, "bad-request"));
    }
}
fn error(stanza: roxmltree::Node, condition: &str) -> String {
    format!(
        "<{} xmlns='jabber:client' type='error' from='{}' id='{}'><error type='cancel'><{condition} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></{}>",
        stanza.tag_name().name(),
        escape(stanza.attribute("to").unwrap_or("")),
        escape(stanza.attribute("id").unwrap_or("")),
        stanza.tag_name().name()
    )
}
// Keep a lossless original alongside a JSON view of supported settings. Binary
// salts and mixed-key extension metadata survive configuration updates untouched.
fn view_value(v: &crate::storage::LuaValue) -> Value {
    use crate::storage::LuaValue as L;
    match v {
        L::Nil => Value::Null,
        L::Bool(v) => json!(v),
        L::Integer(v) => json!(v),
        L::Number(v) => json!(v),
        L::String(v) => std::str::from_utf8(v)
            .map(|s| json!(s))
            .unwrap_or(Value::Null),
        L::Table(t) => {
            let mut o = serde_json::Map::new();
            for (k, v) in t {
                if let Some(k) = k.as_str() {
                    o.insert(k.into(), view_value(v));
                }
            }
            Value::Object(o)
        }
    }
}
fn merge_value(raw: &mut crate::storage::LuaValue, v: &Value) {
    use crate::storage::LuaValue as L;
    match v {
        Value::Null => {}
        Value::Bool(v) => *raw = L::Bool(*v),
        Value::Number(v) => {
            *raw = if let Some(i) = v.as_i64() {
                L::Integer(i)
            } else {
                L::Number(v.as_f64().unwrap())
            }
        }
        Value::String(v) => *raw = L::from(v.clone()),
        Value::Object(o) => {
            if !matches!(raw, L::Table(_)) {
                *raw = L::table();
            }
            for (k, v) in o {
                let mut item = raw.get(k).cloned().unwrap_or(L::Nil);
                merge_value(&mut item, v);
                raw.set(k, item);
            }
        }
        Value::Array(_) => {}
    }
}
fn read_value(path: &std::path::Path) -> Result<Value> {
    Ok(view_value(&crate::storage::parse(&std::fs::read(path)?)?))
}
fn write_value(path: &std::path::Path, value: &Value) -> Result<()> {
    fn lua(v: &Value) -> String {
        match v {
            Value::Null => "nil".into(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::String(s) => {
                let mut out = "\"".to_string();
                for b in s.as_bytes() {
                    match b {
                        b'"' => out.push_str("\\\""),
                        b'\\' => out.push_str("\\\\"),
                        32..=126 => out.push(*b as char),
                        _ => out.push_str(&format!("\\{b:03}")),
                    }
                }
                out.push('"');
                out
            }
            Value::Array(a) => format!("{{{}}}", a.iter().map(lua).collect::<Vec<_>>().join(",")),
            Value::Object(o) => format!(
                "{{{}}}",
                o.iter()
                    .map(|(k, v)| format!("[{}]={}", lua(&json!(k)), lua(v)))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
    crate::storage::atomic_write(path, format!("return {};\n", lua(value)).as_bytes())?;
    Ok(())
}

fn avatar_hash(root: &std::path::Path, domain: &str, room: &str) -> Result<Option<String>> {
    use base64::Engine;
    use sha1::Digest;
    let Some(v) =
        crate::storage::load(root, domain, Some(room.split('@').next().unwrap()), "vcard")?
    else {
        return Ok(None);
    };
    let xml = crate::storage::stanza_xml(&v)?;
    let doc = roxmltree::Document::parse(&xml)?;
    let Some(bin) = doc
        .descendants()
        .find(|n| n.tag_name().name() == "BINVAL")
        .and_then(|n| n.text())
    else {
        return Ok(None);
    };
    let compact = bin
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    match base64::engine::general_purpose::STANDARD.decode(compact) {
        Ok(bytes) => Ok(Some(hex::encode(sha1::Sha1::digest(bytes)))),
        Err(_) => Ok(None),
    }
}

fn voice_request(
    room: &mut Room,
    name: &str,
    jid: &str,
    stanza: roxmltree::Node,
) -> Option<ModuleResult> {
    let form = stanza
        .children()
        .find(|n| n.has_tag_name(("jabber:x:data", "x")))?;
    let field = |key: &str| {
        form.children()
            .find(|n| n.attribute("var") == Some(key))
            .and_then(|n| {
                n.children()
                    .find(|n| n.has_tag_name(("jabber:x:data", "value")))
            })
            .and_then(|n| n.text())
    };
    if field("FORM_TYPE") != Some("http://jabber.org/protocol/muc#request") {
        return None;
    }
    if form.attribute("type") != Some("submit") {
        return Some(ModuleResult::reply(error(stanza, "bad-request")));
    }
    let Some(actor) = room.occupants.get(jid).cloned() else {
        return Some(ModuleResult::reply(error(stanza, "not-acceptable")));
    };
    let mut out = ModuleResult::default();
    if actor.role == "moderator" {
        if !matches!(field("muc#request_allow"), Some("true" | "1")) {
            return Some(out);
        }
        let Some(target) = field("muc#jid")
            .and_then(|j| room.occupants.get(j))
            .cloned()
        else {
            return Some(out);
        };
        if target.role != "visitor" {
            return Some(out);
        }
        for session in room
            .occupants
            .values_mut()
            .filter(|o| o.nick == target.nick && bare(&o.jid) == bare(&target.jid))
        {
            session.role = "participant".into();
        }
        let mut promoted = target;
        promoted.role = "participant".into();
        for dest in room.occupants.values() {
            out.deliveries.push((
                dest.jid.clone(),
                room.presence(name, &promoted, dest, false, ""),
            ));
        }
    } else if actor.role == "visitor" {
        // Never trust requester-supplied identity, nickname, role or allow flag.
        let payload = format!(
            "<x xmlns='jabber:x:data' type='form'><title>Voice Request</title><field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#jid' type='jid-single'><value>{}</value></field><field var='muc#roomnick' type='text-single'><value>{}</value></field><field var='muc#role' type='list-single'><value>participant</value></field><field var='muc#request_allow' type='boolean'><value>0</value></field></x>",
            escape(jid),
            escape(&actor.nick)
        );
        for dest in room.occupants.values().filter(|o| o.role == "moderator") {
            out.deliveries.push((dest.jid.clone(),format!("<message xmlns='jabber:client' from='{}' to='{}' type='normal'>{payload}</message>",escape(name),escape(&dest.jid))));
        }
    }
    Some(out)
}

fn sanitize_archived(packet: &str, public: bool) -> Result<String> {
    use crate::storage::LuaValue as V;
    fn walk(n: roxmltree::Node, public: bool) -> Option<V> {
        if n.has_tag_name((USER, "x")) && !public {
            return None;
        }
        let mut value = crate::storage::stanza_value(n);
        if n.is_element() {
            if let V::Table(entries) = &mut value {
                entries.retain(|(key, _)| !matches!(key, V::Integer(_)));
            }
            if n.tag_name().name() == "message" {
                let mut attr = value.get("attr").cloned().unwrap_or_default();
                attr.set("to", V::Nil);
                value.set("attr", attr);
            }
            let mut index = 1;
            for child in n.children().filter(|n| n.is_element() || n.is_text()) {
                if let Some(child) = walk(child, public) {
                    value.set_key(V::Integer(index), child);
                    index += 1;
                }
            }
        }
        Some(value)
    }
    let doc = roxmltree::Document::parse(packet)?;
    crate::storage::stanza_xml(&walk(doc.root_element(), public).unwrap())
}

fn room_info(r: &Room, avatar: Option<&str>) -> String {
    let mut out = String::new();
    for feature in [
        "http://jabber.org/protocol/muc#stable_id",
        "http://jabber.org/protocol/muc#self-ping-optimization",
        if r.data("hidden").as_bool() == Some(true) {
            "muc_hidden"
        } else {
            "muc_public"
        },
        if r.data("members_only").as_bool() == Some(true) {
            "muc_membersonly"
        } else {
            "muc_open"
        },
        if r.data("moderated").as_bool() == Some(true) {
            "muc_moderated"
        } else {
            "muc_unmoderated"
        },
        if r.data("persistent").as_bool() == Some(true) {
            "muc_persistent"
        } else {
            "muc_temporary"
        },
        if r.data("password").as_str().is_some_and(|p| !p.is_empty()) {
            "muc_passwordprotected"
        } else {
            "muc_unsecured"
        },
        if r.data("whois").as_str() == Some("anyone") {
            "muc_nonanonymous"
        } else {
            "muc_semianonymous"
        },
    ] {
        out.push_str(&format!("<feature var='{feature}'/>"));
    }
    out.push_str("<x xmlns='jabber:x:data' type='result'><field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/muc#roominfo</value></field>");
    for (name, value) in [
        (
            "muc#roominfo_lang",
            r.data("language").as_str().unwrap_or(""),
        ),
        (
            "muc#roominfo_description",
            r.data("description").as_str().unwrap_or(""),
        ),
    ] {
        out.push_str(&format!(
            "<field var='{name}'><value>{}</value></field>",
            escape(value)
        ));
    }
    let count = r
        .occupants
        .values()
        .map(|o| o.nick.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    out.push_str(&format!(
        "<field var='muc#roominfo_occupants'><value>{count}</value></field>"
    ));
    for (name, value) in [
        (
            "muc#roomconfig_changesubject",
            r.data("changesubject").as_bool() == Some(true),
        ),
        (
            "{http://prosody.im/protocol/muc}roomconfig_allowmemberinvites",
            r.data("allow_member_invites").as_bool() == Some(true),
        ),
        (
            "muc#roomconfig_allowinvites",
            r.data("members_only").as_bool() != Some(true)
                || r.data("allow_member_invites").as_bool() == Some(true),
        ),
    ] {
        out.push_str(&format!(
            "<field var='{name}' type='boolean'><value>{}</value></field>",
            if value { "1" } else { "0" }
        ));
    }
    if let Some(avatar) = avatar {
        out.push_str(&format!(
            "<field var='muc#roominfo_avatarhash' type='text-multi'><value>{}</value></field>",
            escape(avatar)
        ));
    }
    out.push_str("</x>");
    out
}

fn archive_presence(
    root: &std::path::Path,
    domain: &str,
    room: &str,
    nick: &str,
    unavailable: bool,
) -> Result<()> {
    crate::archive::append_new(
        root,
        domain,
        Some(room.split('@').next().unwrap()),
        "muc_log",
        crate::archive::Entry {
            id: uuid::Uuid::new_v4().to_string(),
            when: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs_f64(),
            peer: if unavailable {
                "presence<unavailable"
            } else {
                "presence<"
            }
            .into(),
            xml: format!(
                "<presence xmlns='jabber:client' from='{}/{}'{}>{}</presence>",
                escape(room),
                escape(nick),
                if unavailable {
                    " type='unavailable'"
                } else {
                    ""
                },
                if unavailable {
                    ""
                } else {
                    "<x xmlns='http://jabber.org/protocol/muc'/>"
                }
            ),
        },
    )?;
    Ok(())
}
