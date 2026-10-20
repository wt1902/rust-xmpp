//! Local account IQ protocols over the original Prosody stores.
use crate::{
    protocol::{ModuleResult, bare, iq_error, iq_result},
    storage::{self, LuaValue as V},
    wire::escape,
};
use anyhow::{Result, ensure};
use roxmltree::Node;
use std::path::Path;
fn reply(iq: Node<'_, '_>, s: &str) -> Option<ModuleResult> {
    Some(ModuleResult::reply(iq_result(iq, s)))
}
fn err(iq: Node<'_, '_>, s: &str) -> Option<ModuleResult> {
    Some(ModuleResult::reply(iq_error(iq, s)))
}
fn text<'a>(v: &'a V, k: &str) -> Option<&'a str> {
    v.get(k).and_then(V::as_str)
}
fn roster_item(jid: &str, v: &V) -> String {
    let mut s = format!(
        "<item jid='{}' subscription='{}'",
        escape(jid),
        escape(text(v, "subscription").unwrap_or("none"))
    );
    for k in ["name", "ask", "approved"] {
        if let Some(v) = text(v, k) {
            s.push_str(&format!(" {k}='{}'", escape(v)))
        }
    }
    s.push('>');
    if let Some(groups) = v.get("groups") {
        for (k, _) in groups.entries() {
            if let Some(g) = k.as_str() {
                s.push_str(&format!("<group>{}</group>", escape(g)))
            }
        }
    }
    s.push_str("</item>");
    s
}
fn roster_version_number(v: &V) -> Option<i64> {
    match v {
        V::Integer(n) => Some(*n),
        V::Number(n)
            if n.is_finite() && n.fract() == 0.0 && *n >= 0.0 && *n < (i64::MAX as f64) =>
        {
            Some(*n as i64)
        }
        V::String(v) => std::str::from_utf8(v).ok()?.parse().ok(),
        _ => None,
    }
}
fn bump(v: &mut V) -> Result<()> {
    let mut meta = v.get_key(&V::Bool(false)).cloned().unwrap_or_default();
    ensure!(
        !meta
            .get("broken")
            .is_some_and(|v| !matches!(v, V::Nil | V::Bool(false))),
        "refusing to overwrite broken roster"
    );
    if meta.get("version") != Some(&V::Bool(true)) {
        meta.set(
            "version",
            V::Integer(
                meta.get("version")
                    .and_then(roster_version_number)
                    .unwrap_or(0)
                    .saturating_add(1),
            ),
        );
    }
    v.set_key(V::Bool(false), meta);
    Ok(())
}
fn version(v: &V) -> String {
    match v.get_key(&V::Bool(false)).and_then(|v| v.get("version")) {
        Some(v) if roster_version_number(v).is_some() => {
            roster_version_number(v).unwrap().to_string()
        }
        Some(V::Bool(true)) => "true".into(),
        _ => "1".into(),
    }
}
pub fn handle(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    handle_with_vcard_store(root, domain, jid, iq, "vcard")
}
pub fn handle_with_vcard_store(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: Node<'_, '_>,
    vcard_store: &str,
) -> Result<Option<ModuleResult>> {
    match handle_account_inner(root, domain, jid, iq, vcard_store) {
        Ok(r) => Ok(r),
        Err(_) => Ok(err(iq, "internal-server-error")),
    }
}
fn handle_account_inner(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: Node<'_, '_>,
    vcard_store: &str,
) -> Result<Option<ModuleResult>> {
    let Some(q) = iq.children().find(|n| n.is_element()) else {
        return Ok(None);
    };
    let ns = q.tag_name().namespace().unwrap_or("");
    if ![
        "jabber:iq:roster",
        "jabber:iq:private",
        "vcard-temp",
        "urn:xmpp:blocking",
    ]
    .contains(&ns)
    {
        return Ok(None);
    }
    if iq.children().filter(|n| n.is_element()).count() != 1 || iq.attribute("id").is_none() {
        return Ok(err(iq, "bad-request"));
    }
    let typ = iq.attribute("type").unwrap_or("");
    if !["get", "set"].contains(&typ) {
        return Ok(None);
    }
    let own = bare(jid);
    let Some((user, host)) = own.split_once('@') else {
        return Ok(err(iq, "not-authorized"));
    };
    if host != domain {
        return Ok(err(iq, "not-authorized"));
    }
    let target = iq.attribute("to").map(bare).unwrap_or(own);
    let self_target = target == own || target == domain;
    if ns != "vcard-temp" && !self_target {
        return Ok(err(iq, "forbidden"));
    }
    match ns {
        "jabber:iq:roster" => {
            if q.tag_name().name() != "query" {
                return Ok(err(iq, "bad-request"));
            }
            if typ == "get" {
                let data = storage::load(root, domain, Some(user), "roster")?.unwrap_or_default();
                let ver = version(&data);
                if ver != "true" && q.attribute("ver") == Some(ver.as_str()) {
                    return Ok(reply(iq, ""));
                }
                let mut s = format!("<query xmlns='jabber:iq:roster' ver='{}'>", escape(&ver));
                for (k, v) in data.entries() {
                    if let Some(contact) = k.as_str()
                        && text(v, "subscription").is_some()
                    {
                        s.push_str(&roster_item(contact, v));
                    }
                }
                s.push_str("</query>");
                return Ok(reply(iq, &s));
            }
            let items: Vec<_> = q.children().filter(|n| n.is_element()).collect();
            if items.len() != 1 || !items[0].has_tag_name(("jabber:iq:roster", "item")) {
                return Ok(err(iq, "bad-request"));
            }
            let item = items[0];
            let Some(contact) = item.attribute("jid") else {
                return Ok(err(iq, "bad-request"));
            };
            let contact = match normalize_bare_jid(contact) {
                Ok(c) => c,
                Err(_) => return Ok(err(iq, "jid-malformed")),
            };
            if contact == own {
                return Ok(err(iq, "not-allowed"));
            }
            let remove = item.attribute("subscription") == Some("remove");
            let mut pushed = String::new();
            let mut removed = V::Nil;
            let mut missing = false;
            let data = storage::update(root, domain, Some(user), "roster", |data| {
                ensure!(
                    !data
                        .get_key(&V::Bool(false))
                        .and_then(|m| m.get("broken"))
                        .is_some_and(|v| !matches!(v, V::Nil | V::Bool(false))),
                    "refusing to overwrite broken roster"
                );
                if remove && data.get(&contact).is_none() {
                    missing = true;
                    return Ok(());
                }
                if remove {
                    removed = data.get(&contact).cloned().unwrap_or(V::Nil);
                    data.set(&contact, V::Nil);
                    set_pending(data, &contact, V::Nil);
                    pushed = format!("<item jid='{}' subscription='remove'/>", escape(&contact));
                } else {
                    let mut v = data.get(&contact).cloned().unwrap_or_default();
                    if v.get("subscription").is_none() {
                        v.set("subscription", "none".into())
                    }
                    v.set(
                        "name",
                        item.attribute("name")
                            .filter(|n| !n.is_empty())
                            .map(V::from)
                            .unwrap_or(V::Nil),
                    );
                    let mut groups = V::table();
                    for g in item
                        .children()
                        .filter(|n| n.has_tag_name(("jabber:iq:roster", "group")))
                    {
                        if let Some(text) = g.text() {
                            groups.set(text, V::Bool(true));
                        }
                    }
                    v.set("groups", groups);
                    pushed = roster_item(&contact, &v);
                    data.set(&contact, v);
                }
                bump(data)?;
                Ok(())
            })?;
            if missing {
                return Ok(err(iq, "item-not-found"));
            }
            let mut result = ModuleResult::reply(iq_result(iq, ""));
            result.deliveries.push((own.into(),format!("<iq xmlns='jabber:client' type='set' id='roster-{}'><query xmlns='jabber:iq:roster' ver='{}'>{pushed}</query></iq>",uuid::Uuid::new_v4(),version(&data))));
            if remove && removed != V::Nil {
                let (to, from) = directions(&removed);
                for (needed, kind) in [
                    (to || text(&removed, "ask").is_some(), "unsubscribe"),
                    (from, "unsubscribed"),
                ] {
                    if needed {
                        result.deliveries.push((
                            contact.clone(),
                            format!(
                                "<presence xmlns='jabber:client' from='{}' to='{}' type='{kind}'/>",
                                escape(own),
                                escape(&contact)
                            ),
                        ));
                    }
                }
                if let Some((u, h)) = contact.split_once('@')
                    && h == domain
                    && storage::load(root, domain, Some(u), "accounts")?.is_some()
                {
                    let other = storage::update(root, domain, Some(u), "roster", |v| {
                        if let Some(mut e) = v.get(own).cloned() {
                            set_subscription(&mut e, false, false);
                            e.set("ask", V::Nil);
                            v.set(own, e);
                        }
                        set_pending(v, own, V::Nil);
                        bump(v)?;
                        Ok(())
                    })?;
                    roster_push(&mut result, &contact, own, &other);
                }
            }
            Ok(Some(result))
        }
        "jabber:iq:private" => {
            let children: Vec<_> = q.children().filter(|n| n.is_element()).collect();
            if q.tag_name().name() != "query" || children.len() != 1 {
                return Ok(err(iq, "bad-request"));
            }
            let n = children[0];
            let Some(ns) = n.tag_name().namespace() else {
                return Ok(err(iq, "bad-request"));
            };
            if ns == "jabber:iq:private" {
                return Ok(err(iq, "bad-request"));
            }
            let key = format!("{}:{ns}", n.tag_name().name());
            if typ == "set" {
                storage::update(root, domain, Some(user), "private", |v| {
                    v.set(
                        &key,
                        if n.children().any(|c| c.is_element() || c.is_text()) {
                            storage::stanza_value(n)
                        } else {
                            V::Nil
                        },
                    );
                    Ok(())
                })?;
                Ok(reply(iq, ""))
            } else {
                let data = storage::load(root, domain, Some(user), "private")?.unwrap_or_default();
                let value = data
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| storage::stanza_value(n));
                Ok(reply(
                    iq,
                    &format!(
                        "<query xmlns='jabber:iq:private'>{}</query>",
                        storage::stanza_xml(&value)?
                    ),
                ))
            }
        }
        "vcard-temp" => {
            if q.tag_name().name() != "vCard" {
                return Ok(err(iq, "bad-request"));
            }
            if typ == "set" {
                if target != own {
                    return Ok(err(iq, "forbidden"));
                }
                storage::save(
                    root,
                    domain,
                    Some(user),
                    vcard_store,
                    &storage::stanza_value(q),
                )?;
                Ok(reply(iq, ""))
            } else {
                let target_user = if target == domain {
                    None
                } else {
                    match target.split_once('@') {
                        Some((u, h)) if h == domain => Some(u),
                        _ => return Ok(None),
                    }
                };
                match storage::load(root, domain, target_user, vcard_store)? {
                    Some(v) => Ok(reply(iq, &storage::stanza_xml(&v)?)),
                    None => Ok(err(iq, "item-not-found")),
                }
            }
        }
        "urn:xmpp:blocking" => {
            let name = q.tag_name().name();
            if typ == "get" && name == "blocklist" {
                let data = load_blocklist(root, domain, user, true)?;
                let mut s = "<blocklist xmlns='urn:xmpp:blocking'>".to_string();
                for (k, v) in data.entries() {
                    if !matches!(v, V::Nil | V::Bool(false))
                        && let Some(j) = k.as_str()
                    {
                        s.push_str(&format!("<item jid='{}'/>", escape(j)))
                    }
                }
                s.push_str("</blocklist>");
                return Ok(reply(iq, &s));
            }
            if typ != "set" || !["block", "unblock"].contains(&name) {
                return Ok(err(iq, "bad-request"));
            }
            let mut contacts = vec![];
            for n in q.children().filter(|n| n.is_element()) {
                if !n.has_tag_name(("urn:xmpp:blocking", "item")) {
                    return Ok(err(iq, "bad-request"));
                }
                let Some(j) = n.attribute("jid") else {
                    return Ok(err(iq, "bad-request"));
                };
                let j = match normalize_jid(j) {
                    Ok(j) => j,
                    Err(_) => return Ok(err(iq, "jid-malformed")),
                };
                contacts.push(j);
            }
            if name == "block" && contacts.is_empty() {
                return Ok(err(iq, "bad-request"));
            }
            let _ = load_blocklist(root, domain, user, true)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64;
            storage::update(root, domain, Some(user), "blocklist", |v| {
                let mut meta = v.get_key(&V::Bool(false)).cloned().unwrap_or_default();
                if meta.get("created").is_none() {
                    meta.set("created", V::Integer(now));
                }
                meta.set("modified", V::Integer(now));
                if name == "unblock" && contacts.is_empty() {
                    *v = V::table()
                } else {
                    for j in &contacts {
                        v.set(
                            j,
                            if name == "block" {
                                V::Integer(now)
                            } else {
                                V::Nil
                            },
                        );
                    }
                }
                v.set_key(V::Bool(false), meta);
                Ok(())
            })?;
            let mut r = ModuleResult::reply(iq_result(iq, ""));
            r.deliveries.push((
                own.into(),
                format!(
                    "<iq xmlns='jabber:client' type='set' id='blocklist-{}'>{}</iq>",
                    uuid::Uuid::new_v4(),
                    format_args!(
                        "<{name} xmlns='urn:xmpp:blocking'>{}</{name}>",
                        contacts
                            .iter()
                            .map(|j| format!("<item jid='{}'/>", escape(j)))
                            .collect::<String>()
                    )
                ),
            ));
            Ok(Some(r))
        }
        _ => Ok(None),
    }
}
/// Required by stanza routing for both inbound and outbound filtering.
pub fn is_blocked(root: &Path, domain: &str, user: &str, contact: &str) -> Result<bool> {
    let v = load_blocklist(root, domain, user, true)?;
    let b = bare(contact);
    let h = b.split_once('@').map(|(_, h)| h).unwrap_or(b);
    Ok([contact, b, h].iter().any(|k| {
        v.get(k)
            .is_some_and(|value| !matches!(value, V::Nil | V::Bool(false)))
    }))
}

pub fn normalize_bare_jid(jid: &str) -> Result<String> {
    ensure!(!jid.contains('/'), "bare JID required");
    let (u, h) = match jid.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, jid),
    };
    let h = stringprep::nameprep(h).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    ensure!(
        !h.is_empty()
            && h.len() <= 1023
            && !h
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || "@<>\"'&".contains(c)),
        "invalid domain"
    );
    if let Some(u) = u {
        let u = stringprep::nodeprep(u).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        ensure!(!u.is_empty() && u.len() <= 1023, "invalid localpart");
        Ok(format!("{u}@{h}"))
    } else {
        Ok(h.into_owned())
    }
}
fn normalize_jid(jid: &str) -> Result<String> {
    match jid.split_once('/') {
        Some((b, r)) => {
            let b = normalize_bare_jid(b)?;
            let r = stringprep::resourceprep(r).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            ensure!(!r.is_empty() && r.len() <= 1023, "invalid resource");
            Ok(format!("{b}/{r}"))
        }
        None => normalize_bare_jid(jid),
    }
}
fn contact_entry(data: &V, contact: &str) -> V {
    data.get(contact).cloned().unwrap_or_else(|| {
        let mut v = V::table();
        v.set("subscription", "none".into());
        v.set("groups", V::table());
        v
    })
}
fn set_subscription(v: &mut V, to: bool, from: bool) {
    v.set(
        "subscription",
        match (to, from) {
            (true, true) => "both",
            (true, false) => "to",
            (false, true) => "from",
            _ => "none",
        }
        .into(),
    );
}
fn directions(v: &V) -> (bool, bool) {
    match text(v, "subscription") {
        Some("both") => (true, true),
        Some("to") => (true, false),
        Some("from") => (false, true),
        _ => (false, false),
    }
}
fn pending(data: &V, contact: &str) -> bool {
    data.get_key(&V::Bool(false))
        .and_then(|m| m.get("pending"))
        .and_then(|p| p.get(contact))
        .is_some()
}
fn set_pending(data: &mut V, contact: &str, value: V) {
    let mut meta = data.get_key(&V::Bool(false)).cloned().unwrap_or_default();
    let mut p = meta.get("pending").cloned().unwrap_or_default();
    p.set(contact, value);
    meta.set("pending", p);
    data.set_key(V::Bool(false), meta);
}
fn roster_push(result: &mut ModuleResult, owner: &str, contact: &str, data: &V) {
    let item = data
        .get(contact)
        .map(|v| roster_item(contact, v))
        .unwrap_or_else(|| format!("<item jid='{}' subscription='remove'/>", escape(contact)));
    result.deliveries.push((owner.into(),format!("<iq xmlns='jabber:client' type='set' id='roster-{}'><query xmlns='jabber:iq:roster' ver='{}'>{item}</query></iq>",uuid::Uuid::new_v4(),version(data))));
}
/// Apply an authenticated client's subscription transition. Remote delivery is routed by caller.
pub fn subscription(
    root: &Path,
    domain: &str,
    jid: &str,
    p: Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    let kind = p.attribute("type").unwrap_or("");
    if !["subscribe", "subscribed", "unsubscribe", "unsubscribed"].contains(&kind) {
        return Ok(None);
    }
    let Some(raw) = p.attribute("to") else {
        return Ok(Some(ModuleResult::default()));
    };
    let target = normalize_bare_jid(bare(raw))?;
    let sender = bare(jid);
    let (user, h) = sender
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("unauthenticated sender"))?;
    ensure!(h == domain, "wrong domain");
    if sender == target {
        return Ok(Some(ModuleResult::default()));
    }
    if is_blocked(root, domain, user, &target)? {
        return Ok(Some(ModuleResult::default()));
    }
    let mut r = ModuleResult::default();
    let mut deliver = true;
    let data = storage::update(root, domain, Some(user), "roster", |data| {
        let mut entry = contact_entry(data, &target);
        let (to, from) = directions(&entry);
        match kind {
            "subscribe" => {
                if to {
                    deliver = false
                } else {
                    entry.set("ask", "subscribe".into())
                }
            }
            "subscribed" => {
                if pending(data, &target) {
                    set_pending(data, &target, V::Nil);
                    set_subscription(&mut entry, to, true)
                } else if !from {
                    entry.set("approved", "true".into());
                    deliver = false
                }
            }
            "unsubscribe" => {
                entry.set("ask", V::Nil);
                set_subscription(&mut entry, false, from)
            }
            "unsubscribed" => {
                set_pending(data, &target, V::Nil);
                entry.set("approved", V::Nil);
                set_subscription(&mut entry, to, false)
            }
            _ => {}
        }
        data.set(&target, entry);
        bump(data)?;
        Ok(())
    })?;
    roster_push(&mut r, sender, &target, &data);
    if !deliver {
        return Ok(Some(r));
    }
    let (to_user, to_host) = target.split_once('@').unwrap_or(("", &target));
    let stanza = crate::protocol::address(p, sender, &target);
    if to_host == domain {
        if storage::load(root, domain, Some(to_user), "accounts")?.is_none() {
            return Ok(Some(r));
        }
        if is_blocked(root, domain, to_user, sender)? {
            return Ok(Some(r));
        }
        let preauthenticated = match crate::preauth::token_from_presence(p) {
            Some(token) => crate::preauth::consume(
                root,
                domain,
                &target,
                sender,
                token,
                chrono::Utc::now().timestamp(),
            )?,
            None => false,
        };
        let mut autoapprove = false;
        let recipient = storage::update(root, domain, Some(to_user), "roster", |data| {
            let mut entry = contact_entry(data, sender);
            let (to, from) = directions(&entry);
            match kind {
                "subscribe" => {
                    if preauthenticated || from || text(&entry, "approved") == Some("true") {
                        autoapprove = true;
                        set_pending(data, sender, V::Nil);
                        set_subscription(&mut entry, to, true);
                    } else {
                        let d = roxmltree::Document::parse(&stanza)?;
                        set_pending(data, sender, storage::stanza_value(d.root_element()));
                    }
                }
                "subscribed" => {
                    if text(&entry, "ask") == Some("subscribe") {
                        entry.set("ask", V::Nil);
                        set_subscription(&mut entry, true, from)
                    } else {
                        deliver = false
                    }
                }
                "unsubscribe" => {
                    set_pending(data, sender, V::Nil);
                    set_subscription(&mut entry, to, false)
                }
                "unsubscribed" => {
                    entry.set("ask", V::Nil);
                    set_subscription(&mut entry, false, from)
                }
                _ => {}
            }
            data.set(sender, entry);
            bump(data)?;
            Ok(())
        })?;
        roster_push(&mut r, &target, sender, &recipient);
        if autoapprove {
            let own = storage::update(root, domain, Some(user), "roster", |data| {
                let mut entry = contact_entry(data, &target);
                let (_, from) = directions(&entry);
                entry.set("ask", V::Nil);
                set_subscription(&mut entry, true, from);
                data.set(&target, entry);
                bump(data)?;
                Ok(())
            })?;
            roster_push(&mut r, sender, &target, &own);
            r.deliveries.push((
                sender.into(),
                format!(
                    "<presence xmlns='jabber:client' from='{}' to='{}' type='subscribed'/>",
                    escape(&target),
                    escape(sender)
                ),
            ));
            deliver = false;
        }
        if preauthenticated {
            let reciprocal = format!(
                "<presence xmlns='jabber:client' to='{}' type='subscribe'/>",
                escape(sender)
            );
            let doc = roxmltree::Document::parse(&reciprocal)?;
            if let Some(mut result) = subscription(root, domain, &target, doc.root_element())? {
                r.deliveries.append(&mut result.deliveries);
                r.replies.append(&mut result.replies);
            }
        }
    }
    if deliver {
        r.deliveries.push((target, stanza));
    }
    Ok(Some(r))
}
pub fn subscribers(root: &Path, domain: &str, user: &str) -> Result<Vec<String>> {
    contacts(root, domain, user, false)
}
pub fn subscriptions(root: &Path, domain: &str, user: &str) -> Result<Vec<String>> {
    contacts(root, domain, user, true)
}
fn contacts(root: &Path, domain: &str, user: &str, outbound: bool) -> Result<Vec<String>> {
    let d = storage::load(root, domain, Some(user), "roster")?.unwrap_or_default();
    Ok(d.entries()
        .iter()
        .filter_map(|(k, v)| {
            let (t, f) = directions(v);
            if if outbound { t } else { f } {
                k.as_str().map(str::to_owned)
            } else {
                None
            }
        })
        .collect())
}
/// Pending subscription requests must be replayed on initial available presence.
pub fn pending_subscriptions(root: &Path, domain: &str, user: &str) -> Result<Vec<String>> {
    let data = storage::load(root, domain, Some(user), "roster")?.unwrap_or_default();
    let mut out = vec![];
    if let Some(p) = data.get_key(&V::Bool(false)).and_then(|m| m.get("pending")) {
        for (k, v) in p.entries() {
            if let Some(sender) = k.as_str() {
                out.push(if *v == V::Bool(true) {
                    format!(
                        "<presence xmlns='jabber:client' type='subscribe' from='{}' to='{}@{}'/>",
                        escape(sender),
                        escape(user),
                        escape(domain)
                    )
                } else {
                    storage::stanza_xml(v)?
                });
            }
        }
    }
    Ok(out)
}
/// Persist eligible messages for delivery after the recipient becomes available.
pub fn offline_enqueue(root: &Path, domain: &str, user: &str, xml: &str) -> Result<bool> {
    let d = roxmltree::Document::parse(xml)?;
    let n = d.root_element();
    if n.tag_name().name() != "message"
        || !["chat", "normal"].contains(&n.attribute("type").unwrap_or("normal"))
    {
        return Ok(false);
    }
    if n.children().any(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some("urn:xmpp:hints")
            && ["no-store", "no-storage"].contains(&n.tag_name().name())
    }) {
        return Ok(false);
    }
    if storage::load(root, domain, Some(user), "accounts")?.is_none() {
        return Ok(false);
    }
    crate::archive::append_new(
        root,
        domain,
        Some(user),
        "offline",
        crate::archive::Entry {
            id: uuid::Uuid::new_v4().to_string(),
            when: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs_f64(),
            peer: "".into(),
            xml: xml.into(),
        },
    )?;
    Ok(true)
}
/// Returns IDs with stanzas; delete IDs only after queueing them successfully to recipient.
pub fn offline_pending(root: &Path, domain: &str, user: &str) -> Result<Vec<(String, String)>> {
    crate::archive::load_store(root, domain, Some(user), "offline")?
        .into_iter()
        .map(|e| {
            let d = roxmltree::Document::parse(&e.xml)?;
            let mut value = storage::stanza_value(d.root_element());
            let delay = format!(
                "<delay xmlns='urn:xmpp:delay' from='{}' stamp='{}'/>",
                escape(domain),
                crate::archive::timestamp(e.when)?
            );
            let dd = roxmltree::Document::parse(&delay)?;
            let mut i = 1;
            while value.get_key(&V::Integer(i)).is_some() {
                i += 1;
            }
            value.set_key(V::Integer(i), storage::stanza_value(dd.root_element()));
            Ok((e.id, storage::stanza_xml(&value)?))
        })
        .collect()
}
const PUBSUB: &str = "http://jabber.org/protocol/pubsub";
static LEGACY_PEP_LIMITS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::BTreeMap<(std::path::PathBuf, String), usize>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
/// Set once when constructing a runtime, matching the host's pep_max_items option.
pub fn set_legacy_pep_limit(root: &Path, domain: &str, max_items: usize) -> Result<()> {
    ensure!(max_items > 0, "PEP item limit must be positive");
    LEGACY_PEP_LIMITS
        .lock()
        .map_err(|_| anyhow::anyhow!("PEP limit lock poisoned"))?
        .insert((root.to_owned(), domain.into()), max_items);
    Ok(())
}

fn pep_request(
    root: &Path,
    domain: &str,
    actor: &str,
    owner: &str,
    kind: &str,
    body: &str,
    owner_ns: bool,
) -> Result<ModuleResult> {
    let ns = if owner_ns {
        "http://jabber.org/protocol/pubsub#owner"
    } else {
        PUBSUB
    };
    let s = format!(
        "<iq type='{kind}' id='internal' to='{}'><pubsub xmlns='{ns}'>{body}</pubsub></iq>",
        escape(owner)
    );
    let d = roxmltree::Document::parse(&s)?;
    let max_items = LEGACY_PEP_LIMITS
        .lock()
        .map_err(|_| anyhow::anyhow!("PEP limit lock poisoned"))?
        .get(&(root.to_owned(), domain.into()))
        .copied()
        .unwrap_or(256);
    let options = crate::pubsub::Options {
        max_items,
        ..Default::default()
    };
    crate::pubsub::handle_with_options(root, domain, actor, d.root_element(), &options)?
        .ok_or_else(|| anyhow::anyhow!("PEP target unsupported"))
}
fn pep_items(
    root: &Path,
    domain: &str,
    actor: &str,
    owner: &str,
    node: &str,
) -> Result<Vec<(String, String)>> {
    let r = pep_request(
        root,
        domain,
        actor,
        owner,
        "get",
        &format!(
            "<items node='{}' max_items='{}'/>",
            escape(node),
            usize::MAX
        ),
        false,
    )?;
    let s = r
        .replies
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing PEP response"))?;
    let d = roxmltree::Document::parse(s)?;
    if d.root_element().attribute("type") == Some("error") {
        if d.descendants().any(|n| n.has_tag_name("item-not-found")) {
            return Ok(vec![]);
        }
        anyhow::bail!("PEP retrieval denied");
    }
    Ok(d.descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "item"
                && n.tag_name().namespace() == Some(PUBSUB)
        })
        .map(|n| {
            (
                n.attribute("id").unwrap_or("").into(),
                crate::protocol::xml(n),
            )
        })
        .collect())
}
// Explicit storage coordinates keep the compatibility helper independent of runtime state.
#[allow(clippy::too_many_arguments)]
fn pep_publish(
    root: &Path,
    domain: &str,
    actor: &str,
    node: &str,
    id: &str,
    payload: &str,
    access: &str,
    max: &str,
) -> Result<Vec<(String, String)>> {
    let owner = bare(actor);
    let create = pep_request(
        root,
        domain,
        actor,
        owner,
        "set",
        &format!(
            "<create node='{}'/><configure><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#access_model'><value>{access}</value></field><field var='pubsub#max_items'><value>{max}</value></field></x></configure>",
            escape(node)
        ),
        false,
    )?;
    if create
        .replies
        .iter()
        .any(|x| x.contains("type='error'") && !x.contains("conflict"))
    {
        anyhow::bail!("PEP node creation rejected")
    }
    let r = pep_request(
        root,
        domain,
        actor,
        owner,
        "set",
        &format!(
            "<publish node='{}'><item id='{}'>{payload}</item></publish>",
            escape(node),
            escape(id)
        ),
        false,
    )?;
    if r.replies.iter().any(|x| x.contains("type='error'")) {
        anyhow::bail!("PEP publish rejected")
    };
    Ok(r.deliveries)
}
fn child<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    n.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}
fn child_text<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Option<&'a str> {
    child(n, name).and_then(|n| n.text())
}
fn tag(name: &str, text: Option<&str>) -> String {
    format!("<{name}>{}</{name}>", escape(text.unwrap_or("")))
}
fn category(n: Node<'_, '_>, v4: bool) -> String {
    if v4 {
        let typ = if child(n, "HOME").is_some() {
            "home"
        } else if child(n, "WORK").is_some() {
            "work"
        } else {
            ""
        };
        format!(
            "<parameters><type>{}</type></parameters>",
            tag("text", Some(typ))
        )
    } else {
        let typ = child(n, "parameters")
            .and_then(|p| child(p, "type"))
            .and_then(|t| child_text(t, "text"));
        match typ {
            Some("home") => "<HOME/>".into(),
            Some("work") => "<WORK/>".into(),
            _ => String::new(),
        }
    }
}
/// XEP-0398 conversion following the pinned Prosody module's field mappings.
pub type AvatarPayload = (String, String, String);
pub fn vcard_to_pep(n: Node<'_, '_>) -> Result<(String, Option<AvatarPayload>)> {
    use base64::Engine;
    use sha1::{Digest, Sha1};
    let mut s = "<vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'>".to_string();
    s.push_str(&format!("<fn>{}</fn>", tag("text", child_text(n, "FN"))));
    s.push_str("<n>");
    let name = child(n, "N");
    for (a, b) in [
        ("surname", "FAMILY"),
        ("given", "GIVEN"),
        ("additional", "MIDDLE"),
        ("prefix", "PREFIX"),
        ("suffix", "SUFFIX"),
    ] {
        s.push_str(&tag(a, name.and_then(|n| child_text(n, b))))
    }
    s.push_str("</n>");
    let mut avatar = None;
    for c in n.children().filter(|n| n.is_element()) {
        let name = c.tag_name().name();
        let lower = name.to_lowercase();
        let simple = match name {
            "NICKNAME" | "TITLE" | "ROLE" | "CATEGORIES" | "NOTE" => Some("text"),
            "URL" => Some("uri"),
            "BDAY" => Some("date"),
            _ => None,
        };
        if let Some(typ) = simple {
            s.push_str(&format!("<{lower}>{}</{lower}>", tag(typ, c.text())));
            continue;
        }
        match name {
            "EMAIL" => {
                if let Some(t) = child_text(c, "USERID") {
                    s.push_str(&format!(
                        "<email>{}{}</email>",
                        tag("text", Some(t)),
                        category(c, true)
                    ))
                }
            }
            "TEL" => {
                if let Some(t) = child_text(c, "NUMBER") {
                    s.push_str(&format!(
                        "<tel>{}{}</tel>",
                        tag("uri", Some(&format!("tel:{t}"))),
                        category(c, true)
                    ))
                }
            }
            "ORG" => s.push_str(&format!(
                "<org>{}</org>",
                tag("text", child_text(c, "ORGNAME"))
            )),
            "DESC" => s.push_str(&format!("<note>{}</note>", tag("text", c.text()))),
            "ADR" => {
                s.push_str("<adr>");
                for (a, b) in [
                    ("pobox", "POBOX"),
                    ("ext", "EXTADD"),
                    ("street", "STREET"),
                    ("locality", "LOCALITY"),
                    ("region", "REGION"),
                    ("code", "PCODE"),
                    ("country", "CTRY"),
                ] {
                    s.push_str(&tag(a, child_text(c, b)))
                }
                s.push_str(&category(c, true));
                s.push_str("</adr>")
            }
            "JABBERID" => s.push_str(&format!(
                "<impp>{}</impp>",
                tag("uri", Some(&format!("xmpp:{}", c.text().unwrap_or(""))))
            )),
            "PHOTO" => {
                if let Some(payload) = child_text(c, "BINVAL") {
                    let compact: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
                    let raw = base64::engine::general_purpose::STANDARD.decode(&compact)?;
                    ensure!(raw.len() <= 1024 * 1024, "avatar too large");
                    let hash = hex::encode(Sha1::digest(&raw));
                    let data = format!(
                        "<data xmlns='urn:xmpp:avatar:data'>{}</data>",
                        escape(&compact)
                    );
                    let mime = child_text(c, "TYPE")
                        .map(|t| format!(" type='{}'", escape(t)))
                        .unwrap_or_default();
                    let metadata = format!(
                        "<metadata xmlns='urn:xmpp:avatar:metadata'><info id='{hash}' bytes='{}'{mime}/></metadata>",
                        raw.len()
                    );
                    avatar = Some((hash, data, metadata));
                }
            }
            _ => {}
        }
    }
    s.push_str("</vcard>");
    Ok((s, avatar))
}
fn v4_to_temp(n: Node<'_, '_>) -> String {
    let mut s = tag("FN", child(n, "fn").and_then(|n| child_text(n, "text")));
    s.push_str("<N>");
    let name = child(n, "n");
    for (a, b) in [
        ("FAMILY", "surname"),
        ("GIVEN", "given"),
        ("MIDDLE", "additional"),
        ("PREFIX", "prefix"),
        ("SUFFIX", "suffix"),
    ] {
        s.push_str(&tag(a, name.and_then(|n| child_text(n, b))))
    }
    s.push_str("</N>");
    for c in n.children().filter(|n| n.is_element()) {
        let name = c.tag_name().name();
        let simple = match name {
            "nickname" | "title" | "role" | "categories" | "note" => Some("text"),
            "url" => Some("uri"),
            "bday" => Some("date"),
            _ => None,
        };
        if let Some(t) = simple {
            s.push_str(&tag(&name.to_uppercase(), child_text(c, t)));
            continue;
        }
        match name {
            "email" => s.push_str(&format!(
                "<EMAIL>{}<INTERNET/>{}</EMAIL>",
                tag("USERID", child_text(c, "text")),
                category(c, false)
            )),
            "tel" => s.push_str(&format!(
                "<TEL>{}{}</TEL>",
                tag(
                    "NUMBER",
                    child_text(c, "uri").map(|v| v.strip_prefix("tel:").unwrap_or(v))
                ),
                category(c, false)
            )),
            "org" => s.push_str(&format!(
                "<ORG>{}</ORG>",
                tag("ORGNAME", child_text(c, "text"))
            )),
            "impp" => {
                if let Some(v) = child_text(c, "uri").and_then(|v| v.strip_prefix("xmpp:")) {
                    s.push_str(&tag("JABBERID", Some(v)))
                }
            }
            "adr" => {
                s.push_str("<ADR>");
                for (a, b) in [
                    ("POBOX", "pobox"),
                    ("EXTADD", "ext"),
                    ("STREET", "street"),
                    ("LOCALITY", "locality"),
                    ("REGION", "region"),
                    ("PCODE", "code"),
                    ("CTRY", "country"),
                ] {
                    s.push_str(&tag(a, child_text(c, b)))
                }
                s.push_str(&category(c, false));
                s.push_str("</ADR>")
            }
            _ => {}
        }
    }
    s
}
pub fn handle_legacy(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    let Some(q) = iq.children().find(|n| n.is_element()) else {
        return Ok(None);
    };
    let ns = q.tag_name().namespace().unwrap_or("");
    if !["vcard-temp", "urn:ietf:params:xml:ns:vcard-4.0"].contains(&ns) {
        return handle_bookmarks(root, domain, jid, iq);
    }
    if iq.children().filter(|n| n.is_element()).count() != 1 || iq.attribute("id").is_none() {
        return Ok(err(iq, "bad-request"));
    }
    if (ns == "vcard-temp" && q.tag_name().name() != "vCard")
        || (ns == "urn:ietf:params:xml:ns:vcard-4.0" && q.tag_name().name() != "vcard")
    {
        return Ok(err(iq, "bad-request"));
    }
    let typ = iq.attribute("type").unwrap_or("");
    if !["get", "set"].contains(&typ) {
        return Ok(None);
    }
    let owner = bare(iq.attribute("to").unwrap_or(jid));
    if !owner.ends_with(&format!("@{domain}")) {
        return Ok(None);
    }
    if typ == "set" {
        if owner != bare(jid) {
            return Ok(err(iq, "forbidden"));
        }
        let mut r = ModuleResult::reply(iq_result(iq, ""));
        if ns == "vcard-temp" {
            let (v4, avatar) = match vcard_to_pep(q) {
                Ok(v) => v,
                Err(_) => return Ok(err(iq, "bad-request")),
            };
            for node in ["urn:xmpp:avatar:metadata", "urn:xmpp:avatar:data"] {
                let purge = pep_request(
                    root,
                    domain,
                    jid,
                    owner,
                    "set",
                    &format!("<purge node='{node}'/>"),
                    true,
                )?;
                r.deliveries.extend(purge.deliveries);
            }
            if let Some((hash, data, meta)) = avatar {
                r.deliveries.extend(pep_publish(
                    root,
                    domain,
                    jid,
                    "urn:xmpp:avatar:data",
                    &hash,
                    &data,
                    "open",
                    "1",
                )?);
                r.deliveries.extend(pep_publish(
                    root,
                    domain,
                    jid,
                    "urn:xmpp:avatar:metadata",
                    &hash,
                    &meta,
                    "open",
                    "1",
                )?);
            }
            r.deliveries.extend(pep_publish(
                root,
                domain,
                jid,
                "urn:xmpp:vcard4",
                "current",
                &v4,
                "open",
                "1",
            )?);
        } else {
            r.deliveries.extend(pep_publish(
                root,
                domain,
                jid,
                "urn:xmpp:vcard4",
                "current",
                &crate::protocol::xml(q),
                "presence",
                "1",
            )?);
        }
        return Ok(Some(r));
    }
    let items = match pep_items(root, domain, jid, owner, "urn:xmpp:vcard4") {
        Ok(v) => v,
        Err(_) => return Ok(err(iq, "forbidden")),
    };
    let v4 = items
        .last()
        .and_then(|(_, s)| roxmltree::Document::parse(s).ok())
        .map(|d| {
            d.root_element()
                .children()
                .find(|n| n.is_element())
                .map(crate::protocol::xml)
                .unwrap_or_default()
        });
    if ns != "vcard-temp" {
        return Ok(match v4 {
            Some(s) => reply(iq, &s),
            None => err(iq, "item-not-found"),
        });
    }
    let mut s = "<vCard xmlns='vcard-temp'>".to_string();
    if let Some(v4) = v4 {
        let d = roxmltree::Document::parse(&v4)?;
        s.push_str(&v4_to_temp(d.root_element()));
    } else if let Ok(items) = pep_items(root, domain, jid, owner, "http://jabber.org/protocol/nick")
        && let Some((_, x)) = items.last()
    {
        let d = roxmltree::Document::parse(x)?;
        s.push_str(&tag("NICKNAME", child_text(d.root_element(), "nick")));
    }
    if let Ok(items) = pep_items(root, domain, jid, owner, "urn:xmpp:avatar:metadata")
        && let Some((_, x)) = items.last()
    {
        let d = roxmltree::Document::parse(x)?;
        if let Some(info) = d.descendants().find(|n| n.has_tag_name("info")) {
            s.push_str("<PHOTO>");
            if let Some(t) = info.attribute("type") {
                s.push_str(&tag("TYPE", Some(t)))
            }
            if let Some(url) = info.attribute("url") {
                s.push_str(&tag("EXTVAL", Some(url)))
            } else if let Some(hash) = info.attribute("id")
                && let Ok(data) = pep_items(root, domain, jid, owner, "urn:xmpp:avatar:data")
                && let Some((_, x)) = data.iter().find(|(id, _)| id == hash)
            {
                let d = roxmltree::Document::parse(x)?;
                s.push_str(&tag("BINVAL", child_text(d.root_element(), "data")))
            }
            s.push_str("</PHOTO>");
        }
    }
    s.push_str("</vCard>");
    Ok(reply(iq, &s))
}
pub fn legacy_bookmarks(root: &Path, domain: &str, actor: &str) -> Result<String> {
    legacy_bookmark_storage(&pep_items(
        root,
        domain,
        actor,
        bare(actor),
        "urn:xmpp:bookmarks:1",
    )?)
}
pub fn legacy_bookmark_storage(items: &[(String, String)]) -> Result<String> {
    let mut s = "<storage xmlns='storage:bookmarks'>".to_string();
    for (id, x) in items {
        let d = roxmltree::Document::parse(x)?;
        if let Some(c) = child(d.root_element(), "conference") {
            s.push_str(&format!("<conference jid='{}'", escape(id)));
            for a in ["name", "autojoin"] {
                if let Some(v) = c.attribute(a) {
                    s.push_str(&format!(" {a}='{}'", escape(v)))
                }
            }
            s.push('>');
            for name in ["nick", "password"] {
                if let Some(t) = child_text(c, name) {
                    s.push_str(&tag(name, Some(t)))
                }
            }
            s.push_str("</conference>");
        }
    }
    s.push_str("</storage>");
    Ok(s)
}
fn save_bookmarks(
    root: &Path,
    domain: &str,
    actor: &str,
    bookmarks: Node<'_, '_>,
    synchronize: bool,
) -> Result<Vec<(String, String)>> {
    let previous = pep_items(root, domain, actor, bare(actor), "urn:xmpp:bookmarks:1")?;
    let mut keep = vec![];
    let mut out = vec![];
    // Validate the entire request before mutating any node.
    for c in bookmarks
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "conference")
    {
        normalize_bare_jid(c.attribute("jid").unwrap_or(""))?;
    }
    for c in bookmarks
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "conference")
    {
        let id = normalize_bare_jid(c.attribute("jid").unwrap())?;
        keep.push(id.clone());
        let mut payload = "<conference xmlns='urn:xmpp:bookmarks:1'".to_string();
        for a in ["name", "autojoin"] {
            if let Some(v) = c.attribute(a) {
                payload.push_str(&format!(" {a}='{}'", escape(v)))
            }
        }
        payload.push('>');
        for name in ["nick", "password"] {
            if let Some(t) = child_text(c, name) {
                payload.push_str(&tag(name, Some(t)))
            }
        }
        payload.push_str("</conference>");
        out.extend(pep_publish(
            root,
            domain,
            actor,
            "urn:xmpp:bookmarks:1",
            &id,
            &payload,
            "whitelist",
            "max",
        )?);
    }
    if synchronize {
        for (id, _) in previous {
            if !keep.contains(&id) {
                let r = pep_request(
                    root,
                    domain,
                    actor,
                    bare(actor),
                    "set",
                    &format!(
                        "<retract node='urn:xmpp:bookmarks:1' notify='true'><item id='{}'/></retract>",
                        escape(&id)
                    ),
                    false,
                )?;
                ensure!(
                    !r.replies.iter().any(|s| s.contains("type='error'")),
                    "bookmark retract failed"
                );
                out.extend(r.deliveries);
            }
        }
    }
    Ok(out)
}
fn handle_bookmarks(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    let Some(q) = iq.children().find(|n| n.is_element()) else {
        return Ok(None);
    };
    let ns = q.tag_name().namespace().unwrap_or("");
    let typ = iq.attribute("type").unwrap_or("");
    if !["get", "set"].contains(&typ) {
        return Ok(None);
    }
    let private = ns == "jabber:iq:private"
        && child(q, "storage")
            .is_some_and(|n| n.tag_name().namespace() == Some("storage:bookmarks"));
    let pubsub = ns == PUBSUB
        && q.children()
            .any(|n| n.is_element() && n.attribute("node") == Some("storage:bookmarks"));
    if !private && !pubsub {
        return Ok(None);
    }
    if (private && q.tag_name().name() != "query") || (pubsub && q.tag_name().name() != "pubsub") {
        return Ok(err(iq, "bad-request"));
    }
    if private && q.children().filter(|n| n.is_element()).count() != 1 {
        return Ok(err(iq, "bad-request"));
    }
    if pubsub
        && typ == "get"
        && !q.children().any(|n| {
            n.has_tag_name((PUBSUB, "items")) && n.attribute("node") == Some("storage:bookmarks")
        })
    {
        return Ok(err(iq, "bad-request"));
    }
    if iq.children().filter(|n| n.is_element()).count() != 1 || iq.attribute("id").is_none() {
        return Ok(err(iq, "bad-request"));
    }
    let owner = bare(iq.attribute("to").unwrap_or(jid));
    if owner != bare(jid) {
        return Ok(err(iq, "forbidden"));
    }
    if typ == "get" {
        let storage = legacy_bookmarks(root, domain, jid)?;
        let payload = if private {
            format!("<query xmlns='jabber:iq:private'>{storage}</query>")
        } else {
            format!(
                "<pubsub xmlns='{PUBSUB}'><items node='storage:bookmarks'><item id='current'>{storage}</item></items></pubsub>"
            )
        };
        return Ok(reply(iq, &payload));
    }
    let bookmarks = if private {
        child(q, "storage")
    } else {
        child(q, "publish")
            .and_then(|n| child(n, "item"))
            .and_then(|n| child(n, "storage"))
    };
    let Some(bookmarks) = bookmarks else {
        return Ok(err(iq, "bad-request"));
    };
    let deliveries = match save_bookmarks(root, domain, jid, bookmarks, true) {
        Ok(v) => v,
        Err(_) => return Ok(err(iq, "bad-request")),
    };
    let mut r = ModuleResult::reply(iq_result(iq, ""));
    r.deliveries = deliveries;
    Ok(Some(r))
}
/// Migrate legacy stores without replacing existing PEP items; remove source only after success.
pub fn legacy_on_bind(root: &Path, domain: &str, jid: &str) -> Result<ModuleResult> {
    let Some((user, h)) = bare(jid).split_once('@') else {
        return Ok(ModuleResult::default());
    };
    ensure!(h == domain, "wrong domain");
    let mut r = ModuleResult::default();
    if let Some(v) = storage::load(root, domain, Some(user), "vcard")? {
        let s = storage::stanza_xml(&v)?;
        let d = roxmltree::Document::parse(&s)?;
        let (v4, avatar) = vcard_to_pep(d.root_element())?;
        if pep_items(root, domain, jid, bare(jid), "urn:xmpp:vcard4")?.is_empty() {
            r.deliveries.extend(pep_publish(
                root,
                domain,
                jid,
                "urn:xmpp:vcard4",
                "current",
                &v4,
                "open",
                "1",
            )?);
        }
        if pep_items(root, domain, jid, bare(jid), "urn:xmpp:avatar:metadata")?.is_empty()
            && pep_items(root, domain, jid, bare(jid), "urn:xmpp:avatar:data")?.is_empty()
            && let Some((id, data, meta)) = avatar
        {
            r.deliveries.extend(pep_publish(
                root,
                domain,
                jid,
                "urn:xmpp:avatar:data",
                &id,
                &data,
                "open",
                "1",
            )?);
            r.deliveries.extend(pep_publish(
                root,
                domain,
                jid,
                "urn:xmpp:avatar:metadata",
                &id,
                &meta,
                "open",
                "1",
            )?);
        }
        storage::save(root, domain, Some(user), "vcard", &V::Nil)?;
    }
    let old = pep_items(root, domain, jid, bare(jid), "storage:bookmarks")?;
    for (_, item) in &old {
        let d = roxmltree::Document::parse(item)?;
        if let Some(bookmarks) = child(d.root_element(), "storage") {
            r.deliveries
                .extend(save_bookmarks(root, domain, jid, bookmarks, false)?);
        }
    }
    if !old.is_empty() {
        let purge = pep_request(
            root,
            domain,
            jid,
            bare(jid),
            "set",
            "<purge node='storage:bookmarks'/>",
            true,
        )?;
        ensure!(
            !purge.replies.iter().any(|s| s.contains("type='error'")),
            "legacy bookmarks purge failed"
        );
    }
    if let Some(data) = storage::load(root, domain, Some(user), "private")?
        && let Some(b) = data.get("storage:storage:bookmarks")
    {
        let s = storage::stanza_xml(b)?;
        let d = roxmltree::Document::parse(&s)?;
        r.deliveries
            .extend(save_bookmarks(root, domain, jid, d.root_element(), false)?);
        storage::update(root, domain, Some(user), "private", |v| {
            v.set("storage:storage:bookmarks", V::Nil);
            Ok(())
        })?;
    }
    Ok(r)
}
pub fn avatar_presence(
    root: &Path,
    domain: &str,
    jid: &str,
    presence: Node<'_, '_>,
) -> Result<String> {
    if presence.attribute("type").is_some() {
        return Ok(crate::protocol::xml(presence));
    }
    let mut v = storage::stanza_value(presence);
    if presence.children().any(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some("vcard-temp:x:update")
            && child(n, "photo").is_some()
    }) {
        return storage::stanza_xml(&v);
    }
    let items = pep_items(root, domain, jid, bare(jid), "urn:xmpp:avatar:metadata")?;
    let hash = items.last().map(|(id, _)| id.as_str()).unwrap_or("");
    let s = format!(
        "<x xmlns='vcard-temp:x:update'><photo>{}</photo></x>",
        escape(hash)
    );
    let d = roxmltree::Document::parse(&s)?;
    let mut i = 1;
    while v.get_key(&V::Integer(i)).is_some() {
        i += 1
    }
    v.set_key(V::Integer(i), storage::stanza_value(d.root_element()));
    storage::stanza_xml(&v)
}
/// Caller must authenticate the remote domain before invoking this federation handler.
pub fn inbound_subscription(
    root: &Path,
    domain: &str,
    from: &str,
    p: Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    let kind = p.attribute("type").unwrap_or("");
    if !["subscribe", "subscribed", "unsubscribe", "unsubscribed"].contains(&kind) {
        return Ok(None);
    }
    let sender = normalize_bare_jid(bare(from))?;
    let target = normalize_bare_jid(bare(p.attribute("to").unwrap_or("")))?;
    let (user, host) = target
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("recipient must be account"))?;
    ensure!(host == domain, "not local recipient");
    if storage::load(root, domain, Some(user), "accounts")?.is_none()
        || is_blocked(root, domain, user, &sender)?
    {
        return Ok(Some(ModuleResult::default()));
    }
    let preauthenticated = match crate::preauth::token_from_presence(p) {
        Some(token) => crate::preauth::consume(
            root,
            domain,
            &target,
            &sender,
            token,
            chrono::Utc::now().timestamp(),
        )?,
        None => false,
    };
    let mut deliver = true;
    let mut autoapprove = false;
    let stanza = crate::protocol::address(p, &sender, &target);
    let data = storage::update(root, domain, Some(user), "roster", |data| {
        let mut entry = contact_entry(data, &sender);
        let (to, from) = directions(&entry);
        match kind {
            "subscribe" => {
                if preauthenticated || from || text(&entry, "approved") == Some("true") {
                    autoapprove = true;
                    set_pending(data, &sender, V::Nil);
                    set_subscription(&mut entry, to, true)
                } else {
                    let d = roxmltree::Document::parse(&stanza)?;
                    set_pending(data, &sender, storage::stanza_value(d.root_element()))
                }
            }
            "subscribed" => {
                if text(&entry, "ask") == Some("subscribe") {
                    entry.set("ask", V::Nil);
                    set_subscription(&mut entry, true, from)
                } else {
                    deliver = false
                }
            }
            "unsubscribe" => {
                set_pending(data, &sender, V::Nil);
                set_subscription(&mut entry, to, false)
            }
            "unsubscribed" => {
                entry.set("ask", V::Nil);
                set_subscription(&mut entry, false, from)
            }
            _ => {}
        }
        data.set(&sender, entry);
        bump(data)?;
        Ok(())
    })?;
    let mut r = ModuleResult::default();
    roster_push(&mut r, &target, &sender, &data);
    if autoapprove {
        r.deliveries.push((
            sender.clone(),
            format!(
                "<presence xmlns='jabber:client' type='subscribed' from='{}' to='{}'/>",
                escape(&target),
                escape(&sender)
            ),
        ));
        deliver = false;
    }
    if preauthenticated {
        let reciprocal = format!(
            "<presence xmlns='jabber:client' to='{}' type='subscribe'/>",
            escape(&sender)
        );
        let doc = roxmltree::Document::parse(&reciprocal)?;
        if let Some(mut result) = subscription(root, domain, &target, doc.root_element())? {
            r.deliveries.append(&mut result.deliveries);
            r.replies.append(&mut result.replies);
        }
    }
    if deliver {
        r.deliveries.push((target, stanza));
    }
    Ok(Some(r))
}
/// The caller must disconnect all user sessions before calling; does not send stanzas.
pub fn remove_account(root: &Path, domain: &str, user: &str) -> Result<()> {
    ensure!(!user.is_empty(), "empty username");
    crate::archive::with_exclusive_access(|| storage::purge_user(root, domain, user))
}
/// Migrate only the legacy default deny-JID privacy list, matching mod_blocklist.
pub fn load_blocklist(root: &Path, domain: &str, user: &str, migrate: bool) -> Result<V> {
    if let Some(data) = storage::load(root, domain, Some(user), "blocklist")? {
        return Ok(data);
    }
    if !migrate || storage::load(root, domain, Some(user), "accounts")?.is_none() {
        return Ok(V::table());
    }
    let Some(privacy) = storage::load(root, domain, Some(user), "privacy")? else {
        return Ok(V::table());
    };
    let Some(default) = privacy.get("default").and_then(V::as_str) else {
        return Ok(V::table());
    };
    let Some(items) = privacy
        .get("lists")
        .and_then(|v| v.get(default))
        .and_then(|v| v.get("items"))
    else {
        return Ok(V::table());
    };
    let mut migrated = V::table();
    for (_, item) in items.entries() {
        if text(item, "type") == Some("jid")
            && text(item, "action") == Some("deny")
            && let Some(j) = text(item, "value")
            && let Ok(j) = normalize_jid(j)
        {
            migrated.set(&j, V::Bool(true));
        }
    }
    let mut metadata = V::table();
    metadata.set(
        "created",
        V::Integer(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64,
        ),
    );
    metadata.set("migrated", "privacy".into());
    migrated.set_key(V::Bool(false), metadata);
    storage::update(root, domain, Some(user), "blocklist", |data| {
        if data.entries().is_empty() {
            *data = migrated;
        }
        Ok(())
    })
}
