//! Personal XEP-0313 queries, preferences and RSM paging.
use crate::{
    archive,
    protocol::{self, ModuleResult},
    storage::{self, LuaValue as V},
    wire::escape,
};
use anyhow::{Context, Result, anyhow, bail};
use std::path::Path;
pub const NS: &str = "urn:xmpp:mam:2";
pub const EXTENDED_NS: &str = "urn:xmpp:mam:2#extended";
fn s(x: &str) -> V {
    V::String(x.as_bytes().to_vec())
}
fn prep_jid(value: &str) -> Result<String> {
    let bare = crate::account_modules::normalize_bare_jid(protocol::bare(value))?;
    if let Some((_, resource)) = value.split_once('/') {
        let resource = stringprep::resourceprep(resource).map_err(|e| anyhow!(e.to_string()))?;
        anyhow::ensure!(
            !resource.is_empty() && resource.len() <= 1023,
            "invalid resource"
        );
        Ok(format!("{bare}/{resource}"))
    } else {
        Ok(bare)
    }
}
fn policy(v: Option<&V>) -> &str {
    match v {
        Some(V::Bool(false)) => "never",
        Some(V::String(_)) => "roster",
        _ => "always",
    }
}
fn prefs_xml(p: &V) -> String {
    let mut yes = String::new();
    let mut no = String::new();
    if let V::Table(t) = p {
        for (k, v) in t {
            if let V::String(k) = k {
                let j = format!("<jid>{}</jid>", escape(&String::from_utf8_lossy(k)));
                if v == &V::Bool(true) {
                    yes.push_str(&j)
                } else if v == &V::Bool(false) {
                    no.push_str(&j)
                }
            }
        }
    }
    format!(
        "<prefs xmlns='{NS}' default='{}'><always>{yes}</always><never>{no}</never></prefs>",
        policy(p.get_key(&V::Bool(false)))
    )
}
/// Apply stored personal policy. default_policy is always/never/roster from config.
pub fn should_archive(
    root: &Path,
    domain: &str,
    user: &str,
    peer: &str,
    default_policy: &str,
) -> Result<bool> {
    should_archive_with_options(root, domain, user, peer, default_policy, false)
}
pub fn should_archive_with_options(
    root: &Path,
    domain: &str,
    user: &str,
    peer: &str,
    default_policy: &str,
    smart_enable: bool,
) -> Result<bool> {
    let stored = storage::load(root, domain, Some(user), "archive_prefs")?;
    if smart_enable && stored.is_none() {
        return Ok(false);
    }
    let p = stored.unwrap_or_default();
    if let Some(V::Bool(b)) = p.get(peer) {
        return Ok(*b);
    }
    let pol = if p.get_key(&V::Bool(false)).is_some() {
        policy(p.get_key(&V::Bool(false)))
    } else {
        default_policy
    };
    Ok(match pol {
        "never" => false,
        "roster" => storage::load(root, domain, Some(user), "roster")?
            .and_then(|r| r.get(peer).cloned())
            .is_some(),
        _ => true,
    })
}
pub fn handle(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: roxmltree::Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    handle_with_policy(root, domain, jid, iq, "always")
}
pub fn handle_with_policy(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: roxmltree::Node<'_, '_>,
    default_policy: &str,
) -> Result<Option<ModuleResult>> {
    handle_with_options(root, domain, jid, iq, default_policy, false)
}
pub fn handle_with_options(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: roxmltree::Node<'_, '_>,
    default_policy: &str,
    smart_enable: bool,
) -> Result<Option<ModuleResult>> {
    let Some(q) = iq
        .children()
        .find(|n| n.is_element() && n.tag_name().namespace() == Some(NS))
    else {
        return Ok(None);
    };
    let own = protocol::bare(jid);
    if let Some(to) = iq.attribute("to")
        && to != own
        && to != domain
    {
        return Ok(Some(ModuleResult::reply(protocol::iq_error(
            iq,
            "forbidden",
        ))));
    }
    let Some((user, host)) = own.split_once('@') else {
        return Ok(Some(ModuleResult::reply(protocol::iq_error(
            iq,
            "forbidden",
        ))));
    };
    if host != domain {
        return Ok(Some(ModuleResult::reply(protocol::iq_error(
            iq,
            "forbidden",
        ))));
    }
    if smart_enable
        && matches!(q.tag_name().name(), "query" | "prefs")
        && matches!(iq.attribute("type"), Some("get" | "set"))
        && storage::load(root, domain, Some(user), "archive_prefs")?.is_none()
    {
        storage::update(root, domain, Some(user), "archive_prefs", |p| {
            if p.entries().is_empty() {
                p.set_key(
                    V::Bool(false),
                    match default_policy {
                        "never" => V::Bool(false),
                        "roster" => s("roster"),
                        _ => V::Bool(true),
                    },
                );
            }
            Ok(())
        })?;
    }
    match process(root, domain, user, own, iq, q, default_policy) {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            let condition = if e.to_string() == "item-not-found" {
                "item-not-found"
            } else if e.to_string().starts_with("MAM archive read failed")
                || e.to_string().starts_with("MAM preferences storage failed")
            {
                "internal-server-error"
            } else {
                "bad-request"
            };
            let xml = protocol::iq_error(iq, condition);
            let xml = if condition == "internal-server-error" {
                xml
            } else {
                xml.replace("<error type='cancel'>", "<error type='modify'>")
            };
            Ok(Some(ModuleResult::reply(xml)))
        }
    }
}
fn process(
    root: &Path,
    domain: &str,
    user: &str,
    own: &str,
    iq: roxmltree::Node<'_, '_>,
    q: roxmltree::Node<'_, '_>,
    default_policy: &str,
) -> Result<ModuleResult> {
    let typ = iq.attribute("type").unwrap_or("");
    if q.tag_name().name() == "prefs" {
        let p = if typ == "set" {
            let mut p = V::default();
            let d = match q.attribute("default") {
                Some("always") => V::Bool(true),
                Some("never") => V::Bool(false),
                Some("roster") => s("roster"),
                _ => bail!("invalid policy"),
            };
            p.set_key(V::Bool(false), d);
            for group in q.children().filter(|n| n.is_element()) {
                let value = match group.tag_name().name() {
                    "always" => true,
                    "never" => false,
                    _ => bail!("invalid prefs"),
                };
                for j in group.children().filter(|n| n.is_element()) {
                    if j.tag_name().name() != "jid" {
                        bail!("invalid jid field")
                    };
                    let jid = j.text().ok_or_else(|| anyhow!("missing jid"))?;
                    if jid.is_empty() || jid.contains(char::is_whitespace) {
                        bail!("invalid jid")
                    };
                    p.set(&prep_jid(jid)?, V::Bool(value));
                }
            }
            storage::save(root, domain, Some(user), "archive_prefs", &p)
                .context("MAM preferences storage failed")?;
            p
        } else if typ == "get" {
            {
                let mut p = storage::load(root, domain, Some(user), "archive_prefs")
                    .context("MAM preferences storage failed")?
                    .unwrap_or_default();
                if p.get_key(&V::Bool(false)).is_none() {
                    p.set_key(
                        V::Bool(false),
                        match default_policy {
                            "never" => V::Bool(false),
                            "roster" => s("roster"),
                            _ => V::Bool(true),
                        },
                    );
                }
                p
            }
        } else {
            bail!("invalid IQ")
        };
        return Ok(ModuleResult::reply(protocol::iq_result(iq, &prefs_xml(&p))));
    }
    handle_archive_query(root, domain, Some(user), "archive", own, iq, q)
}
/// Caller MUST authorize access before invoking (e.g. MUC membership).
pub fn handle_archive_query(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    archive_jid: &str,
    iq: roxmltree::Node<'_, '_>,
    q: roxmltree::Node<'_, '_>,
) -> Result<ModuleResult> {
    handle_archive_query_with_options(root, host, user, store, archive_jid, (iq, q), true)
}
/// Room archives can suppress optional totals without altering personal MAM defaults.
pub fn handle_archive_query_with_options(
    root: &Path,
    host: &str,
    user: Option<&str>,
    store: &str,
    archive_jid: &str,
    request: (roxmltree::Node<'_, '_>, roxmltree::Node<'_, '_>),
    include_total: bool,
) -> Result<ModuleResult> {
    let (iq, q) = request;
    let typ = iq.attribute("type").unwrap_or("");
    if q.tag_name().name() == "metadata" && typ == "get" {
        let mut first = None;
        let mut last = None;
        archive::scan_store(root, host, user, store, |e| {
            if first.is_none() {
                first = Some((e.id.clone(), e.when));
            }
            last = Some((e.id, e.when));
            Ok(())
        })
        .context("MAM archive read failed")?;
        let mut payload = format!("<metadata xmlns='{NS}'>");
        if let Some((id, when)) = first {
            payload.push_str(&format!(
                "<start id='{}' timestamp='{}'/>",
                escape(&id),
                archive::timestamp(when)?
            ));
        }
        if let Some((id, when)) = last {
            payload.push_str(&format!(
                "<end id='{}' timestamp='{}'/>",
                escape(&id),
                archive::timestamp(when)?
            ));
        }
        payload.push_str("</metadata>");
        return Ok(ModuleResult::reply(protocol::iq_result(iq, &payload)));
    }
    if q.tag_name().name() != "query" {
        return Ok(ModuleResult::reply(protocol::iq_error(
            iq,
            "feature-not-implemented",
        )));
    }
    if typ == "get" {
        return Ok(ModuleResult::reply(protocol::iq_result(
            iq,
            &format!(
                "<query xmlns='{NS}'><x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE' type='hidden'><value>{NS}</value></field><field var='with' type='jid-single'/><field var='start' type='text-single'/><field var='end' type='text-single'/><field var='before-id' type='text-single'/><field var='after-id' type='text-single'/><field var='ids' type='list-multi'/></x></query>"
            ),
        )));
    }
    if typ != "set" {
        bail!("invalid query")
    }
    // mod_muc_mam indexes stanza kind in the archive's `with` column.
    let mut peer = (store == "muc_log").then(|| "message<groupchat".to_owned());
    let mut start = None;
    let mut end = None;
    let mut after = None;
    let mut before = None;
    let mut ids = None;
    if let Some(form) = q
        .children()
        .find(|n| n.has_tag_name(("jabber:x:data", "x")))
    {
        if form.attribute("type") != Some("submit") {
            bail!("invalid form")
        };
        let mut form_type = false;
        let mut seen = std::collections::HashSet::new();
        for f in form
            .children()
            .filter(|n| n.has_tag_name(("jabber:x:data", "field")))
        {
            let var = f.attribute("var").unwrap_or("");
            anyhow::ensure!(seen.insert(var), "duplicate query form field");
            anyhow::ensure!(
                var == "ids"
                    || f.children()
                        .filter(|n| n.has_tag_name(("jabber:x:data", "value")))
                        .count()
                        <= 1,
                "multiple values in single-valued query field"
            );
            let value = f
                .children()
                .find(|n| n.has_tag_name(("jabber:x:data", "value")))
                .and_then(|n| n.text())
                .unwrap_or("");
            match f.attribute("var").unwrap_or("") {
                "FORM_TYPE" => {
                    if value != NS {
                        bail!("wrong form type")
                    };
                    form_type = true
                }
                "with" => {
                    if store != "muc_log" && !value.is_empty() {
                        peer = Some(protocol::bare(&prep_jid(value)?).to_owned())
                    }
                }
                "start" => {
                    if !value.is_empty() {
                        start = Some(archive::parse_time(value)?)
                    }
                }
                "end" => {
                    if !value.is_empty() {
                        end = Some(archive::parse_time(value)?)
                    }
                }
                "before-id" => {
                    if !value.is_empty() {
                        before = Some(value.to_owned());
                    }
                }
                "after-id" => {
                    if !value.is_empty() {
                        after = Some(value.to_owned());
                    }
                }
                "ids" => {
                    ids = Some(
                        f.children()
                            .filter(|n| n.has_tag_name(("jabber:x:data", "value")))
                            .map(|n| n.text().unwrap_or("").to_owned())
                            .collect::<std::collections::HashSet<_>>(),
                    );
                }
                _ => bail!("unsupported field"),
            }
        }
        if !form_type {
            bail!("missing form type")
        }
    }
    if start.zip(end).is_some_and(|(s, e)| s > e) {
        bail!("invalid interval")
    }
    // Native internal storage omits optional totals; avoid a misleading base-set
    // count/index when form ID boundaries further restrict the query.
    let omit_totals = !include_total || before.is_some() || after.is_some();
    let mut max = 20usize;
    let mut reverse = false;
    if let Some(set) = q
        .children()
        .find(|n| n.has_tag_name(("http://jabber.org/protocol/rsm", "set")))
    {
        for f in set.children().filter(|n| n.is_element()) {
            match f.tag_name().name() {
                "max" => max = f.text().unwrap_or("").parse::<usize>()?.min(50),
                "after" => after = Some(f.text().unwrap_or("").to_owned()),
                "before" => {
                    reverse = true;
                    before = Some(f.text().unwrap_or("").to_owned());
                }
                _ => bail!("unsupported RSM field"),
            }
        }
    }
    let mut page = std::collections::VecDeque::new();
    let mut total = 0usize;
    let mut eligible = 0usize;
    let mut after_found = after.is_none();
    let mut before_found = before.as_ref().is_none_or(|id| id.is_empty());
    let mut before_reached = false;
    archive::scan_store(root, host, user, store, |e| {
        if peer.as_ref().is_some_and(|p| p != &e.peer)
            || start.is_some_and(|s| e.when < s)
            || end.is_some_and(|t| e.when > t)
            || ids.as_ref().is_some_and(|ids| !ids.contains(&e.id))
        {
            return Ok(());
        }
        let index = total;
        total += 1;
        let is_after = after.as_ref() == Some(&e.id);
        let passed_after = after_found;
        if is_after {
            after_found = true;
        }
        if before
            .as_ref()
            .is_some_and(|id| !id.is_empty() && id == &e.id)
        {
            before_found = true;
            before_reached = true;
            return Ok(());
        }
        if !passed_after || is_after {
            return Ok(());
        }
        if before_reached {
            return Ok(());
        }
        eligible += 1;
        if reverse {
            if max > 0 {
                page.push_back((index, e));
                if page.len() > max {
                    page.pop_front();
                }
            }
        } else if page.len() < max {
            page.push_back((index, e));
        }
        Ok(())
    })
    .context("MAM archive read failed")?;
    if !after_found || !before_found {
        bail!("item-not-found")
    }
    let a = page.front().map(|(i, _)| *i).unwrap_or(0);
    let complete = eligible <= max;
    let queryid = q
        .attribute("queryid")
        .map(|v| format!(" queryid='{}'", escape(v)))
        .unwrap_or_default();
    let mut result = ModuleResult::default();
    let flip = q.children().any(|n| n.has_tag_name((NS, "flip-page")));
    let ordered: Box<dyn Iterator<Item = &(usize, archive::Entry)>> = if flip {
        Box::new(page.iter().rev())
    } else {
        Box::new(page.iter())
    };
    for (_, e) in ordered {
        let doc = roxmltree::Document::parse(&e.xml)?;
        let forwarded = match doc.root_element().tag_name().namespace() {
            Some("jabber:client") => e.xml.clone(),
            None => {
                anyhow::ensure!(
                    doc.root_element().tag_name().name() == "message",
                    "MAM archive contains a non-message stanza"
                );
                e.xml
                    .replacen("<message", "<message xmlns='jabber:client'", 1)
            }
            _ => {
                let mut stored = storage::stanza_value(doc.root_element());
                let mut attrs = stored.get("attr").cloned().unwrap_or_default();
                attrs.set("xmlns", "jabber:client".into());
                stored.set("attr", attrs);
                storage::stanza_xml(&stored)?
            }
        };
        result.replies.push(format!("<message xmlns='jabber:client' from='{}'><result xmlns='{NS}' id='{}'{queryid}><forwarded xmlns='urn:xmpp:forward:0'><delay xmlns='urn:xmpp:delay' stamp='{}'/>{}</forwarded></result></message>",escape(archive_jid),escape(&e.id),archive::timestamp(e.when)?,forwarded));
    }
    let bounds = page
        .front()
        .zip(page.back())
        .map(|((_, f), (_, l))| {
            let index = if omit_totals {
                String::new()
            } else {
                format!(" index='{a}'")
            };
            format!(
                "<first{index}>{}</first><last>{}</last>",
                escape(&f.id),
                escape(&l.id)
            )
        })
        .unwrap_or_default();
    let count = if omit_totals {
        String::new()
    } else {
        format!("<count>{total}</count>")
    };
    result.replies.push(protocol::iq_result(iq,&format!("<fin xmlns='{NS}' complete='{complete}' stable='true'><set xmlns='http://jabber.org/protocol/rsm'>{bounds}{count}</set></fin>")));
    Ok(result)
}

/// Exact default message selection from Prosody 13 mod_mam, before user preferences.
pub fn should_store(stanza: roxmltree::Node<'_, '_>) -> bool {
    if !stanza.has_tag_name(("jabber:client", "message")) && stanza.tag_name().name() != "message" {
        return false;
    }
    match stanza.attribute("type").unwrap_or("normal") {
        "headline" | "groupchat" => return false,
        "error" => return stanza.attribute("to").is_some_and(|j| j.contains('/')),
        _ => (),
    }
    let has = |ns: &str, name: &str| stanza.children().any(|n| n.has_tag_name((ns, name)));
    if has("urn:xmpp:hints", "no-store") || has("urn:xmpp:hints", "no-permanent-store") {
        return false;
    }
    if has("urn:xmpp:hints", "store") {
        return true;
    }
    stanza.children().filter(|n| n.is_element()).any(|n| {
        let ns = n.tag_name().namespace().unwrap_or("");
        let name = n.tag_name().name();
        ((name == "body" || name == "subject") && (ns == "jabber:client" || ns.is_empty()))
            || (ns == "urn:xmpp:eme:0" && name == "encryption")
            || matches!(
                ns,
                "urn:xmpp:receipts"
                    | "urn:xmpp:chat-markers:0"
                    | "urn:xmpp:jingle-message:0"
                    | "urn:xmpp:jingle-message:1"
            )
            || (ns == "jabber:x:conference" && name == "x")
            || (ns == "http://jabber.org/protocol/muc#user"
                && name == "x"
                && n.children().any(|c| c.has_tag_name((ns, "invite"))))
    })
}

fn retain_stanza_children(value: &mut V, mut keep: impl FnMut(&V) -> bool) {
    let mut children = vec![];
    let mut i = 1;
    while let Some(child) = value.get_key(&V::Integer(i)) {
        if keep(child) {
            children.push(child.clone());
        }
        i += 1;
    }
    if let V::Table(fields) = value {
        fields.retain(|(k, _)| !matches!(k, V::Integer(_)));
    }
    for (i, child) in children.into_iter().enumerate() {
        value.set_key(V::Integer(i as i64 + 1), child);
    }
}
fn sid_belongs_to(by: &str, domain: &str, owner: &str) -> bool {
    if by.contains('/') {
        return false;
    }
    let Some((user, host)) = by.split_once('@') else {
        return false;
    };
    let Ok(user) = stringprep::nodeprep(user) else {
        return false;
    };
    let Ok(host) = stringprep::nameprep(host) else {
        return false;
    };
    let Ok(expected_host) = stringprep::nameprep(domain) else {
        return false;
    };
    user == owner && host == expected_host
}
fn strip_owner_sid_value(value: &mut V, domain: &str, owner: &str) {
    retain_stanza_children(value, |child| {
        let attr = child.get("attr");
        !(child.get("name").and_then(V::as_str) == Some("stanza-id")
            && attr.and_then(|a| a.get("xmlns")).and_then(V::as_str) == Some("urn:xmpp:sid:0")
            && attr
                .and_then(|a| a.get("by"))
                .and_then(V::as_str)
                .is_some_and(|by| sid_belongs_to(by, domain, owner)))
    });
}
/// Remove SIDs claiming this user's archive before routing out of their account.
/// This also removes forged SIDs submitted by clients. Other issuers are preserved.
pub fn strip_owner_stanza_ids(xml: &str, domain: &str, owner: &str) -> Result<String> {
    let doc = roxmltree::Document::parse(xml)?;
    let mut value = storage::stanza_value(doc.root_element());
    strip_owner_sid_value(&mut value, domain, owner);
    storage::stanza_xml(&value)
}
/// Store the sanitized message and return a delivery copy bearing its real archive ID.
/// The newly generated SID is not embedded in the archived stanza itself.
/// Default Prosody chat-state namespace stripping applies only to persisted content.
pub fn archive_for_user(
    root: &Path,
    domain: &str,
    owner: &str,
    peer: &str,
    xml: &str,
    time: f64,
) -> Result<(String, String)> {
    archive_for_user_with_namespaces(
        root,
        domain,
        owner,
        peer,
        xml,
        time,
        &["http://jabber.org/protocol/chatstates"],
    )
}
pub fn archive_for_user_with_namespaces(
    root: &Path,
    domain: &str,
    owner: &str,
    peer: &str,
    xml: &str,
    time: f64,
    strip_namespaces: &[&str],
) -> Result<(String, String)> {
    let doc = roxmltree::Document::parse(xml)?;
    anyhow::ensure!(
        doc.root_element().tag_name().name() == "message",
        "only message stanzas can be archived for a user"
    );
    let mut delivery = storage::stanza_value(doc.root_element());
    strip_owner_sid_value(&mut delivery, domain, owner);
    let mut persisted = delivery.clone();
    retain_stanza_children(&mut persisted, |child| {
        !child
            .get("attr")
            .and_then(|a| a.get("xmlns"))
            .and_then(V::as_str)
            .is_some_and(|ns| strip_namespaces.contains(&ns))
    });
    let stored_xml = storage::stanza_xml(&persisted)?;
    let id =
        archive::archive_message(root, domain, owner, protocol::bare(peer), &stored_xml, time)?;
    let mut sid = V::default();
    sid.set("name", "stanza-id".into());
    let mut attr = V::default();
    attr.set("xmlns", "urn:xmpp:sid:0".into());
    attr.set("by", format!("{owner}@{domain}").into());
    attr.set("id", id.clone().into());
    sid.set("attr", attr);
    let mut index = 1;
    while delivery.get_key(&V::Integer(index)).is_some() {
        index += 1;
    }
    delivery.set_key(V::Integer(index), sid);
    Ok((id, storage::stanza_xml(&delivery)?))
}
