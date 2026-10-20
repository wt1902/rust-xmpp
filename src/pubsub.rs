//! Persistent PEP and PubSub subset. Access checks precede item reads and writes.
use crate::{
    protocol::{ModuleResult, bare, iq_error, iq_result},
    storage::{self, LuaValue as V},
    wire::escape,
};
use anyhow::Result;
use std::{path::Path, sync::Mutex};
const NS: &str = "http://jabber.org/protocol/pubsub";
const OWNER: &str = "http://jabber.org/protocol/pubsub#owner";
static LOCK: Mutex<()> = Mutex::new(());
fn text<'a>(v: &'a V, k: &str, default: &'a str) -> &'a str {
    v.get(k).and_then(V::as_str).unwrap_or(default)
}
fn tab(v: &V, k: &str) -> V {
    v.get(k).cloned().unwrap_or_default()
}
fn defaults(name: &str, owner: &str, pep: bool) -> V {
    let mut v = V::table();
    v.set("name", name.into());
    let mut c = V::table();
    c.set("access_model", if pep { "presence" } else { "open" }.into());
    c.set("max_items", V::Integer(if pep { 1 } else { 20 }));
    c.set("publish_model", "publishers".into());
    c.set("notification_type", "headline".into());
    c.set("itemreply", "none".into());
    c.set(
        "send_last_published_item",
        if pep { "on_sub_and_presence" } else { "never" }.into(),
    );
    c.set("persist_items", V::Bool(true));
    // These options default to true in delivery as well. Materialize them so
    // publish preconditions compare against effective defaults, including nodes
    // loaded from older stores which did not persist these fields.
    for key in [
        "notify_items",
        "include_payload",
        "notify_delete",
        "notify_retract",
    ] {
        c.set(key, V::Bool(true));
    }
    v.set("config", c);
    v.set("subscribers", V::table());
    let mut a = V::table();
    a.set(owner, "owner".into());
    v.set("affiliations", a);
    v
}
fn publish_denied(
    root: &Path,
    host: &str,
    user: Option<&str>,
    owner: &str,
    actor: &str,
    node: &V,
) -> Result<bool> {
    let actor_bare = bare(actor);
    if let Some(user) = user {
        if crate::account_modules::is_blocked(root, host, user, actor)? {
            return Ok(true);
        }
        if let Some((peer, peer_host)) = actor_bare.split_once('@')
            && peer_host == host
            && crate::account_modules::is_blocked(root, host, peer, owner)?
        {
            return Ok(true);
        }
    }
    let aff = tab(node, "affiliations");
    let a = text(&aff, actor_bare, "");
    if a == "outcast" {
        return Ok(true);
    }
    Ok(false)
}
fn allowed(
    root: &Path,
    host: &str,
    user: Option<&str>,
    owner: &str,
    actor: &str,
    node: &V,
) -> Result<bool> {
    let actor_bare = bare(actor);
    if actor_bare == owner {
        return Ok(true);
    }
    if publish_denied(root, host, user, owner, actor, node)? {
        return Ok(false);
    }
    let aff = tab(node, "affiliations");
    let a = text(&aff, actor_bare, "");
    if matches!(a, "owner" | "publisher" | "member") {
        return Ok(true);
    }
    let c = tab(node, "config");
    Ok(
        match text(
            &c,
            "access_model",
            if user.is_some() { "presence" } else { "open" },
        ) {
            "open" => true,
            "presence" => {
                if let Some(u) = user {
                    let r = storage::load(root, host, Some(u), "roster")?.unwrap_or_default();
                    matches!(
                        text(&tab(&r, actor_bare), "subscription", ""),
                        "both" | "from"
                    )
                } else {
                    false
                }
            }
            "roster" => {
                if let Some(u) = user {
                    let r = storage::load(root, host, Some(u), "roster")?.unwrap_or_default();
                    let g = tab(&tab(&r, actor_bare), "groups");
                    tab(&c, "roster_groups_allowed")
                        .entries()
                        .iter()
                        .any(|(_, v)| v.as_str().is_some_and(|s| g.get(s) == Some(&V::Bool(true))))
                } else {
                    false
                }
            }
            _ => false,
        },
    )
}
fn form(action: roxmltree::Node<'_, '_>, maximum: usize) -> std::result::Result<V, &'static str> {
    let Some(x) = action
        .children()
        .find(|n| n.has_tag_name(("jabber:x:data", "x")))
    else {
        return Err("bad-request");
    };
    if x.attribute("type") != Some("submit") {
        return Err("bad-request");
    }
    let mut out = V::table();
    for f in x
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "field")
    {
        let Some(k) = f.attribute("var") else {
            return Err("bad-request");
        };
        let vals: Vec<_> = f
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "value")
            .map(|n| n.text().unwrap_or(""))
            .collect();
        if k == "FORM_TYPE" {
            if !matches!(
                vals.first().copied(),
                Some(
                    "http://jabber.org/protocol/pubsub#node_config"
                        | "http://jabber.org/protocol/pubsub#publish-options"
                )
            ) {
                return Err("bad-request");
            }
            continue;
        }
        let Some(k) = k.strip_prefix("pubsub#") else {
            return Err("feature-not-implemented");
        };
        // XEP-0060 wire field names map to Prosody's internal config keys.
        let k = match k {
            "deliver_notifications" => "notify_items",
            "deliver_payloads" => "include_payload",
            "type" => "payload_type",
            _ => k,
        };
        let value = vals.first().copied().unwrap_or("");
        let v = match k {
            "access_model" if matches!(value, "open" | "presence" | "roster" | "whitelist") => {
                value.into()
            }
            "max_items" => V::Integer(if value == "max" {
                maximum as i64
            } else {
                value
                    .parse::<i64>()
                    .ok()
                    .filter(|n| (1..=maximum as i64).contains(n))
                    .ok_or("not-acceptable")?
            }),

            "persist_items" | "notify_items" | "notify_retract" | "notify_delete"
            | "include_payload" => V::Bool(match value {
                "1" | "true" => true,
                "0" | "false" => false,
                _ => return Err("bad-request"),
            }),
            "title" | "description" | "payload_type" => value.into(),
            "publish_model" if matches!(value, "publishers" | "open" | "subscribers") => {
                value.into()
            }
            "notification_type" if matches!(value, "normal" | "headline") => value.into(),
            "itemreply" if matches!(value, "none" | "owner" | "publisher") => value.into(),
            "publish_model" | "notification_type" | "itemreply" => return Err("not-acceptable"),
            "send_last_published_item"
                if matches!(value, "never" | "on_sub" | "on_sub_and_presence") =>
            {
                value.into()
            }
            "roster_groups_allowed" => V::Table(
                vals.iter()
                    .enumerate()
                    .map(|(i, s)| (V::Integer(i as i64 + 1), (*s).into()))
                    .collect(),
            ),
            _ => return Err("feature-not-implemented"),
        };
        out.set(k, v)
    }
    Ok(out)
}
fn merge(a: &mut V, b: &V) {
    for (k, v) in b.entries() {
        a.set_key(k.clone(), v.clone())
    }
}
fn form_xml(c: &V) -> String {
    let mut s="<x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#node_config</value></field>".to_string();
    for (k, v) in c.entries() {
        let Some(k) = k.as_str() else { continue };
        let field = match k {
            "notify_items" => "deliver_notifications",
            "include_payload" => "deliver_payloads",
            "payload_type" => "type",
            _ => k,
        };
        s.push_str(&format!("<field var='pubsub#{}'>", escape(field)));
        match v {
            V::Table(t) => {
                for (_, v) in t {
                    if let Some(v) = v.as_str() {
                        s.push_str(&format!("<value>{}</value>", escape(v)))
                    }
                }
            }
            _ => {
                let value = match v {
                    V::Bool(b) => {
                        if *b {
                            "1".into()
                        } else {
                            "0".into()
                        }
                    }
                    V::Integer(n) => n.to_string(),
                    _ => v.as_str().unwrap_or("").into(),
                };
                s.push_str(&format!("<value>{}</value>", escape(&value)))
            }
        }
        s.push_str("</field>")
    }
    s.push_str("</x>");
    s
}
#[derive(Clone, Debug)]
pub struct Options {
    pub max_items: usize,
    pub restrict_node_creation: bool,
    pub autocreate_on_publish: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            max_items: 256,
            restrict_node_creation: true,
            autocreate_on_publish: false,
        }
    }
}
pub fn handle(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: roxmltree::Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    handle_with_options(
        root,
        domain,
        jid,
        iq,
        &Options {
            autocreate_on_publish: true,
            restrict_node_creation: false,
            ..Options::default()
        },
    )
}
pub fn handle_with_options(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: roxmltree::Node<'_, '_>,
    options: &Options,
) -> Result<Option<ModuleResult>> {
    // Server and resource disco describe those entities, not the virtual PEP service.
    if iq.children().any(|n| {
        n.has_tag_name(("http://jabber.org/protocol/disco#info", "query"))
            || n.has_tag_name(("http://jabber.org/protocol/disco#items", "query"))
    }) && iq.attribute("to").is_none_or(|to| to.contains('/'))
    {
        return Ok(None);
    }
    let target = bare(iq.attribute("to").unwrap_or(bare(jid)));
    let Some((u, h)) = target.split_once('@') else {
        return Ok(None);
    };
    if h != domain {
        return Ok(None);
    }
    handle_inner(root, domain, Some(u), target, jid, false, iq, options)
}
pub fn handle_component(
    root: &Path,
    component: &str,
    jid: &str,
    admins: &[String],
    iq: roxmltree::Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    handle_component_with_options(root, component, jid, admins, iq, &Options::default())
}
pub fn handle_component_with_options(
    root: &Path,
    component: &str,
    jid: &str,
    admins: &[String],
    iq: roxmltree::Node<'_, '_>,
    options: &Options,
) -> Result<Option<ModuleResult>> {
    handle_inner(
        root,
        component,
        None,
        component,
        jid,
        admins.iter().any(|a| a == bare(jid)),
        iq,
        options,
    )
}
// Explicit storage coordinates match both PEP and component backends.
#[allow(clippy::too_many_arguments)]
fn handle_inner(
    root: &Path,
    host: &str,
    user: Option<&str>,
    owner: &str,
    jid: &str,
    admin: bool,
    iq: roxmltree::Node<'_, '_>,
    options: &Options,
) -> Result<Option<ModuleResult>> {
    let Some(p) = iq.children().find(|n| {
        n.is_element()
            && ((n.tag_name().name() == "pubsub"
                && matches!(n.tag_name().namespace(), Some(NS | OWNER)))
                || n.has_tag_name(("http://jabber.org/protocol/disco#items", "query"))
                || n.has_tag_name(("http://jabber.org/protocol/disco#info", "query")))
    }) else {
        return Ok(None);
    };
    let _lock = LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("pubsub lock poisoned"))?;
    let actor = bare(jid);
    let own = actor == owner || admin;
    let fail = |s| Ok(Some(ModuleResult::reply(iq_error(iq, s))));
    if let Some(u) = user
        && storage::load(root, host, Some(u), "accounts")?.is_none()
    {
        return fail("item-not-found");
    }
    let pep = user.is_some();
    let mut nodes = if pep {
        storage::load(root, host, user, "pep")?.unwrap_or_default()
    } else {
        V::table()
    };
    // Component metadata is one keyval file per node; enumerate only its dedicated store.
    if !pep {
        let dir = storage::path(root, host, Some("dummy"), "pubsub_nodes")
            .parent()
            .unwrap()
            .to_owned();
        if dir.exists() {
            for e in std::fs::read_dir(dir)? {
                let e = e?;
                if e.path().extension().and_then(|s| s.to_str()) != Some("dat") {
                    continue;
                }
                let v = storage::parse(&std::fs::read(e.path())?)?;
                if let Some(name) = v.get("name").and_then(V::as_str) {
                    nodes.set(name, v.clone())
                }
            }
        }
    }
    if p.has_tag_name(("http://jabber.org/protocol/disco#info", "query")) {
        if iq.attribute("type") != Some("get") {
            return fail("bad-request");
        }
        let node_attr = p
            .attribute("node")
            .map(|n| format!(" node='{}'", escape(n)))
            .unwrap_or_default();
        let mut body = format!(
            "<query xmlns='http://jabber.org/protocol/disco#info'{node_attr}><identity category='pubsub' type='{}'/>",
            if p.attribute("node").is_some() {
                "leaf"
            } else if pep {
                "pep"
            } else {
                "service"
            }
        );
        if pep && p.attribute("node").is_none() {
            body.push_str("<identity category='account' type='registered'/>");
        }
        if let Some(requested) = p.attribute("node") {
            let Some(n) = nodes.get(requested) else {
                return fail("item-not-found");
            };
            if !own && !allowed(root, host, user, owner, jid, n)? {
                return fail("forbidden");
            }
            body.push_str(
                &form_xml(&tab(n, "config"))
                    .replace("type='form'", "type='result'")
                    .replace("pubsub#node_config", "pubsub#meta-data"),
            );
        }
        body.push_str("<feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/>");
        body.push_str(&if pep { pep_features() } else { features() });
        body.push_str("</query>");
        return Ok(Some(ModuleResult::reply(iq_result(iq, &body))));
    }
    if p.tag_name().name() == "query" {
        if iq.attribute("type") != Some("get") {
            return fail("bad-request");
        }
        if let Some(requested) = p.attribute("node") {
            let Some(n) = nodes.get(requested) else {
                return fail("item-not-found");
            };
            if !own && !allowed(root, host, user, owner, jid, n)? {
                return fail("forbidden");
            }
            let mut s = format!(
                "<query xmlns='http://jabber.org/protocol/disco#items' node='{}'>",
                escape(requested)
            );
            for entry in read_items(root, host, user, requested)? {
                s.push_str(&format!(
                    "<item jid='{}' name='{}'/>",
                    escape(owner),
                    escape(&entry.id)
                ));
            }
            s.push_str("</query>");
            return Ok(Some(ModuleResult::reply(iq_result(iq, &s))));
        }
        let mut s = "<query xmlns='http://jabber.org/protocol/disco#items'>".to_string();
        for (k, v) in nodes.entries() {
            if (own || allowed(root, host, user, owner, jid, v)?) && k.as_str().is_some() {
                s.push_str(&format!(
                    "<item jid='{}' node='{}'/>",
                    escape(owner),
                    escape(k.as_str().unwrap())
                ))
            }
        }
        s.push_str("</query>");
        return Ok(Some(ModuleResult::reply(iq_result(iq, &s))));
    }
    let Some(a) = p.children().find(|n| n.is_element()) else {
        return fail("bad-request");
    };
    if a.tag_name().namespace() != p.tag_name().namespace() {
        return fail("bad-request");
    }
    let action = a.tag_name().name();
    let typ = iq.attribute("type").unwrap_or("");
    let owner_ns = p.tag_name().namespace() == Some(OWNER);
    let node_name = a.attribute("node").map(str::to_owned).unwrap_or_else(|| {
        if action == "create" {
            uuid::Uuid::new_v4().to_string()
        } else {
            String::new()
        }
    });
    let mut node = nodes.get(&node_name).cloned();
    if node == Some(V::Bool(true)) {
        node = Some(defaults(&node_name, owner, pep))
    }
    if let Some(n) = node.as_mut() {
        let mut effective = tab(&defaults(&node_name, owner, pep), "config");
        merge(&mut effective, &tab(n, "config"));
        // Early Rust releases stored the wire alias as `type`. Canonicalize it
        // so a later native-form submission cannot produce duplicate fields.
        if let Some(legacy) = effective.get("type").cloned() {
            if effective.get("payload_type").is_none() {
                effective.set("payload_type", legacy);
            }
            effective.set("type", V::Nil);
        }
        n.set("config", effective);
    }
    let node_owner = own
        || node
            .as_ref()
            .is_some_and(|n| text(&tab(n, "affiliations"), actor, "") == "owner");
    if owner_ns && !node_owner && !(action == "default" && typ == "get") {
        return fail("forbidden");
    }
    let mut payload = String::new();
    let mut notify: Option<(String, String)> = None;
    let mut changed = false;
    if action == "affiliations" && typ == "get" && !owner_ns {
        let mut out = String::new();
        for (k, n) in nodes.entries() {
            let affiliation = if own {
                "owner"
            } else {
                n.get("affiliations")
                    .and_then(|a| a.get(actor))
                    .and_then(V::as_str)
                    .unwrap_or("none")
            };
            if affiliation != "none" {
                out.push_str(&format!(
                    "<affiliation node='{}' affiliation='{}'/>",
                    escape(k.as_str().unwrap_or("")),
                    escape(affiliation)
                ));
            }
        }
        payload = format!("<affiliations>{out}</affiliations>");
    } else if action == "default" && typ == "get" && owner_ns {
        payload = format!(
            "<default>{}</default>",
            form_xml(&tab(&defaults("", owner, pep), "config"))
        );
    } else if action == "subscriptions" && typ == "get" {
        let mut s = String::new();
        for (k, n) in nodes.entries() {
            if !node_name.is_empty() && k.as_str() != Some(&node_name) {
                continue;
            }
            if owner_ns && !own && text(&tab(n, "affiliations"), actor, "") != "owner" {
                return fail("forbidden");
            }
            for (j, _) in tab(n, "subscribers").entries() {
                if let Some(j) = j.as_str()
                    && (owner_ns || bare(j) == actor)
                {
                    s.push_str(&format!(
                        "<subscription node='{}' jid='{}' subscription='subscribed'/>",
                        escape(k.as_str().unwrap_or("")),
                        escape(j)
                    ))
                }
            }
        }
        payload = format!("<subscriptions>{s}</subscriptions>");
    } else {
        if node_name.is_empty() {
            return fail("bad-request");
        }
        match (typ, action, owner_ns) {
            ("set", "create", false) | ("set", "publish", false) => {
                let publisher = if let Some(n) = node.as_ref() {
                    let explicit = text(&tab(n, "affiliations"), actor, "") == "publisher";
                    let model = tab(n, "config");
                    let eligible = text(&model, "publish_model", "publishers") == "open"
                        || (text(&model, "publish_model", "publishers") == "subscribers"
                            && tab(n, "subscribers")
                                .entries()
                                .iter()
                                .any(|(j, _)| j.as_str().is_some_and(|j| bare(j) == actor)));
                    explicit || (eligible && !publish_denied(root, host, user, owner, jid, n)?)
                } else {
                    false
                };
                let may_create = own || (!pep && !options.restrict_node_creation);
                if (action == "create" && !may_create)
                    || (action == "publish"
                        && !(node_owner || publisher || (node.is_none() && may_create)))
                {
                    return fail("forbidden");
                }
                if action == "create" && node.is_some() {
                    return fail("conflict");
                }
                if node.is_none() && !pep && !options.autocreate_on_publish && action == "publish" {
                    return fail("item-not-found");
                }
                let was_new = node.is_none();
                let n = node.get_or_insert_with(|| defaults(&node_name, actor, pep));
                let mut c = tab(n, "config");
                if let Some(f) = p.children().find(|n| {
                    n.is_element()
                        && n.tag_name().name()
                            == if action == "create" {
                                "configure"
                            } else {
                                "publish-options"
                            }
                }) {
                    let opts = match form(f, options.max_items) {
                        Ok(v) => v,
                        Err(e) => return fail(e),
                    };
                    if !was_new
                        && opts.entries().iter().any(|(k, v)| {
                            // Prosody persists max_items as either a number or a form string.
                            if k.as_str() == Some("max_items") {
                                item_limit(&c, options.max_items)
                                    != item_limit(&opts, options.max_items)
                            } else {
                                c.get_key(k) != Some(v)
                            }
                        })
                    {
                        let reply = iq_error(iq, "conflict").replace(
                            "</error>",
                            "<precondition-not-met xmlns='http://jabber.org/protocol/pubsub#errors'/></error>",
                        );
                        return Ok(Some(ModuleResult::reply(reply)));
                    }
                    merge(&mut c, &opts)
                }
                n.set("config", c.clone());
                if action == "publish" {
                    let items: Vec<_> = a.children().filter(|n| n.is_element()).collect();
                    if items.len() != 1 || !items[0].has_tag_name((NS, "item")) {
                        return fail("bad-request");
                    }
                    let i = items[0];
                    let children: Vec<_> = i.children().filter(|n| n.is_element()).collect();
                    if children.len() != 1 {
                        return fail("bad-request");
                    }
                    let id = i
                        .attribute("id")
                        .map(str::to_owned)
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                    let xml = crate::protocol::xml(children[0]);
                    write_item(
                        root,
                        host,
                        user,
                        &node_name,
                        &id,
                        &xml,
                        actor,
                        item_limit(&c, options.max_items),
                        c.get("persist_items") != Some(&V::Bool(false)),
                    )?;
                    payload = format!(
                        "<publish node='{}'><item id='{}'/></publish>",
                        escape(&node_name),
                        escape(&id)
                    );
                    notify = Some(("items".into(), item_xml(&c, &id, &xml, actor)));
                } else {
                    payload = format!("<create node='{}'/>", escape(&node_name))
                }
                changed = true;
            }
            ("get", "items", false) => {
                let Some(n) = node.as_ref() else {
                    return fail("item-not-found");
                };
                if !own && !allowed(root, host, user, owner, jid, n)? {
                    return fail("forbidden");
                };
                let wanted: Vec<_> = a
                    .children()
                    .filter(|n| n.is_element())
                    .filter_map(|n| n.attribute("id"))
                    .collect();
                let max = match a.attribute("max_items") {
                    Some(s) => match s.parse::<usize>() {
                        Ok(n) => n,
                        Err(_) => return fail("bad-request"),
                    },
                    None => options.max_items,
                };
                let items = read_items(root, host, user, &node_name)?;
                let chosen: Vec<_> = items
                    .iter()
                    .rev()
                    .filter(|i| wanted.is_empty() || wanted.contains(&i.id.as_str()))
                    .take(max)
                    .collect();
                if !wanted.is_empty() && wanted.iter().any(|id| !chosen.iter().any(|i| i.id == *id))
                {
                    return fail("item-not-found");
                }
                // Native Prosody returns newest first; clients commonly read
                // only the first item (notably OMEMO device-list parsers).
                let s = chosen
                    .iter()
                    .map(|i| item_xml(&tab(n, "config"), &i.id, &i.xml, &i.peer))
                    .collect::<String>();
                payload = format!("<items node='{}'>{s}</items>", escape(&node_name));
            }
            ("get", "configure", true) => {
                let Some(n) = node.as_ref() else {
                    return fail("item-not-found");
                };
                payload = format!(
                    "<configure node='{}'>{}</configure>",
                    escape(&node_name),
                    form_xml(&tab(n, "config"))
                );
            }
            ("set", "configure", true) => {
                let Some(n) = node.as_mut() else {
                    return fail("item-not-found");
                };
                let opts = match form(a, options.max_items) {
                    Ok(v) => v,
                    Err(e) => return fail(e),
                };
                let mut c = tab(n, "config");
                merge(&mut c, &opts);
                let max = item_limit(&c, options.max_items);
                let mut entries = read_items(root, host, user, &node_name)?;
                if entries.len() > max {
                    entries.drain(..entries.len() - max);
                }
                save_items(
                    root,
                    host,
                    user,
                    &node_name,
                    &entries,
                    c.get("persist_items") != Some(&V::Bool(false)),
                )?;
                n.set("config", c);
                changed = true;
            }
            ("set", "subscribe", false) | ("set", "unsubscribe", false) => {
                let Some(n) = node.as_mut() else {
                    return fail("item-not-found");
                };
                let Some(sub) = a.attribute("jid") else {
                    return fail("bad-request");
                };
                if bare(sub) != actor {
                    return fail("forbidden");
                }
                if action == "subscribe"
                    && !own
                    && (!allowed(root, host, user, owner, jid, n)?
                        || !allowed(root, host, user, owner, sub, n)?)
                {
                    return fail("forbidden");
                };
                let mut subs = tab(n, "subscribers");
                let sub_options = if let Some(o) = p
                    .children()
                    .find(|n| n.is_element() && n.tag_name().name() == "options")
                {
                    match subscription_form(o) {
                        Ok(v) => v,
                        Err(e) => return fail(e),
                    }
                } else {
                    V::Bool(true)
                };
                subs.set(
                    sub,
                    if action == "subscribe" {
                        sub_options
                    } else {
                        V::Nil
                    },
                );
                n.set("subscribers", subs);
                changed = true;
                payload = format!(
                    "<subscription node='{}' jid='{}' subscription='{}'/>",
                    escape(&node_name),
                    escape(sub),
                    if action == "subscribe" {
                        "subscribed"
                    } else {
                        "none"
                    }
                );
            }
            ("get", "affiliations", true) => {
                let Some(n) = node.as_ref() else {
                    return fail("item-not-found");
                };
                let mut out = String::new();
                for (j, a) in tab(n, "affiliations").entries() {
                    if let (Some(j), Some(a)) = (j.as_str(), a.as_str()) {
                        out.push_str(&format!(
                            "<affiliation jid='{}' affiliation='{}'/>",
                            escape(j),
                            escape(a)
                        ))
                    }
                }
                payload = format!(
                    "<affiliations node='{}'>{out}</affiliations>",
                    escape(&node_name)
                );
            }
            ("set", "affiliations", true) => {
                let Some(n) = node.as_mut() else {
                    return fail("item-not-found");
                };
                let mut aff = tab(n, "affiliations");
                for a in a.children().filter(|n| n.is_element()) {
                    let (Some(j), Some(v)) = (a.attribute("jid"), a.attribute("affiliation"))
                    else {
                        return fail("bad-request");
                    };
                    if !j.contains('@')
                        || j.contains('/')
                        || !matches!(v, "owner" | "publisher" | "member" | "outcast" | "none")
                    {
                        return fail("bad-request");
                    }
                    if pep && j == owner && v != "owner" {
                        return fail("forbidden");
                    }
                    aff.set(j, if v == "none" { V::Nil } else { v.into() });
                }
                if !aff
                    .entries()
                    .iter()
                    .any(|(_, v)| v.as_str() == Some("owner"))
                {
                    return fail("not-acceptable");
                }
                n.set("affiliations", aff);
                changed = true;
            }
            ("set", "subscriptions", true) => {
                let Some(n) = node.as_mut() else {
                    return fail("item-not-found");
                };
                let mut subs = tab(n, "subscribers");
                for a in a.children().filter(|n| n.is_element()) {
                    let (Some(j), Some(v)) = (a.attribute("jid"), a.attribute("subscription"))
                    else {
                        return fail("bad-request");
                    };
                    if !j.contains('@') || !matches!(v, "subscribed" | "none") {
                        return fail("bad-request");
                    }
                    subs.set(j, if v == "none" { V::Nil } else { V::Bool(true) });
                }
                n.set("subscribers", subs);
                changed = true;
            }
            ("get", "options", false) | ("set", "options", false) => {
                let Some(n) = node.as_mut() else {
                    return fail("item-not-found");
                };
                let Some(sub) = a.attribute("jid") else {
                    return fail("bad-request");
                };
                if bare(sub) != actor {
                    return fail("forbidden");
                }
                let mut subs = tab(n, "subscribers");
                let Some(current) = subs.get(sub).cloned() else {
                    return fail("item-not-found");
                };
                if typ == "get" {
                    let deliver = current.get("pubsub#deliver") != Some(&V::Bool(false));
                    payload = format!(
                        "<options node='{}' jid='{}'><x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#subscribe_options</value></field><field var='pubsub#deliver' type='boolean'><value>{}</value></field></x></options>",
                        escape(&node_name),
                        escape(sub),
                        if deliver { "1" } else { "0" }
                    );
                } else {
                    let opts = match subscription_form(a) {
                        Ok(v) => v,
                        Err(e) => return fail(e),
                    };
                    subs.set(sub, opts);
                    n.set("subscribers", subs);
                    changed = true;
                }
            }
            ("set", "retract", false) => {
                if !node_owner {
                    return fail("forbidden");
                }
                if node.is_none() {
                    return fail("item-not-found");
                }
                let Some(id) = a
                    .children()
                    .find(|n| n.is_element())
                    .and_then(|n| n.attribute("id"))
                else {
                    return fail("bad-request");
                };
                delete_items(root, host, user, &node_name, Some(id))?;
                if matches!(a.attribute("notify"), Some("1" | "true")) {
                    notify = Some(("retract".into(), format!("<retract id='{}'/>", escape(id))))
                }
            }
            ("set", "purge", true) | ("set", "delete", true) => {
                if node.is_none() {
                    return fail("item-not-found");
                }
                delete_items(root, host, user, &node_name, None)?;
                notify = Some((action.into(), String::new()));
                if action == "delete" {
                    changed = true;
                }
            }
            _ => return fail("feature-not-implemented"),
        }
    }
    let wrapped = if payload.is_empty() {
        String::new()
    } else {
        format!(
            "<pubsub xmlns='{}'>{payload}</pubsub>",
            if owner_ns { OWNER } else { NS }
        )
    };
    let mut result = ModuleResult::reply(iq_result(iq, &wrapped));
    if let (Some((kind, item)), Some(n)) = (notify, node.as_ref()) {
        let c = tab(n, "config");
        if c.get(&format!("notify_{kind}")) != Some(&V::Bool(false)) {
            // Check notify_retract before mapping the event to its wire container.
            let kind = if kind == "retract" { "items" } else { &kind };
            let mut recipients = tab(n, "subscribers");
            if pep {
                for recipient in interested(root, owner, &node_name)? {
                    if recipients.get(&recipient).is_none() {
                        recipients.set(&recipient, V::Bool(true));
                    }
                }
            }
            for (j, opts) in recipients.entries() {
                if opts.get("pubsub#deliver") == Some(&V::Bool(false)) {
                    continue;
                }
                if let Some(j) = j.as_str()
                    && allowed(root, host, user, owner, j, n)?
                {
                    let item = notification_payload(&c, &item);
                    result.deliveries.push((j.into(),format!("<message xmlns='jabber:client' from='{}' to='{}' type='{}'><event xmlns='http://jabber.org/protocol/pubsub#event'><{} node='{}'>{}</{}></event></message>",escape(owner),escape(j),notification_type(&c, pep),kind,escape(&node_name),item,kind)))
                }
            }
        }
    }
    if pep
        && node_name == "urn:xmpp:bookmarks:1"
        && typ == "set"
        && matches!(action, "publish" | "retract" | "purge" | "delete")
        && let Some(meta) = node.as_ref()
    {
        let entries = read_items(root, host, user, &node_name)?;
        let items = entries
            .iter()
            .map(|e| (e.id.clone(), format!("<item>{}</item>", e.xml)))
            .collect::<Vec<_>>();
        let legacy = crate::account_modules::legacy_bookmark_storage(&items)?;
        for recipient in interested(root, owner, "storage:bookmarks")? {
            if allowed(root, host, user, owner, &recipient, meta)? {
                let item = notification_payload(
                    &tab(meta, "config"),
                    &format!("<item id='current'>{legacy}</item>"),
                );
                result.deliveries.push((recipient.clone(),format!("<message xmlns='jabber:client' from='{}' to='{}' type='headline'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='storage:bookmarks'>{item}</items></event></message>",escape(owner),escape(&recipient))));
            }
        }
    }
    if action == "subscribe"
        && typ == "set"
        && node
            .as_ref()
            .and_then(|n| n.get("subscribers"))
            .and_then(|s| s.get(a.attribute("jid").unwrap_or("")))
            .and_then(|o| o.get("pubsub#deliver"))
            != Some(&V::Bool(false))
        && let Some(n) = node.as_ref()
        && text(
            &tab(n, "config"),
            "send_last_published_item",
            "on_sub_and_presence",
        ) != "never"
        && let Some(last) = read_items(root, host, user, &node_name)?.last()
    {
        let to = a.attribute("jid").unwrap();
        let item = notification_payload(
            &tab(n, "config"),
            &item_xml(&tab(n, "config"), &last.id, &last.xml, &last.peer),
        );
        result.deliveries.push((to.into(),format!("<message xmlns='jabber:client' from='{}' to='{}' type='{}'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='{}'>{item}</items></event></message>",escape(owner),escape(to),notification_type(&tab(n, "config"), pep),escape(&node_name))));
    }
    if changed {
        if action == "delete" {
            EPHEMERAL
                .lock()
                .unwrap()
                .remove(&ephemeral_key(root, host, user, &node_name));
            node = None
        }
        if pep {
            nodes.set(&node_name, node.clone().unwrap_or(V::Nil));
            storage::save(root, host, user, "pep", &nodes)?
        } else if let Some(n) = node {
            storage::save(root, host, Some(&node_name), "pubsub_nodes", &n)?
        } else {
            let path = storage::path(root, host, Some(&node_name), "pubsub_nodes");
            if path.exists() {
                std::fs::remove_file(path)?
            }
        }
    }
    Ok(Some(result))
}
// Native mod_pep uses headline messages, while mod_pubsub honors this option.
fn notification_type(config: &V, pep: bool) -> &str {
    if !pep && text(config, "notification_type", "headline") == "normal" {
        "normal"
    } else {
        "headline"
    }
}
// Native handlers expose item publisher JIDs only for itemreply=publisher;
// owner and none both keep them private. Publishers are stored bare in Entry::peer.
fn item_xml(config: &V, id: &str, payload: &str, publisher: &str) -> String {
    let publisher = if text(config, "itemreply", "none") == "publisher" && !publisher.is_empty() {
        format!(" publisher='{}'", escape(bare(publisher)))
    } else {
        String::new()
    };
    format!("<item id='{}'{publisher}>{payload}</item>", escape(id))
}
// Apply the same notification policy to live events and last-item replays.
fn notification_payload(config: &V, item: &str) -> String {
    if config.get("include_payload") == Some(&V::Bool(false))
        && let Ok(doc) = roxmltree::Document::parse(item)
        && doc.root_element().tag_name().name() == "item"
    {
        let item = doc.root_element();
        let publisher = item
            .attribute("publisher")
            .map(|j| format!(" publisher='{}'", escape(j)))
            .unwrap_or_default();
        return format!(
            "<item id='{}'{publisher}/>",
            escape(item.attribute("id").unwrap_or(""))
        );
    }
    item.to_owned()
}

fn store(user: Option<&str>, node: &str) -> String {
    format!("{}_{}", if user.is_some() { "pep" } else { "pubsub" }, node)
}
fn read_items(
    root: &Path,
    host: &str,
    user: Option<&str>,
    node: &str,
) -> Result<Vec<crate::archive::Entry>> {
    if let Some(entries) = EPHEMERAL
        .lock()
        .unwrap()
        .get(&ephemeral_key(root, host, user, node))
    {
        return Ok(entries.clone());
    }
    if !persistent(root, host, user, node)? {
        return Ok(vec![]);
    }
    crate::archive::load_store(root, host, user, &store(user, node))
}
// Explicit storage coordinates match both PEP and component backends.
#[allow(clippy::too_many_arguments)]
fn write_item(
    root: &Path,
    host: &str,
    user: Option<&str>,
    node: &str,
    id: &str,
    xml: &str,
    actor: &str,
    max: usize,
    persist: bool,
) -> Result<()> {
    let mut entries = read_items(root, host, user, node)?;
    entries.retain(|e| e.id != id);
    entries.push(crate::archive::Entry {
        id: id.into(),
        when: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs_f64(),
        peer: actor.into(),
        xml: xml.into(),
    });
    if entries.len() > max {
        entries.drain(..entries.len() - max);
    }
    save_items(root, host, user, node, &entries, persist)
}
fn delete_items(
    root: &Path,
    host: &str,
    user: Option<&str>,
    node: &str,
    id: Option<&str>,
) -> Result<()> {
    let mut entries = read_items(root, host, user, node)?;
    entries.retain(|e| id.is_some_and(|id| id != e.id));
    save_items(
        root,
        host,
        user,
        node,
        &entries,
        persistent(root, host, user, node)?,
    )
}

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
#[derive(Default)]
struct Interests {
    subscriptions: BTreeMap<(String, String, String), BTreeSet<String>>,
    pending: BTreeMap<(String, String, String), Vec<String>>,
}
static INTERESTS: LazyLock<Mutex<Interests>> = LazyLock::new(|| Mutex::new(Interests::default()));
fn interested(root: &Path, owner: &str, node: &str) -> Result<Vec<String>> {
    let root_key = root.to_string_lossy();
    let candidates: Vec<_> = INTERESTS
        .lock()
        .unwrap()
        .subscriptions
        .iter()
        .filter(|((r, o, _), nodes)| r == root_key.as_ref() && o == owner && nodes.contains(node))
        .map(|((_, _, j), _)| j.clone())
        .collect();
    let mut out = vec![];
    for jid in candidates {
        if presence_authorized(root, owner, &jid)? {
            out.push(jid)
        }
    }
    Ok(out)
}
fn presence_authorized(root: &Path, owner: &str, recipient: &str) -> Result<bool> {
    if bare(recipient) == owner {
        return Ok(true);
    }
    let Some((user, host)) = owner.split_once('@') else {
        return Ok(false);
    };
    if crate::account_modules::is_blocked(root, host, user, recipient)? {
        return Ok(false);
    }
    let roster = storage::load(root, host, Some(user), "roster")?.unwrap_or_default();
    Ok(matches!(
        text(&tab(&roster, bare(recipient)), "subscription", ""),
        "from" | "both"
    ))
}
/// Call with the authenticated full JID, never a client-supplied from attribute.
pub fn on_presence(
    root: &Path,
    domain: &str,
    jid: &str,
    presence: roxmltree::Node<'_, '_>,
) -> Result<ModuleResult> {
    if presence.attribute("to").is_some()
        || presence
            .attribute("type")
            .is_some_and(|t| t != "unavailable" && t != "error")
    {
        return Ok(ModuleResult::default());
    }
    if presence.attribute("type").is_none()
        && !presence
            .children()
            .any(|n| n.has_tag_name(("http://jabber.org/protocol/caps", "c")))
    {
        return Ok(ModuleResult::default());
    }
    let root_key = root.to_string_lossy().into_owned();
    let mut state = INTERESTS.lock().unwrap();
    state
        .subscriptions
        .retain(|(r, _, j), _| r != &root_key || j != jid);
    state
        .pending
        .retain(|(r, j, _), _| r != &root_key || j != jid);
    if matches!(presence.attribute("type"), Some("unavailable" | "error")) {
        return Ok(ModuleResult::default());
    }
    if presence.attribute("type").is_some() || presence.attribute("to").is_some() {
        return Ok(ModuleResult::default());
    }
    if !presence
        .children()
        .any(|n| n.has_tag_name(("http://jabber.org/protocol/caps", "c")))
    {
        return Ok(ModuleResult::default());
    }
    let Some((user, host)) = bare(jid).split_once('@') else {
        return Ok(ModuleResult::default());
    };
    if host != domain {
        return Ok(ModuleResult::default());
    }
    let mut owners = vec![bare(jid).to_owned()];
    let roster = storage::load(root, domain, Some(user), "roster")?.unwrap_or_default();
    for (k, v) in roster.entries() {
        if matches!(text(v, "subscription", ""), "to" | "both")
            && let Some(j) = k.as_str()
            && j.rsplit_once('@').is_some_and(|(_, h)| h == domain)
        {
            owners.push(j.into())
        }
    }
    if state.pending.len() > 10000 || state.subscriptions.len() > 50000 {
        return Ok(ModuleResult::default());
    }
    let id = format!("pep-caps-{}", uuid::Uuid::new_v4());
    state
        .pending
        .insert((root_key, jid.into(), id.clone()), owners);
    let query = format!(
        "<iq xmlns='jabber:client' from='{}' to='{}' type='get' id='{}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
        escape(domain),
        escape(jid),
        escape(&id)
    );
    Ok(ModuleResult {
        terminal_reply: false,
        replies: vec![],
        deliveries: vec![(jid.into(), query)],
    })
}
/// Consume only server-issued capability requests correlated to the authenticated resource.
pub fn on_disco_result(
    root: &Path,
    domain: &str,
    jid: &str,
    iq: roxmltree::Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    if !matches!(iq.attribute("type"), Some("result" | "error")) {
        return Ok(None);
    }
    let root_key = root.to_string_lossy().into_owned();
    let key = (
        root_key.clone(),
        jid.into(),
        iq.attribute("id").unwrap_or("").into(),
    );
    let owners = { INTERESTS.lock().unwrap().pending.remove(&key) };
    let Some(owners) = owners else {
        return Ok(None);
    };
    let mut result = ModuleResult::default();
    if iq.attribute("type") == Some("error") {
        return Ok(Some(result));
    }
    let Some(query) = iq
        .children()
        .find(|n| n.has_tag_name(("http://jabber.org/protocol/disco#info", "query")))
    else {
        return Ok(Some(result));
    };
    let nodes: BTreeSet<String> = query
        .children()
        .filter(|n| n.has_tag_name(("http://jabber.org/protocol/disco#info", "feature")))
        .filter_map(|n| n.attribute("var"))
        .filter_map(|v| v.strip_suffix("+notify").map(str::to_owned))
        .take(1024)
        .collect();
    let _lock = LOCK.lock().unwrap();
    for owner in owners {
        let Some((user, host)) = owner.split_once('@') else {
            continue;
        };
        if host != domain {
            continue;
        }
        if !presence_authorized(root, &owner, jid)? {
            continue;
        }
        let metadata = storage::load(root, domain, Some(user), "pep")?.unwrap_or_default();
        let mut permitted = BTreeSet::new();
        for node in &nodes {
            // Retain interests for nodes which are created after discovery; delivery rechecks ACLs.
            permitted.insert(node.clone());
            if node == "storage:bookmarks" {
                if let Some(meta) = metadata.get("urn:xmpp:bookmarks:1")
                    && allowed(root, domain, Some(user), &owner, jid, meta)?
                {
                    let entries = read_items(root, domain, Some(user), "urn:xmpp:bookmarks:1")?;
                    let items = entries
                        .iter()
                        .map(|e| (e.id.clone(), format!("<item>{}</item>", e.xml)))
                        .collect::<Vec<_>>();
                    let legacy = crate::account_modules::legacy_bookmark_storage(&items)?;
                    let item = notification_payload(
                        &tab(meta, "config"),
                        &format!("<item id='current'>{legacy}</item>"),
                    );
                    result.deliveries.push((jid.into(),format!("<message xmlns='jabber:client' from='{}' to='{}' type='headline'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='storage:bookmarks'>{item}</items></event></message>",escape(&owner),escape(jid))));
                }
                continue;
            }
            let Some(meta) = metadata.get(node) else {
                continue;
            };
            if !allowed(root, domain, Some(user), &owner, jid, meta)? {
                continue;
            }
            if text(
                &tab(meta, "config"),
                "send_last_published_item",
                "on_sub_and_presence",
            ) != "on_sub_and_presence"
            {
                continue;
            }
            if let Some(entry) = read_items(root, domain, Some(user), node)?.last() {
                let item = notification_payload(
                    &tab(meta, "config"),
                    &item_xml(&tab(meta, "config"), &entry.id, &entry.xml, &entry.peer),
                );
                result.deliveries.push((jid.into(),format!("<message xmlns='jabber:client' from='{}' to='{}' type='headline'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='{}'>{item}</items></event></message>",escape(&owner),escape(jid),escape(node))));
            }
        }
        INTERESTS
            .lock()
            .unwrap()
            .subscriptions
            .insert((root_key.clone(), owner, jid.into()), permitted);
    }
    Ok(Some(result))
}

/// Common features implemented by both the component and account PEP services.
pub fn features() -> String {
    let mut s = format!("<feature var='{NS}'/>");
    for feature in [
        "access-open",
        "access-presence",
        "access-whitelist",
        "access-roster",
        "config-node",
        "config-node-max",
        "create-and-configure",
        "create-nodes",
        "delete-items",
        "delete-nodes",
        "item-ids",
        "manage-subscriptions",
        "modify-affiliations",
        "multi-items",
        "persistent-items",
        "publish",
        "publish-options",
        "purge-nodes",
        "retrieve-affiliations",
        "retrieve-items",
        "retrieve-subscriptions",
        "subscribe",
        "last-published",
    ] {
        s.push_str(&format!("<feature var='{NS}#{feature}'/>"));
    }
    s
}

/// Account capabilities backed by automatic creation and presence/caps handling.
/// Advertise these on the account service rather than on the server or component.
pub fn pep_features() -> String {
    let mut s = features();
    for feature in ["auto-create", "auto-subscribe", "filtered-notifications"] {
        s.push_str(&format!("<feature var='{NS}#{feature}'/>"));
    }
    s
}

fn item_limit(config: &V, maximum: usize) -> usize {
    config
        .get("max_items")
        .and_then(|v| {
            v.as_i64()
                .and_then(|n| usize::try_from(n).ok())
                .or_else(|| {
                    v.as_str().and_then(|s| {
                        if s == "max" {
                            Some(maximum)
                        } else {
                            s.parse().ok()
                        }
                    })
                })
        })
        .unwrap_or(1)
        .min(maximum)
}

fn subscription_form(action: roxmltree::Node<'_, '_>) -> std::result::Result<V, &'static str> {
    let Some(x) = action
        .children()
        .find(|n| n.has_tag_name(("jabber:x:data", "x")))
    else {
        return Err("bad-request");
    };
    if x.attribute("type") != Some("submit") {
        return Err("bad-request");
    }
    let mut out = V::table();
    for f in x.children().filter(|n| n.is_element()) {
        let Some(var) = f.attribute("var") else {
            return Err("bad-request");
        };
        let value = f
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "value")
            .and_then(|n| n.text())
            .unwrap_or("");
        if var == "FORM_TYPE" {
            if value != "http://jabber.org/protocol/pubsub#subscribe_options" {
                return Err("bad-request");
            }
            continue;
        }
        if var != "pubsub#deliver" {
            return Err("feature-not-implemented");
        }
        out.set(
            var,
            V::Bool(match value {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => return Err("bad-request"),
            }),
        );
    }
    Ok(out)
}

type EphemeralKey = (String, String, Option<String>, String);
static EPHEMERAL: LazyLock<Mutex<BTreeMap<EphemeralKey, Vec<crate::archive::Entry>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
fn ephemeral_key(root: &Path, host: &str, user: Option<&str>, node: &str) -> EphemeralKey {
    (
        root.to_string_lossy().into_owned(),
        host.into(),
        user.map(str::to_owned),
        node.into(),
    )
}
fn persistent(root: &Path, host: &str, user: Option<&str>, node: &str) -> Result<bool> {
    let meta = if user.is_some() {
        storage::load(root, host, user, "pep")?.and_then(|v| v.get(node).cloned())
    } else {
        storage::load(root, host, Some(node), "pubsub_nodes")?
    };
    Ok(meta
        .and_then(|v| v.get("config").cloned())
        .and_then(|v| v.get("persist_items").cloned())
        != Some(V::Bool(false)))
}
fn save_items(
    root: &Path,
    host: &str,
    user: Option<&str>,
    node: &str,
    entries: &[crate::archive::Entry],
    persist: bool,
) -> Result<()> {
    let key = ephemeral_key(root, host, user, node);
    if persist {
        crate::archive::save_store(root, host, user, &store(user, node), entries)?;
        EPHEMERAL.lock().unwrap().remove(&key);
    } else {
        let mut cache = EPHEMERAL.lock().unwrap();
        anyhow::ensure!(
            cache.contains_key(&key) || cache.len() < 10000,
            "ephemeral node limit"
        );
        let total = entries.iter().map(|e| e.xml.len()).sum::<usize>();
        anyhow::ensure!(total <= 16 * 1024 * 1024, "ephemeral payload limit");
        let existing = cache
            .iter()
            .filter(|(k, _)| *k != &key)
            .flat_map(|(_, items)| items)
            .map(|e| e.xml.len())
            .sum::<usize>();
        anyhow::ensure!(
            existing.saturating_add(total) <= 64 * 1024 * 1024,
            "ephemeral global payload limit"
        );
        cache.insert(key, entries.to_vec());
        crate::archive::save_store(root, host, user, &store(user, node), &[])?;
    }
    Ok(())
}

/// Federated presence callback. Caller must authenticate `verified_from` against the s2s stream domain.
/// Only the addressed account's interests are changed; presence for another contact is independent.
pub fn on_remote_presence(
    root: &Path,
    domain: &str,
    verified_from: &str,
    presence: roxmltree::Node<'_, '_>,
) -> Result<ModuleResult> {
    let Some(owner) = presence.attribute("to").map(bare) else {
        return Ok(ModuleResult::default());
    };
    let Some((user, host)) = owner.split_once('@') else {
        return Ok(ModuleResult::default());
    };
    let Some((_, remote_host)) = bare(verified_from).split_once('@') else {
        return Ok(ModuleResult::default());
    };
    if host != domain
        || remote_host == domain
        || presence
            .attribute("from")
            .is_some_and(|f| f != verified_from)
    {
        return Ok(ModuleResult::default());
    }
    let unavailable = matches!(presence.attribute("type"), Some("unavailable" | "error"));
    if !verified_from.contains('/') && !unavailable {
        return Ok(ModuleResult::default());
    }
    if presence.attribute("type").is_some() && !unavailable {
        return Ok(ModuleResult::default());
    }
    let has_caps = presence
        .children()
        .any(|n| n.has_tag_name(("http://jabber.org/protocol/caps", "c")));
    if !unavailable && !has_caps {
        return Ok(ModuleResult::default());
    }
    let root_key = root.to_string_lossy().into_owned();
    {
        let mut state = INTERESTS.lock().unwrap();
        state.subscriptions.retain(|(r, o, j), _| {
            !(r == &root_key
                && o == owner
                && (j == verified_from
                    || (!verified_from.contains('/') && bare(j) == verified_from)))
        });
        state.pending.retain(|(r, j, _), owners| {
            if r == &root_key
                && (j == verified_from
                    || (!verified_from.contains('/') && bare(j) == verified_from))
            {
                owners.retain(|o| o != owner)
            }
            !owners.is_empty()
        });
    }
    if unavailable
        || !presence_authorized(root, owner, verified_from)?
        || storage::load(root, domain, Some(user), "accounts")?.is_none()
    {
        return Ok(ModuleResult::default());
    }
    let id = format!("pep-caps-{}", uuid::Uuid::new_v4());
    let mut state = INTERESTS.lock().unwrap();
    if state.pending.len() >= 10000 || state.subscriptions.len() >= 50000 {
        return Ok(ModuleResult::default());
    }
    state.pending.insert(
        (root_key, verified_from.into(), id.clone()),
        vec![owner.into()],
    );
    Ok(ModuleResult {
        terminal_reply: false,
        replies: vec![],
        deliveries: vec![(
            verified_from.into(),
            format!(
                "<iq xmlns='jabber:client' from='{}' to='{}' type='get' id='{}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
                escape(owner),
                escape(verified_from),
                escape(&id)
            ),
        )],
    })
}
