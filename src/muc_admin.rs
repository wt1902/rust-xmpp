//! The two native MUC component administration commands. Authority belongs to
//! configured component administrators and is checked again on every step.
use super::*;
const COMMANDS: &str = "http://jabber.org/protocol/commands";
const DESTROY: &str = "http://prosody.im/protocol/muc#destroy";
const AFFILIATION: &str = "http://prosody.im/protocol/muc#set-affiliation";
const INFO: &str = "http://jabber.org/protocol/disco#info";
const ITEMS: &str = "http://jabber.org/protocol/disco#items";

pub(super) fn period(value: Option<&Value>) -> Option<f64> {
    let seconds = if let Some(number) = value.and_then(Value::as_f64) {
        number
    } else {
        let text = value?.as_str()?.trim();
        let split = text
            .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '+' || c == '-'))
            .unwrap_or(text.len());
        let number: f64 = text[..split].trim().parse().ok()?;
        let unit = text[split..].trim();
        number
            * match unit {
                "" | "s" | "second" | "seconds" => 1.0,
                "m" | "minute" | "minutes" => 60.0,
                "h" | "hour" | "hours" => 3600.0,
                "d" | "day" | "days" => 86400.0,
                "w" | "week" | "weeks" => 604800.0,
                _ => return None,
            }
    };
    (seconds.is_finite() && seconds >= 0.0).then_some(seconds)
}
pub(super) fn registration_form(nick: Option<&str>) -> String {
    format!(
        "<x xmlns='jabber:x:data' type='{}'><field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/muc#register</value></field><field var='muc#register_roomnick' type='text-single'>{}<required/></field></x>",
        if nick.is_some() { "result" } else { "form" },
        nick.map(|v| format!("<value>{}</value>", escape(v)))
            .unwrap_or_default()
    )
}
fn command_reply(
    stanza: roxmltree::Node,
    node: &str,
    session: &str,
    status: &str,
    body: &str,
) -> ModuleResult {
    ModuleResult::reply(iq_result(
        stanza,
        &format!(
            "<command xmlns='{COMMANDS}' node='{}' sessionid='{}' status='{status}'>{body}</command>",
            escape(node),
            escape(session)
        ),
    ))
}
fn form(muc: &Muc, node: &str) -> String {
    let fields = if node == DESTROY {
        let rooms = muc
            .rooms
            .keys()
            .map(|room| {
                format!(
                    "<option label='{}'><value>{}</value></option>",
                    escape(room),
                    escape(room)
                )
            })
            .collect::<String>();
        format!(
            "<field var='rooms' type='list-multi' label='Rooms to destroy'><required/>{rooms}</field>"
        )
    } else {
        "<field var='room' type='jid-single' label='Room'><required/></field><field var='jid' type='jid-single' label='JID'><required/></field><field var='affiliation' type='list-single' label='Affiliation'><required/><option><value>owner</value></option><option><value>admin</value></option><option><value>member</value></option><option><value>none</value></option><option><value>outcast</value></option></field><field var='reason' type='text-single' label='Reason'/>".to_owned()
    };
    format!(
        "<actions execute='complete'><complete/></actions><x xmlns='jabber:x:data' type='form'><title>{}</title><field var='FORM_TYPE' type='hidden'><value>{node}</value></field>{fields}</x>",
        if node == DESTROY {
            "Destroy rooms"
        } else {
            "Set affiliation"
        }
    )
}
pub(super) fn handle(
    muc: &mut Muc,
    jid: &str,
    stanza: roxmltree::Node,
) -> Result<Option<ModuleResult>> {
    if stanza.tag_name().name() != "iq" {
        return Ok(None);
    }
    let Some(query) = stanza.children().find(|n| n.is_element()) else {
        return Ok(None);
    };
    let ns = query.tag_name().namespace().unwrap_or("");
    let node = query.attribute("node").unwrap_or("");
    let is_admin = muc
        .component_admins
        .iter()
        .any(|admin| bare(admin) == bare(jid));
    if matches!(ns, INFO | ITEMS)
        && (node == COMMANDS || matches!(node, DESTROY | AFFILIATION))
        && stanza.attribute("type") == Some("get")
    {
        let body = if ns == ITEMS && node == COMMANDS {
            if is_admin {
                format!(
                    "<item jid='{}' node='{DESTROY}' name='Destroy Rooms'/><item jid='{}' node='{AFFILIATION}' name='Set affiliation in room'/>",
                    escape(&muc.domain),
                    escape(&muc.domain)
                )
            } else {
                String::new()
            }
        } else if !is_admin && node != COMMANDS {
            return Ok(Some(ModuleResult::reply(iq_error(stanza, "forbidden"))));
        } else if ns == INFO {
            format!(
                "<identity category='automation' type='{}'/><feature var='{COMMANDS}'/><feature var='jabber:x:data'/>",
                if node == COMMANDS {
                    "command-list"
                } else {
                    "command-node"
                }
            )
        } else {
            String::new()
        };
        return Ok(Some(ModuleResult::reply(iq_result(
            stanza,
            &format!("<query xmlns='{ns}' node='{}'>{body}</query>", escape(node)),
        ))));
    }
    if ns != COMMANDS || query.tag_name().name() != "command" {
        return Ok(None);
    }
    if !is_admin {
        return Ok(Some(ModuleResult::reply(iq_error(stanza, "forbidden"))));
    }
    if stanza.attribute("type") != Some("set") {
        return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
    }
    if !matches!(node, DESTROY | AFFILIATION) {
        return Ok(Some(ModuleResult::reply(iq_error(
            stanza,
            "item-not-found",
        ))));
    }
    muc.command_sessions
        .retain(|_, (_, _, started)| started.elapsed() < std::time::Duration::from_secs(600));
    let session = query.attribute("sessionid");
    let action = query.attribute("action").unwrap_or("execute");
    if session.is_none() {
        if action != "execute"
            || query
                .children()
                .any(|n| n.has_tag_name(("jabber:x:data", "x")))
        {
            return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
        }
        if muc.command_sessions.len() >= 1000 {
            return Ok(Some(ModuleResult::reply(iq_error(
                stanza,
                "resource-constraint",
            ))));
        }
        let id = uuid::Uuid::new_v4().to_string();
        muc.command_sessions.insert(
            id.clone(),
            (
                bare(jid).to_owned(),
                node.to_owned(),
                std::time::Instant::now(),
            ),
        );
        return Ok(Some(command_reply(
            stanza,
            node,
            &id,
            "executing",
            &form(muc, node),
        )));
    }
    let session = session.unwrap();
    if !muc
        .command_sessions
        .get(session)
        .is_some_and(|(owner, command, _)| owner == bare(jid) && command == node)
    {
        return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
    }
    if action == "cancel" {
        muc.command_sessions.remove(session);
        return Ok(Some(command_reply(stanza, node, session, "canceled", "")));
    }
    if !matches!(action, "execute" | "complete") {
        return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
    }
    let Some(data) = query
        .children()
        .find(|n| n.has_tag_name(("jabber:x:data", "x")) && n.attribute("type") == Some("submit"))
    else {
        return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
    };
    let values = |name: &str| {
        data.children()
            .filter(|f| {
                f.has_tag_name(("jabber:x:data", "field")) && f.attribute("var") == Some(name)
            })
            .flat_map(|f| {
                f.children()
                    .filter(|v| v.has_tag_name(("jabber:x:data", "value")))
                    .filter_map(|v| v.text())
            })
            .collect::<Vec<_>>()
    };
    if values("FORM_TYPE") != vec![node] {
        return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
    }
    let mut out = ModuleResult::default();
    if node == DESTROY {
        let rooms = values("rooms");
        if rooms.is_empty()
            || rooms
                .iter()
                .any(|room| bare(room) != *room || !room.ends_with(&format!("@{}", muc.domain)))
        {
            return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
        }
        for name in rooms {
            muc.load(name)?;
            if !muc.rooms.contains_key(name) {
                continue;
            }
            // Only this internal, ACL-checked command bypasses room ownership.
            let packet = format!(
                "<iq type='set' to='{}'><query xmlns='{OWNER}'><destroy/></query></iq>",
                escape(name)
            );
            let doc = roxmltree::Document::parse(&packet)?;
            if let Some(mut destroyed) =
                muc.handle_inner_authorized(jid, doc.root_element(), true)?
            {
                out.deliveries.append(&mut destroyed.deliveries);
            }
        }
    } else {
        let rooms = values("room");
        let targets = values("jid");
        let affiliations = values("affiliation");
        if rooms.len() != 1 || targets.len() != 1 || affiliations.len() != 1 {
            return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
        }
        let name = rooms[0];
        let target = targets[0];
        let affiliation = affiliations[0];
        if bare(name) != name
            || !name.ends_with(&format!("@{}", muc.domain))
            || crate::account_modules::normalize_bare_jid(bare(target)).is_err()
            || !matches!(
                affiliation,
                "none" | "member" | "admin" | "owner" | "outcast"
            )
        {
            return Ok(Some(ModuleResult::reply(iq_error(stanza, "bad-request"))));
        }
        muc.load(name)?;
        let Some(room) = muc.rooms.get_mut(name) else {
            return Ok(Some(command_reply(
                stanza,
                node,
                session,
                "canceled",
                "<note type='error'>No such room</note>",
            )));
        };
        let reason = values("reason").first().copied().unwrap_or("");
        let packet = format!(
            "<iq type='set'><query xmlns='{ADMIN}'><item jid='{}' affiliation='{affiliation}'><reason>{}</reason></item></query></iq>",
            escape(&crate::account_modules::normalize_bare_jid(bare(target))?),
            escape(reason)
        );
        let doc = roxmltree::Document::parse(&packet)?;
        let iq = doc.root_element();
        let mut applied = ModuleResult::default();
        admin_with_authority(
            room,
            name,
            jid,
            iq,
            iq.children().find(|n| n.is_element()).unwrap(),
            &mut applied,
            true,
        );
        if applied.replies.iter().any(|p| p.contains("type='error'")) {
            return Ok(Some(command_reply(
                stanza,
                node,
                session,
                "canceled",
                "<note type='error'>Affiliation change failed</note>",
            )));
        }
        out.deliveries.append(&mut applied.deliveries);
        muc.save(name)?;
    }
    muc.command_sessions.remove(session);
    out.replies.append(
        &mut command_reply(
            stanza,
            node,
            session,
            "completed",
            "<note type='info'>Command completed</note>",
        )
        .replies,
    );
    Ok(Some(out))
}
