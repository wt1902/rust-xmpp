//! XEP-0379 presence tokens and the XEP-0401 contact invitation command.
//!
//! Unscoped tokens use Prosody mod_invites' per-user `invite_token` map
//! (token -> Unix expiry). Identity-scoped tokens live separately so a server
//! that does not understand the scope cannot accidentally redeem them.
use crate::{
    account_modules::normalize_bare_jid,
    protocol::{ModuleResult, bare, iq_error, iq_result},
    storage::{self, LuaValue as V},
    wire::escape,
};
use anyhow::{Result, ensure};
use roxmltree::Node;
use std::path::Path;

pub const NS: &str = "urn:xmpp:pars:0";
pub const INVITE_COMMAND: &str = "urn:xmpp:invite#invite";
pub const DEFAULT_TTL: i64 = 7 * 86400;
const SCOPED_STORE: &str = "preauth_scoped";
const MAX_TOKENS: usize = 256;

#[derive(Debug, Clone)]
pub struct Invitation {
    pub token: String,
    pub uri: String,
    pub expires: i64,
}
fn local_user<'a>(domain: &str, owner: &'a str) -> Result<&'a str> {
    let (user, host) = owner
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("account JID required"))?;
    ensure!(
        host == domain && !user.is_empty() && !owner.contains('/'),
        "not a local bare account"
    );
    ensure!(
        normalize_bare_jid(owner)? == owner,
        "noncanonical account JID"
    );
    Ok(user)
}
fn expiry(value: &V) -> Option<i64> {
    match value {
        V::Integer(n) => Some(*n),
        V::Number(n) if n.is_finite() && n.fract() == 0.0 && *n >= 0.0 && *n < i64::MAX as f64 => {
            Some(*n as i64)
        }
        _ => None,
    }
}
/// Issue a single-use token. `owner` and optional `recipient` must be bare JIDs.
/// `now` is Unix seconds; callers normally use `chrono::Utc::now().timestamp()`.
pub fn create_invite(
    root: &Path,
    domain: &str,
    owner: &str,
    recipient: Option<&str>,
    ttl: i64,
    now: i64,
) -> Result<Invitation> {
    let user = local_user(domain, owner)?;
    ensure!(
        storage::load(root, domain, Some(user), "accounts")?
            .is_some_and(|account| account.get("disabled") != Some(&V::Bool(true))),
        "unknown account"
    );
    ensure!(
        now >= 0 && ttl > 0 && ttl <= 30 * 86400,
        "invalid token lifetime"
    );
    let expires = now
        .checked_add(ttl)
        .ok_or_else(|| anyhow::anyhow!("expiry overflow"))?;
    let recipient = recipient.map(normalize_bare_jid).transpose()?;
    ensure!(recipient.as_deref() != Some(owner), "cannot invite self");
    let token = uuid::Uuid::new_v4().simple().to_string();
    let scoped = recipient.is_some();
    let store = if scoped { SCOPED_STORE } else { "invite_token" };
    storage::update(root, domain, Some(user), store, |data| {
        let expired: Vec<_> = data
            .entries()
            .iter()
            .filter_map(|(k, v)| {
                let end = if scoped {
                    v.get("expires").and_then(expiry)
                } else {
                    expiry(v)
                };
                end.filter(|e| *e <= now).map(|_| k.clone())
            })
            .collect();
        for key in expired {
            data.set_key(key, V::Nil);
        }
        ensure!(
            data.entries().len() < MAX_TOKENS,
            "too many pending invitations"
        );
        let value = if let Some(jid) = &recipient {
            let mut value = V::table();
            value.set("expires", V::Integer(expires));
            value.set("jid", jid.clone().into());
            value
        } else {
            V::Integer(expires)
        };
        data.set(&token, value);
        Ok(())
    })?;
    Ok(Invitation {
        uri: format!("xmpp:{owner}?roster;preauth={token}"),
        token,
        expires,
    })
}
/// Atomically validate and consume a token. Invalid/expired/mismatched tokens
/// return false and must follow normal manual subscription processing.
/// Caller must authenticate `sender`, verify recipient account and blocking,
/// then apply roster transitions only when this returns true.
pub fn consume(
    root: &Path,
    domain: &str,
    owner: &str,
    sender: &str,
    token: &str,
    now: i64,
) -> Result<bool> {
    let user = local_user(domain, owner)?;
    let sender = normalize_bare_jid(bare(sender))?;
    if token.is_empty() || token.len() > 256 || sender == owner || now < 0 {
        return Ok(false);
    }
    let mut accepted = false;
    // Never fall back to an unscoped record when a scoped record is present.
    let mut found_scope = false;
    if storage::load(root, domain, Some(user), SCOPED_STORE)?
        .is_some_and(|data| data.get(token).is_some())
    {
        storage::update(root, domain, Some(user), SCOPED_STORE, |data| {
            if let Some(value) = data.get(token) {
                found_scope = true;
                let end = value.get("expires").and_then(expiry);
                accepted = end.is_some_and(|end| end > now)
                    && value.get("jid").and_then(V::as_str) == Some(sender.as_str());
                if accepted || end.is_some_and(|end| end <= now) {
                    data.set(token, V::Nil);
                }
            }
            Ok(())
        })?;
    }
    if found_scope {
        return Ok(accepted);
    }
    if !storage::load(root, domain, Some(user), "invite_token")?
        .is_some_and(|data| data.get(token).is_some())
    {
        return Ok(false);
    }
    storage::update(root, domain, Some(user), "invite_token", |data| {
        if let Some(end) = data.get(token).and_then(expiry) {
            accepted = end > now;
            data.set(token, V::Nil);
        }
        Ok(())
    })?;
    if accepted
        && storage::load(root, domain, None, "invite_token")?
            .is_some_and(|data| data.get(token).is_some())
    {
        // mod_invites also removes the host-level registration side of a
        // combined roster/account invitation when the roster token is used.
        storage::update(root, domain, None, "invite_token", |data| {
            if data.get(token).is_some_and(|record| {
                record.get("type").and_then(V::as_str) == Some("roster")
                    && record.get("jid").and_then(V::as_str) == Some(owner)
            }) {
                data.set(token, V::Nil);
            }
            Ok(())
        })?;
    }
    Ok(accepted)
}
/// Only a single, well-formed direct child of a subscribe presence qualifies.
pub fn token_from_presence<'a>(presence: Node<'a, '_>) -> Option<&'a str> {
    if presence.tag_name().name() != "presence" || presence.attribute("type") != Some("subscribe") {
        return None;
    }
    let mut tokens = presence
        .children()
        .filter(|n| n.has_tag_name((NS, "preauth")));
    let token = tokens.next()?;
    if tokens.next().is_some() || token.children().any(|n| n.is_element()) {
        return None;
    }
    token
        .attribute("token")
        .filter(|t| !t.is_empty() && t.len() <= 256)
}
/// Contact-only subset of XEP-0401, with no registration permission or landing URL.
pub fn handle_iq(
    root: &Path,
    domain: &str,
    actor: &str,
    iq: Node<'_, '_>,
) -> Result<Option<ModuleResult>> {
    let Some(command) = iq.children().find(|n| {
        n.has_tag_name(("http://jabber.org/protocol/commands", "command"))
            && n.attribute("node") == Some(INVITE_COMMAND)
    }) else {
        return Ok(None);
    };
    let error = |name| Ok(Some(ModuleResult::reply(iq_error(iq, name))));
    if iq.attribute("type") != Some("set")
        || iq.attribute("id").is_none()
        || iq.children().filter(|n| n.is_element()).count() != 1
    {
        return error("bad-request");
    }
    let owner = bare(actor);
    if local_user(domain, owner).is_err() {
        return error("not-authorized");
    }
    if iq
        .attribute("to")
        .is_some_and(|to| to != domain && to != owner)
    {
        return error("forbidden");
    }
    if !matches!(command.attribute("action"), None | Some("execute"))
        || command.attribute("sessionid").is_some()
        || command.children().any(|n| n.is_element())
    {
        return error("bad-request");
    }
    let now = chrono::Utc::now().timestamp();
    let invitation = match create_invite(root, domain, owner, None, DEFAULT_TTL, now) {
        Ok(invite) => invite,
        Err(_) => return error("resource-constraint"),
    };
    let expires = chrono::DateTime::from_timestamp(invitation.expires, 0)
        .ok_or_else(|| anyhow::anyhow!("invalid expiry"))?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let payload = format!(
        "<command xmlns='http://jabber.org/protocol/commands' node='{INVITE_COMMAND}' status='completed'><x xmlns='jabber:x:data' type='result'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:invite#invitation</value></field><field var='uri' type='text-single'><value>{}</value></field><field var='expire' type='text-single'><value>{}</value></field></x></command>",
        escape(&invitation.uri),
        escape(&expires)
    );
    Ok(Some(ModuleResult::reply(iq_result(iq, &payload))))
}
