use crate::protocol::bare;
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct Session {
    pub jid: String,
    pub owner: String,
    pub client_id: Option<String>,
    pub push_identifier: Option<String>,
    pub first_push_sent: bool,
    pub connection: String,
    pub sender: Option<mpsc::Sender<String>>,
    pub available: bool,
    pub priority: i8,
    pub presence: Option<String>,
    pub carbons: bool,
    pub csi: crate::csi::Buffer,
    pub roster_interested: bool,
    pub sm: bool,
    pub resume_id: Option<String>,
    pub handled: u32,
    pub sent: u32,
    pub acked: u32,
    pub ack_limit: usize,
    pub ack_requested: bool,
    pub pending: VecDeque<String>,
    pub expires: Option<Instant>,
    pub timeout: Duration,
    pub closed: bool,
    pub close_condition: Option<String>,
    pub cancel: Arc<tokio::sync::Notify>,
    pub(crate) durable: Option<std::sync::Weak<crate::session_store::Store>>,
}
impl Session {
    /// Persist state before acknowledging client input or exposing output to a transport.
    pub fn checkpoint(&self) -> Result<()> {
        crate::session_store::checkpoint(self)
    }
    pub fn mark_handled(&mut self) -> Result<()> {
        ensure!(!self.closed, "session closed");
        if !self.sm {
            return Ok(());
        }
        let previous = self.handled;
        self.handled = self.handled.wrapping_add(1);
        if let Err(error) = self.checkpoint() {
            self.handled = previous;
            return Err(error);
        }
        Ok(())
    }
    pub fn track_outbound(&mut self, xml: &str) -> Result<()> {
        ensure!(!self.closed, "session closed");
        if !self.sm {
            return Ok(());
        }
        ensure!(self.pending.len() < 4096, "stream management queue limit");
        // The byte bound applies to memory-only sessions too.
        ensure!(
            self.pending
                .iter()
                .map(String::len)
                .sum::<usize>()
                .saturating_add(xml.len())
                <= 8 * 1024 * 1024,
            "stream management byte limit"
        );
        self.sent = self.sent.wrapping_add(1);
        self.pending.push_back(xml.into());
        if let Err(error) = self.checkpoint() {
            self.sent = self.sent.wrapping_sub(1);
            self.pending.pop_back();
            return Err(error);
        }
        Ok(())
    }
    pub fn first_important_push(&mut self, normal_timeout: Duration) {
        if self.sender.is_none() && self.expires.is_some() && !self.first_push_sent {
            self.first_push_sent = true;
            self.expires = Some(Instant::now() + normal_timeout);
        }
    }
    pub fn transmit(&mut self, xml: String) -> Result<()> {
        ensure!(!self.closed, "session closed");
        if let Some(tx) = self.sender.clone() {
            let permit = tx
                .try_reserve()
                .map_err(|_| anyhow::anyhow!("recipient queue unavailable"))?;
            self.track_outbound(&xml)?;
            permit.send(xml);
        } else {
            ensure!(
                self.sm && self.resume_id.is_some(),
                "recipient disconnected"
            );
            self.track_outbound(&xml)?;
        }
        Ok(())
    }
    pub fn request_ack(&mut self) -> bool {
        if self.sm && self.pending.len() >= self.ack_limit.max(1) && !self.ack_requested {
            self.ack_requested = true;
            true
        } else {
            false
        }
    }
    pub fn acknowledge(&mut self, h: u32) -> Result<()> {
        ensure!(!self.closed, "session closed");
        let n = h.wrapping_sub(self.acked) as usize;
        ensure!(n <= self.pending.len(), "invalid stream acknowledgement");
        if n == 0 {
            self.ack_requested = false;
            return Ok(());
        }
        let previous = self.clone();
        self.pending.drain(..n);
        self.acked = h;
        self.ack_requested = false;
        if let Err(error) = self.checkpoint() {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }
    pub fn enable(&mut self, resume: bool) -> Result<String> {
        ensure!(!self.closed, "session closed");
        ensure!(!self.sm, "stream management already enabled");
        self.sm = true;
        if resume {
            self.resume_id = Some(uuid::Uuid::new_v4().to_string());
        }
        if let Err(error) = crate::session_store::enable(self) {
            self.sm = false;
            self.resume_id = None;
            return Err(error);
        }
        Ok(match &self.resume_id {
            Some(id) => format!(
                "<enabled xmlns='urn:xmpp:sm:3' id='{id}' resume='true' max='{}'/>",
                self.timeout.as_secs()
            ),
            None => "<enabled xmlns='urn:xmpp:sm:3'/>".into(),
        })
    }
}
pub type SharedSession = Arc<Mutex<Session>>;
/// Prosody's conflict_resolve policy; unspecified values use kick_old.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictPolicy {
    KickOld,
    KickNew,
    Increment,
    Random,
}
impl ConflictPolicy {
    pub fn from_config(value: Option<&str>) -> Self {
        match value {
            Some("kick_new") => Self::KickNew,
            Some("increment") => Self::Increment,
            Some("random") => Self::Random,
            _ => Self::KickOld,
        }
    }
}
#[derive(Clone, Default)]
pub struct Hub {
    sessions: Arc<Mutex<BTreeMap<String, SharedSession>>>,
    store: Option<Arc<crate::session_store::Store>>,
}
impl Hub {
    pub fn persistent(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let (store, records) = crate::session_store::Store::open(path.as_ref())?;
        let mut sessions = BTreeMap::new();
        for record in records {
            let mut session = record.session();
            session.durable = Some(Arc::downgrade(&store));
            ensure!(
                !sessions.contains_key(&session.jid),
                "duplicate durable resource"
            );
            sessions.insert(session.jid.clone(), Arc::new(Mutex::new(session)));
        }
        Ok(Self {
            sessions: Arc::new(Mutex::new(sessions)),
            store: Some(store),
        })
    }
    /// Refresh only connected deadlines; disconnected deadlines never slide.
    pub fn checkpoint_live(&self) -> Result<()> {
        for session in self.all() {
            let state = session.lock().unwrap();
            if state.sender.is_some() && !state.closed {
                state.checkpoint()?;
            }
        }
        Ok(())
    }

    /// Retire in-flight transport handles and commit offline state before shutdown.
    pub fn freeze(&self) -> Result<()> {
        let mut map = self.sessions.lock().unwrap();
        for shared in map.values_mut() {
            let previous = shared.clone();
            let mut old = previous.lock().unwrap();
            if old.closed || !old.sm || old.resume_id.is_none() {
                continue;
            }
            let mut state = old.clone();
            state.sender = None;
            if state.expires.is_none() {
                state.expires = Some(Instant::now() + state.timeout);
            }
            state.connection = format!("shutdown-{}", uuid::Uuid::new_v4());
            state.cancel = Default::default();
            crate::session_store::claim(&old, &state)?;
            old.closed = true;
            old.sender = None;
            old.resume_id = None;
            old.expires = None;
            *shared = Arc::new(Mutex::new(state));
        }
        Ok(())
    }
    pub fn bind(
        &self,
        jid: &str,
        connection: &str,
        sender: mpsc::Sender<String>,
        timeout: Duration,
    ) -> Result<SharedSession> {
        self.bind_resolving(jid, connection, sender, timeout, ConflictPolicy::KickNew)
            .map(|(session, _)| session)
    }
    /// Choose and reserve the resource under the same lock as replacement.
    pub fn bind_resolving(
        &self,
        jid: &str,
        connection: &str,
        sender: mpsc::Sender<String>,
        timeout: Duration,
        policy: ConflictPolicy,
    ) -> Result<(SharedSession, Option<SharedSession>)> {
        let mut map = self.sessions.lock().unwrap();
        let mut jid = jid.to_owned();
        let mut replaced = None;
        if map.contains_key(&jid) {
            match policy {
                ConflictPolicy::KickNew => anyhow::bail!("resource conflict"),
                ConflictPolicy::KickOld => {
                    let old = map.get(&jid).unwrap().clone();
                    {
                        let mut state = old.lock().unwrap();
                        crate::session_store::remove(&state)?;
                        state.closed = true;
                        state.close_condition = Some("conflict".into());
                        state.sender = None;
                        state.resume_id = None;
                        state.expires = None;
                        state.cancel.notify_one();
                    }
                    map.remove(&jid);
                    replaced = Some(old);
                }
                ConflictPolicy::Increment => {
                    let base = jid.clone();
                    let mut count = 1;
                    while map.contains_key(&format!("{base}#{count}")) {
                        count += 1;
                    }
                    jid = format!("{base}#{count}");
                }
                ConflictPolicy::Random => {
                    let owner = bare(&jid).to_owned();
                    loop {
                        jid = format!("{owner}/{}", uuid::Uuid::new_v4());
                        if !map.contains_key(&jid) {
                            break;
                        }
                    }
                }
            }
        }
        let s = Arc::new(Mutex::new(Session {
            jid: jid.clone(),
            owner: bare(&jid).into(),
            client_id: None,
            push_identifier: None,
            first_push_sent: false,
            connection: connection.into(),
            sender: Some(sender),
            available: false,
            priority: 0,
            presence: None,
            carbons: false,
            csi: Default::default(),
            roster_interested: false,
            sm: false,
            resume_id: None,
            handled: 0,
            sent: 0,
            acked: 0,
            ack_limit: 100,
            ack_requested: false,
            pending: VecDeque::new(),
            expires: None,
            timeout,
            closed: false,
            close_condition: None,
            cancel: Default::default(),
            durable: self.store.as_ref().map(Arc::downgrade),
        }));
        map.insert(jid, s.clone());
        Ok((s, replaced))
    }
    pub fn kick_owner_checked(&self, owner: &str) -> Result<()> {
        let mut map = self.sessions.lock().unwrap();
        let victims: Vec<_> = map
            .iter()
            .filter_map(|(jid, session)| {
                (session.lock().unwrap().owner == owner).then_some(jid.clone())
            })
            .collect();
        for jid in victims {
            let shared = map.get(&jid).unwrap().clone();
            let mut state = shared.lock().unwrap();
            // Do not let account deletion/recreation proceed if durable revocation failed.
            crate::session_store::remove(&state)?;
            state.resume_id = None;
            state.sender = None;
            state.closed = true;
            state.cancel.notify_one();
            map.remove(&jid);
        }
        Ok(())
    }
    pub fn kick_owner(&self, owner: &str) {
        let _ = self.kick_owner_checked(owner);
    }
    pub fn get(&self, jid: &str) -> Option<SharedSession> {
        self.sessions.lock().unwrap().get(jid).cloned()
    }
    pub fn all(&self) -> Vec<SharedSession> {
        self.sessions.lock().unwrap().values().cloned().collect()
    }
    /// Filter immutable resource keys before taking any per-session lock. A slow
    /// client from another account must not block this account's routing/carbons.
    pub fn for_owners(&self, owners: &[&str]) -> Vec<SharedSession> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|(jid, _)| owners.contains(&bare(jid)))
            .map(|(_, session)| session.clone())
            .collect()
    }
    pub fn deliver(&self, to: &str, xml: &str) -> usize {
        let roster_push = roxmltree::Document::parse(xml).ok().is_some_and(|d| {
            d.root_element()
                .attribute("id")
                .is_some_and(|id| id.starts_with("roster-"))
        });
        let targets = if to.contains('/') {
            self.get(to).into_iter().collect()
        } else {
            self.for_owners(&[to])
        };
        targets
            .into_iter()
            .filter(|s| {
                let mut s = s.lock().unwrap();
                let matches = if to.contains('/') {
                    s.jid == to
                } else {
                    s.owner == to
                };
                matches && (!roster_push || s.roster_interested) && s.transmit(xml.into()).is_ok()
            })
            .count()
    }
    pub fn message_targets(&self, to: &str) -> Vec<SharedSession> {
        self.message_targets_for_type(to, "normal")
    }
    /// Native mod_message first tries the exact full JID, then applies the
    /// message-type-specific bare-JID policy when that resource is absent.
    pub fn message_targets_for_type(&self, to: &str, kind: &str) -> Vec<SharedSession> {
        if to.contains('/') {
            if let Some(session) = self.get(to) {
                return vec![session];
            }
            if matches!(kind, "headline" | "error" | "groupchat") {
                return vec![];
            }
        } else if matches!(kind, "error" | "groupchat") {
            return vec![];
        }
        let bare = to.split_once('/').map(|(bare, _)| bare).unwrap_or(to);
        let mut max = None;
        let mut out = vec![];
        for s in self.for_owners(&[bare]) {
            let p = {
                let state = s.lock().unwrap();
                if state.owner != bare || !state.available || state.priority < 0 {
                    continue;
                }
                state.priority
            };
            if kind == "headline" {
                out.push(s);
                continue;
            }
            if max.is_none_or(|v| p > v) {
                max = Some(p);
                out.clear();
            }
            if max == Some(p) {
                out.push(s);
            }
        }
        out
    }
    pub fn disconnect(&self, connection: &str, graceful: bool) -> Vec<String> {
        let mut removed = vec![];
        self.sessions.lock().unwrap().retain(|jid, s| {
            let mut s = s.lock().unwrap();
            if s.connection != connection {
                return true;
            }
            if !graceful && s.sm && s.resume_id.is_some() {
                s.csi.reset();
                s.sender = None;
                // Repeated cleanup must not renew an already offline token.
                if s.expires.is_none() {
                    s.expires = Some(Instant::now() + s.timeout);
                }
                if s.checkpoint().is_err() {
                    return true;
                }
                true
            } else {
                if crate::session_store::remove(&s).is_err() {
                    return true;
                }
                s.closed = true;
                s.resume_id = None;
                s.sender = None;
                removed.push(jid.clone());
                false
            }
        });
        removed
    }
    pub fn expired(&self) -> Vec<String> {
        let mut out = vec![];
        self.sessions.lock().unwrap().retain(|jid, session| {
            let mut state = session.lock().unwrap();
            if state.expires.is_some_and(|t| Instant::now() >= t) {
                if crate::session_store::remove(&state).is_err() {
                    return true;
                }
                state.closed = true;
                state.resume_id = None;
                state.sender = None;
                state.cancel.notify_one();
                out.push(jid.clone());
                false
            } else {
                true
            }
        });
        out
    }
    pub fn resume(
        &self,
        owner: &str,
        id: &str,
        h: u32,
        connection: &str,
        sender: mpsc::Sender<String>,
    ) -> Result<(SharedSession, Vec<String>)> {
        self.expired();
        let mut map = self.sessions.lock().unwrap();
        let candidate = map
            .values()
            .find(|session| {
                let state = session.lock().unwrap();
                !state.closed
                    && state
                        .expires
                        .is_none_or(|deadline| deadline > Instant::now())
                    && state.owner == owner
                    && state.resume_id.as_deref() == Some(id)
            })
            .cloned();
        if let Some(previous) = candidate {
            let mut old = previous.lock().unwrap();
            // Validate before changing the old transport or any session counters.
            let count = h.wrapping_sub(old.acked) as usize;
            ensure!(count <= old.pending.len(), "invalid stream acknowledgement");
            // Keep a retired transport's in-flight operations isolated from the
            // resumed queue, acknowledgements and CSI state.
            let mut state = old.clone();
            state.pending.drain(..count);
            state.acked = h;
            state.ack_requested = false;
            state.cancel = Default::default();
            state.csi.reset();
            state.first_push_sent = false;
            state.sender = Some(sender);
            state.connection = connection.into();
            state.expires = None;
            crate::session_store::claim(&old, &state)?;
            let mut replay = vec![format!(
                "<resumed xmlns='urn:xmpp:sm:3' previd='{id}' h='{}'/>",
                state.handled
            )];
            replay.extend(state.pending.iter().cloned());
            old.closed = true;
            old.close_condition = Some("conflict".into());
            old.sender = None;
            old.resume_id = None;
            old.expires = None;
            old.pending.clear();
            old.csi.reset();
            old.cancel.notify_one();
            let jid = state.jid.clone();
            let resumed = Arc::new(Mutex::new(state));
            map.insert(jid, resumed.clone());
            return Ok((resumed, replay));
        }
        anyhow::bail!("resume session not found")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traffic_before_sm_enable_is_not_counted() {
        let hub = Hub::default();
        let (tx, _rx) = mpsc::channel(8);
        let session = hub
            .bind("a@x/r", "plain", tx, Duration::from_secs(30))
            .unwrap();
        let mut session = session.lock().unwrap();
        session.mark_handled().unwrap();
        session.track_outbound("plain reply").unwrap();
        session.enable(true).unwrap();
        assert_eq!((session.handled, session.sent), (0, 0));
        session.mark_handled().unwrap();
        assert_eq!(session.handled, 1);
    }
    #[test]
    fn resume_replays_only_unacked_and_checks_owner() {
        let h = Hub::default();
        let (tx, _rx) = mpsc::channel(8);
        let s = h.bind("a@x/r", "c1", tx, Duration::from_secs(30)).unwrap();
        let id;
        {
            let mut s = s.lock().unwrap();
            s.client_id = Some("stable-device".into());
            s.push_identifier = Some("push.test<node".into());
            s.enable(true).unwrap();
            id = s.resume_id.clone().unwrap();
            s.transmit("one".into()).unwrap();
            s.transmit("two".into()).unwrap();
            s.handled = 7;
            s.csi.configure(256, Duration::from_secs(5), vec![]);
            s.csi.set_inactive(true);
            assert!(
                s.csi
                    .output("<presence/>".into(), "a@x", Instant::now())
                    .is_empty()
            );
        }
        h.disconnect("c1", false);
        let (tx, _rx) = mpsc::channel(8);
        assert!(h.resume("b@x", &id, 1, "c2", tx.clone()).is_err());
        let (s, replay) = h.resume("a@x", &id, 1, "c2", tx).unwrap();
        assert_eq!(
            s.lock().unwrap().client_id.as_deref(),
            Some("stable-device")
        );
        assert_eq!(
            s.lock().unwrap().push_identifier.as_deref(),
            Some("push.test<node")
        );
        assert_eq!(
            s.lock()
                .unwrap()
                .csi
                .output("<presence/>".into(), "a@x", Instant::now())
                .len(),
            1
        );
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[1], "two");
        assert!(replay[0].contains("h='7'"));
        assert!(s.lock().unwrap().acknowledge(3).is_err());
    }
    #[test]
    fn graceful_disconnect_is_not_resumable() {
        let h = Hub::default();
        let (tx, _rx) = mpsc::channel(8);
        let s = h.bind("a@x/r", "c", tx, Duration::from_secs(30)).unwrap();
        s.lock().unwrap().enable(true).unwrap();
        assert_eq!(h.disconnect("c", true), vec!["a@x/r"]);
        assert!(h.get("a@x/r").is_none());
    }
    #[test]
    fn acknowledgement_wraps() {
        let h = Hub::default();
        let (tx, _rx) = mpsc::channel(8);
        let s = h.bind("a@x/r", "c", tx, Duration::from_secs(30)).unwrap();
        let mut s = s.lock().unwrap();
        s.sm = true;
        s.sent = u32::MAX;
        s.acked = u32::MAX;
        s.transmit("x".into()).unwrap();
        s.acknowledge(0).unwrap();
        assert!(s.pending.is_empty());
    }
}

#[cfg(test)]
mod push_timeout_tests {
    use super::*;
    #[test]
    fn first_important_push_shortens_extended_hibernation_once() {
        let hub = Hub::default();
        let (tx, _rx) = mpsc::channel(8);
        let session = hub
            .bind("a@x/r", "c", tx, Duration::from_secs(72 * 3600))
            .unwrap();
        session.lock().unwrap().enable(true).unwrap();
        hub.disconnect("c", false);
        let mut s = session.lock().unwrap();
        let extended = s.expires.unwrap();
        s.first_important_push(Duration::from_secs(300));
        let first = s.expires.unwrap();
        assert!(first < extended);
        assert!(s.first_push_sent);
        s.first_important_push(Duration::from_secs(900));
        assert_eq!(s.expires.unwrap(), first);
    }
}
