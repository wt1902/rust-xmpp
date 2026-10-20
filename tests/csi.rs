use rust_xmpp::csi::{Buffer, important};
use std::time::{Duration, Instant};
#[test]
fn native_importance_rules() {
    for xml in [
        "<presence/>",
        "<presence type='unavailable'/>",
        "<presence type='error'/>",
        "<message><active xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message type='headline'><body>news</body></message>",
    ] {
        assert!(!important(xml, &[]), "{xml}");
    }
    for xml in [
        " ",
        "<iq/>",
        "<r xmlns='urn:xmpp:sm:3'/>",
        "<presence type='subscribe'/>",
        "<message><body/></message>",
        "<message><subject/></message>",
        "<message type='error'/>",
        "<message><encryption xmlns='urn:xmpp:eme:0'/></message>",
        "<message><propose xmlns='urn:xmpp:jingle-message:1'/></message>",
        "<message><sent xmlns='urn:xmpp:carbons:2'/></message>",
        "<message><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'><body>hey</body></message></forwarded></received></message>",
    ] {
        assert!(important(xml, &[]), "{xml}");
    }
    assert!(important(
        "<message><custom xmlns='example:ns'><part/></custom></message>",
        &["{example:ns}custom/part".into()]
    ));
}
#[test]
fn bounded_queue_flush_delay_activity_and_grace() {
    let mut b = Buffer::default();
    b.configure(2, Duration::from_secs(5), vec![]);
    b.set_inactive(true);
    let now = Instant::now();
    assert!(b.output("<presence/>".into(), "a@example", now).is_empty());
    assert!(b.output("<message/>".into(), "a@example", now).is_empty());
    let output = b.output("<presence/>".into(), "a@example", now);
    assert_eq!(output.len(), 3);
    assert!(output[0].contains("urn:xmpp:delay"));
    assert!(output[0].contains("a@example"));
    assert_eq!(b.output("<presence/>".into(), "a@example", now).len(), 1);
    assert!(
        b.output(
            "<presence/>".into(),
            "a@example",
            now + Duration::from_secs(6)
        )
        .is_empty()
    );
    assert_eq!(b.activity(now + Duration::from_secs(6)).len(), 1);
    b.set_inactive(true);
    b.output("<presence/>".into(), "a@example", now);
    assert_eq!(b.set_inactive(false).len(), 1);
    b.set_inactive(true);
    b.output("<presence/>".into(), "a@example", now);
    b.reset();
    assert!(b.activity(now).is_empty());
    assert_eq!(b.output("<presence/>".into(), "a@example", now).len(), 1);
}
