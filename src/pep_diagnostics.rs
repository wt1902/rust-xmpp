//! Payload-shape diagnostics. Values are fixed classifications and counts;
//! account names, node names, item identifiers and key material stay private.
use std::collections::BTreeSet;

const EVENT: &str = "http://jabber.org/protocol/pubsub#event";
const LEGACY: &str = "eu.siacs.conversations.axolotl";
const OMEMO2: &str = "urn:xmpp:omemo:2";

/// Inspect the first direct item in an IQ or event `items` wrapper.
pub fn item_fields(items: roxmltree::Node<'_, '_>) -> Vec<(&'static str, String)> {
    let payload = items
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == "item"
                && n.tag_name().namespace() == items.tag_name().namespace()
        })
        .and_then(|n| n.first_element_child());
    let protocol = match payload.map(|n| (n.tag_name().namespace(), n.tag_name().name())) {
        Some((Some(LEGACY), "list")) => "legacy",
        Some((Some(OMEMO2), "devices")) => "omemo2",
        _ => "other",
    };
    let mut valid = BTreeSet::new();
    let mut invalid = 0;
    if protocol != "other" {
        for device in payload
            .unwrap()
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "device")
        {
            // Conversations' parser checks the local name, then uses Java
            // Integer.valueOf; it does not trim or restrict IDs to positive values.
            if let Some(id) = device.attribute("id").and_then(java_integer) {
                valid.insert(id);
            } else {
                invalid += 1;
            }
        }
    }
    vec![
        ("device_protocol", protocol.into()),
        ("valid_device_count", valid.len().to_string()),
        ("invalid_device_count", invalid.to_string()),
    ]
}

/// Inspect outgoing PEP item notifications without disclosing stanza values.
pub fn event_fields(message: roxmltree::Node<'_, '_>) -> Option<Vec<(&'static str, String)>> {
    if message.tag_name().name() != "message" {
        return None;
    }
    let event = message
        .children()
        .find(|n| n.has_tag_name((EVENT, "event")))?;
    let items = event
        .children()
        .find(|n| n.has_tag_name((EVENT, "items")))?;
    let node_kind = match items.attribute("node") {
        Some("eu.siacs.conversations.axolotl.devicelist" | "urn:xmpp:omemo:2:devices") => {
            "omemo-devices"
        }
        Some("urn:xmpp:avatar:metadata") => "avatar-metadata",
        Some("urn:xmpp:avatar:data") => "avatar-data",
        _ => "other",
    };
    let mut direct_items = items.children().filter(|n| n.has_tag_name((EVENT, "item")));
    let content_present = direct_items
        .next()
        .is_some_and(|n| n.first_element_child().is_some());
    let items_count = items
        .children()
        .filter(|n| n.has_tag_name((EVENT, "item")))
        .count();
    let mut fields = vec![
        ("node_kind", node_kind.into()),
        ("items_count", items_count.to_string()),
        ("content_present", content_present.to_string()),
    ];
    fields.extend(item_fields(items));
    Some(fields)
}

// Java Integer.parseInt accepts BMP decimal digits through Character.digit(char,
// 10), but rejects supplementary digits because it processes UTF-16 code units.
fn java_integer(value: &str) -> Option<i32> {
    let (negative, digits) = if let Some(v) = value.strip_prefix('-') {
        (true, v)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    if digits.is_empty() {
        return None;
    }
    let limit = if negative {
        2_147_483_648_i64
    } else {
        2_147_483_647
    };
    let mut number = 0_i64;
    for digit in digits.chars() {
        let code = digit as u32;
        let zero = [
            0x0030, 0x0660, 0x06f0, 0x07c0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0be6, 0x0c66,
            0x0ce6, 0x0d66, 0x0de6, 0x0e50, 0x0ed0, 0x0f20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946,
            0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0,
            0xa9f0, 0xaa50, 0xabf0, 0xff10,
        ]
        .into_iter()
        .find(|zero| code >= *zero && code < *zero + 10)?;
        number = number * 10 + i64::from(code - zero);
        if number > limit {
            return None;
        }
    }
    Some(if negative { -number } else { number } as i32)
}
