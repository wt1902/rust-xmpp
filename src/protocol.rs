use crate::wire::escape;
#[derive(Default, Debug)]
pub struct ModuleResult {
    pub replies: Vec<String>,
    /// (destination full or bare JID, serialized stanza)
    pub deliveries: Vec<(String, String)>,
}
impl ModuleResult {
    pub fn reply(xml: String) -> Self {
        Self {
            replies: vec![xml],
            deliveries: vec![],
        }
    }
}
pub fn iq_result(iq: roxmltree::Node<'_, '_>, payload: &str) -> String {
    let id = escape(iq.attribute("id").unwrap_or(""));
    let from = iq
        .attribute("to")
        .map(|v| format!(" from='{}'", escape(v)))
        .unwrap_or_default();
    format!("<iq xmlns='jabber:client' type='result' id='{id}'{from}>{payload}</iq>")
}
pub fn iq_error(iq: roxmltree::Node<'_, '_>, condition: &str) -> String {
    let id = escape(iq.attribute("id").unwrap_or(""));
    let from = iq
        .attribute("to")
        .map(|v| format!(" from='{}'", escape(v)))
        .unwrap_or_default();
    let payload = iq.first_element_child().map(xml).unwrap_or_default();
    format!(
        "<iq xmlns='jabber:client' type='error' id='{id}'{from}>{payload}<error type='cancel'><{condition} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
    )
}
/// Re-serialize a subtree, explicitly preserving namespace bindings.
pub fn xml(node: roxmltree::Node<'_, '_>) -> String {
    xml_namespace(node, None)
}
pub fn xml_namespace(node: roxmltree::Node<'_, '_>, mapping: Option<(&str, &str)>) -> String {
    serialize(node, mapping, None)
}
pub fn address(node: roxmltree::Node<'_, '_>, from: &str, to: &str) -> String {
    serialize(node, None, Some((from, to)))
}
fn serialize(
    node: roxmltree::Node<'_, '_>,
    mapping: Option<(&str, &str)>,
    addresses: Option<(&str, &str)>,
) -> String {
    if node.is_text() {
        return escape(node.text().unwrap_or(""));
    }
    if !node.is_element() {
        return String::new();
    }
    let tag = node.tag_name();
    let prefix = tag.namespace().and_then(|ns| node.lookup_prefix(ns));
    let name = prefix
        .map(|p| format!("{p}:{}", tag.name()))
        .unwrap_or_else(|| tag.name().to_owned());
    let mut out = format!("<{name}");
    for ns in node.namespaces() {
        let uri = if let Some((from, to)) = mapping {
            if ns.uri() == from { to } else { ns.uri() }
        } else {
            ns.uri()
        };
        if ns.name() == Some("xml") {
            continue;
        }
        match ns.name() {
            Some(p) => out.push_str(&format!(" xmlns:{p}='{}'", escape(uri))),
            None => out.push_str(&format!(" xmlns='{}'", escape(uri))),
        }
    }
    for a in node.attributes() {
        if addresses.is_some() && a.namespace().is_none() && matches!(a.name(), "from" | "to") {
            continue;
        }
        let name = match a.namespace() {
            Some("http://www.w3.org/XML/1998/namespace") => format!("xml:{}", a.name()),
            Some(ns) => node
                .lookup_prefix(ns)
                .map(|p| format!("{p}:{}", a.name()))
                .unwrap_or_else(|| a.name().into()),
            None => a.name().into(),
        };
        out.push_str(&format!(" {name}='{}'", escape(a.value())));
    }
    if let Some((from, to)) = addresses {
        out.push_str(&format!(" from='{}' to='{}'", escape(from), escape(to)));
    }
    out.push('>');
    for child in node.children() {
        out.push_str(&serialize(child, mapping, None));
    }
    out.push_str(&format!("</{name}>"));
    out
}
pub fn bare(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}
