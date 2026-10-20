use anyhow::{Result, bail, ensure};
use std::collections::BTreeMap;
use tokio::io::{AsyncRead, AsyncReadExt};
const MAX: usize = 256 * 1024;
pub const STREAM_NAMESPACE: &str = "http://etherx.jabber.org/streams";
#[derive(Clone, Debug)]
pub struct StreamHeader {
    pub name: String,
    pub to: Option<String>,
    pub from: Option<String>,
    pub version: Option<String>,
    /// Empty key denotes the default namespace.
    pub namespaces: BTreeMap<String, String>,
}
impl StreamHeader {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        ensure!(
            text.starts_with('<') && !text.starts_with("</") && !text.ends_with("/>"),
            "expected open stream header"
        );
        let name =
            tag_name(text.as_bytes()).ok_or_else(|| anyhow::anyhow!("missing stream name"))?;
        ensure!(
            name.rsplit(':').next() == Some("stream"),
            "expected stream element"
        );
        let document = format!("{text}</{name}>");
        let doc = roxmltree::Document::parse(&document)?;
        let root = doc.root_element();
        ensure!(
            root.tag_name().namespace() == Some(STREAM_NAMESPACE)
                && root.tag_name().name() == "stream",
            "invalid stream namespace"
        );
        Ok(Self {
            name: name.into(),
            to: root.attribute("to").map(str::to_owned),
            from: root.attribute("from").map(str::to_owned),
            version: root.attribute("version").map(str::to_owned),
            namespaces: root
                .namespaces()
                .map(|n| (n.name().unwrap_or("").into(), n.uri().into()))
                .collect(),
        })
    }
    pub fn default_namespace(&self) -> Option<&str> {
        self.namespaces.get("").map(String::as_str)
    }
}
/// Incremental framing. Every emitted stanza must still undergo full XML validation.
#[derive(Default)]
pub struct Framer {
    pub buffer: Vec<u8>,
    pub header: Option<StreamHeader>,
}
impl Framer {
    pub fn wrap(&self, xml: &str) -> String {
        let mut out = "<root".to_owned();
        if let Some(header) = &self.header {
            for (prefix, uri) in &header.namespaces {
                if prefix == "xml" {
                    continue;
                }
                if prefix.is_empty() {
                    out.push_str(&format!(" xmlns='{}'", escape(uri)))
                } else {
                    out.push_str(&format!(" xmlns:{}='{}'", prefix, escape(uri)))
                }
            }
        }
        out.push('>');
        out.push_str(xml);
        out.push_str("</root>");
        out
    }
    pub fn is_stream_end(&self, text: &str) -> bool {
        self.header
            .as_ref()
            .is_some_and(|h| text.trim() == format!("</{}>", h.name))
    }
    pub async fn next<S: AsyncRead + Unpin>(&mut self, s: &mut S) -> Result<String> {
        loop {
            if let Some(n) = boundary(&self.buffer)? {
                let bytes: Vec<_> = self.buffer.drain(..n).collect();
                let text = String::from_utf8(bytes)?.trim().to_owned();
                if text.starts_with("<!--") {
                    let wrapped = format!("<root>{text}</root>");
                    let _ = roxmltree::Document::parse(&wrapped)?;
                    continue;
                }
                if text.starts_with("<?xml") {
                    let doc = format!("{text}<root/>");
                    let _ = roxmltree::Document::parse(&doc)?;
                    return Ok(text);
                }
                if !text.starts_with("</")
                    && tag_name(text.as_bytes())
                        .is_some_and(|n| n.rsplit(':').next() == Some("stream"))
                {
                    self.header = Some(StreamHeader::parse(&text)?);
                }
                return Ok(text);
            }
            ensure!(self.buffer.len() < MAX, "stanza too large");
            let mut chunk = [0u8; 4096];
            let n = s.read(&mut chunk).await?;
            ensure!(n > 0, "connection closed");
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }
}
fn tag_name(tag: &[u8]) -> Option<&str> {
    let start = if tag.starts_with(b"</") {
        2
    } else if tag.starts_with(b"<") {
        1
    } else {
        return None;
    };
    let end = tag[start..]
        .iter()
        .position(|b| b.is_ascii_whitespace() || *b == b'>' || *b == b'/')
        .map(|i| start + i)?;
    std::str::from_utf8(&tag[start..end]).ok()
}
fn boundary(b: &[u8]) -> Result<Option<usize>> {
    ensure!(b.len() <= MAX, "stanza too large");
    let mut i = 0;
    let mut depth = 0usize;
    while i < b.len() {
        if b[i] != b'<' {
            if depth == 0 {
                ensure!(b[i].is_ascii_whitespace(), "text outside stanza")
            }
            i += 1;
            continue;
        }
        let start = i;
        if b[i..].starts_with(b"<!--") {
            if let Some(p) = b[i + 4..].windows(3).position(|w| w == b"-->") {
                i = i + 4 + p + 3;
                if depth == 0 {
                    return Ok(Some(i));
                }
                continue;
            }
            return Ok(None);
        }
        if b[i..].starts_with(b"<![CDATA[") {
            ensure!(depth > 0, "CDATA outside stanza");
            if let Some(p) = b[i + 9..].windows(3).position(|w| w == b"]]>") {
                i = i + 9 + p + 3;
                continue;
            }
            return Ok(None);
        }
        if b[i..].starts_with(b"<!") {
            if b"<!--".starts_with(&b[i..]) || b"<![CDATA[".starts_with(&b[i..]) {
                return Ok(None);
            }
            bail!("DTD/entity declarations forbidden")
        }
        let mut quote = 0;
        i += 1;
        while i < b.len() {
            let c = b[i];
            if quote != 0 {
                if c == quote {
                    quote = 0
                }
            } else if c == b'\'' || c == b'"' {
                quote = c
            } else if c == b'>' {
                break;
            }
            i += 1
        }
        if i == b.len() {
            return Ok(None);
        }
        let end = i + 1;
        let tag = &b[start..end];
        if tag.starts_with(b"<?xml")
            && tag.get(5).is_some_and(|b| b.is_ascii_whitespace())
            && depth == 0
        {
            ensure!(tag.ends_with(b"?>"), "invalid XML declaration");
            return Ok(Some(end));
        }
        ensure!(!tag.starts_with(b"<?"), "processing instructions forbidden");
        if tag_name(tag).is_some_and(|name| name.rsplit(':').next() == Some("stream")) && depth == 0
        {
            return Ok(Some(end));
        }
        if tag.starts_with(b"</") {
            ensure!(depth > 0, "unexpected closing tag");
            depth -= 1
        } else if !tag.ends_with(b"/>") {
            depth += 1;
            ensure!(depth <= 32, "XML nesting limit")
        }
        if depth == 0 {
            return Ok(Some(end));
        }
        i = end;
    }
    Ok(None)
}
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_and_pipelined() {
        assert_eq!(boundary(b"<message><body>hi</body>").unwrap(), None);
        assert_eq!(
            boundary(b"<message><body>hi</body></message><presence/>").unwrap(),
            Some(34)
        );
    }
    #[test]
    fn declarations_rejected() {
        assert!(boundary(b"<!DOCTYPE x>").is_err());
        assert!(boundary(b"<!ENTITY x 'y'>").is_err());
    }
    #[test]
    fn cdata_and_comments_frame_without_counting_brackets() {
        let xml = b"<message><body><![CDATA[<x> & ] x]]></body><!-- <y> --></message>";
        assert_eq!(boundary(xml).unwrap(), Some(xml.len()));
        for i in 0..xml.len() {
            assert_eq!(boundary(&xml[..i]).unwrap(), None, "{i}");
        }
    }
    #[tokio::test]
    async fn arbitrary_prefix_and_inherited_namespaces() {
        let xml = "<?xml version='1.0'?><!-- hello --><s:stream xmlns='jabber:client' xmlns:s='http://etherx.jabber.org/streams' xmlns:a='urn:test' to='example.test' version='1.0'><iq id='a'><a:test/></iq></s:stream>";
        let mut input = xml.as_bytes();
        let mut f = Framer::default();
        assert!(f.next(&mut input).await.unwrap().starts_with("<?xml"));
        let header = f.next(&mut input).await.unwrap();
        assert_eq!(StreamHeader::parse(&header).unwrap().name, "s:stream");
        let stanza = f.next(&mut input).await.unwrap();
        let wrapped = f.wrap(&stanza);
        let doc = roxmltree::Document::parse(&wrapped).unwrap();
        assert!(
            doc.descendants()
                .any(|n| n.has_tag_name(("urn:test", "test")))
        );
        let end = f.next(&mut input).await.unwrap();
        assert!(f.is_stream_end(&end));
    }
    #[tokio::test]
    async fn invalid_namespace_and_declarations_rejected() {
        let mut f = Framer::default();
        let mut input = "<s:stream xmlns:s='urn:evil'>".as_bytes();
        assert!(f.next(&mut input).await.is_err());
        let mut input = "<?xml version='1.0' broken='yes'?>".as_bytes();
        assert!(Framer::default().next(&mut input).await.is_err());
    }
}
