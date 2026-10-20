//! Transport-independent SCRAM exchange. Inputs/outputs are decoded SASL payloads.
//! The transport must enforce TLS and advertise only mechanisms enabled for the account store.
use crate::auth::ScramCredentials;
use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Clone, Debug)]
pub struct ChannelBinding {
    pub name: String,
    pub data: Vec<u8>,
}
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub channel_binding: Option<ChannelBinding>,
    /// Exact advertised mechanism list. None disables Prosody's SSDP extension.
    pub ssdp_mechanisms: Option<Vec<String>>,
    /// Exact supported CB types. None means the profile has no CB table.
    pub ssdp_channel_bindings: Option<Vec<String>>,
}
#[derive(Clone, Copy)]
enum Hash {
    Sha1,
    Sha256,
}
impl Hash {
    fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(bytes).to_vec(),
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
        }
    }
    fn mac(self, key: &[u8], bytes: &[u8]) -> Vec<u8> {
        macro_rules! mac {
            ($t:ty) => {{
                let mut m = Hmac::<$t>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(bytes);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            Self::Sha1 => mac!(Sha1),
            Self::Sha256 => mac!(Sha256),
        }
    }
    fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}
pub struct Scram {
    username: String,
    hash: Hash,
    credentials: ScramCredentials,
    first_bare: String,
    server_first: String,
    nonce: String,
    binding: Vec<u8>,
    eligible: bool,
}
#[derive(Debug)]
pub struct ScramSuccess {
    pub username: String,
    pub server_final: String,
}
fn unescape_name(value: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '=' {
            out.push(c);
            continue;
        }
        match (chars.next(), chars.next()) {
            (Some('2'), Some('C')) => out.push(','),
            (Some('3'), Some('D')) => out.push('='),
            _ => bail!("malformed-request"),
        }
    }
    Ok(out)
}
fn attributes(input: &str) -> Result<Vec<(&str, &str)>> {
    let mut out = Vec::new();
    for part in input.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("malformed-request"))?;
        ensure!(
            key.len() == 1
                && key.as_bytes()[0].is_ascii_alphabetic()
                && !out.iter().any(|(k, _)| *k == key),
            "malformed-request"
        );
        ensure!(key != "m", "extensions-not-supported");
        out.push((key, value));
    }
    Ok(out)
}
impl Scram {
    /// `lookup` receives the prepared username and the selected password hash name.
    pub fn start<F>(
        mechanism: &str,
        initial: &[u8],
        domain: &str,
        lookup: F,
        options: Options,
    ) -> Result<(Self, String)>
    where
        F: FnOnce(&str, &str) -> Result<Option<ScramCredentials>>,
    {
        Self::start_nonce(
            mechanism,
            initial,
            domain,
            lookup,
            options,
            &uuid::Uuid::new_v4().simple().to_string(),
        )
    }
    fn start_nonce<F>(
        mechanism: &str,
        initial: &[u8],
        domain: &str,
        lookup: F,
        options: Options,
        server_nonce: &str,
    ) -> Result<(Self, String)>
    where
        F: FnOnce(&str, &str) -> Result<Option<ScramCredentials>>,
    {
        ensure!(initial.len() <= 8192, "malformed-request");
        let (hash, hash_name, plus) = match mechanism {
            "SCRAM-SHA-1" => (Hash::Sha1, "SHA-1", false),
            "SCRAM-SHA-256" => (Hash::Sha256, "SHA-256", false),
            "SCRAM-SHA-1-PLUS" => (Hash::Sha1, "SHA-1", true),
            "SCRAM-SHA-256-PLUS" => (Hash::Sha256, "SHA-256", true),
            _ => bail!("invalid-mechanism"),
        };
        let input = std::str::from_utf8(initial)?;
        let mut parts = input.splitn(3, ',');
        let flag = parts.next().unwrap_or("");
        let authz = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("malformed-request"))?;
        let bare = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("malformed-request"))?;
        let gs2 = format!("{flag},{authz},");
        let mut binding = gs2.as_bytes().to_vec();
        if plus {
            let cb = options
                .channel_binding
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("channel-binding-not-supported"))?;
            ensure!(
                flag == format!("p={}", cb.name) && !cb.data.is_empty(),
                "unsupported-channel-binding-type"
            );
            binding.extend_from_slice(&cb.data);
        } else {
            ensure!(flag == "n" || flag == "y", "malformed-request");
            ensure!(
                flag != "y" || options.channel_binding.is_none(),
                "server-does-support-channel-binding"
            );
        }
        let attrs = attributes(bare)?;
        ensure!(
            attrs.len() >= 2 && attrs[0].0 == "n" && attrs[1].0 == "r",
            "malformed-request"
        );
        let decoded = unescape_name(attrs[0].1)?;
        let prepared = stringprep::saslprep(&decoded)
            .map_err(|_| anyhow::anyhow!("invalid-username-encoding"))?;
        let username = stringprep::nodeprep(&prepared)
            .map_err(|_| anyhow::anyhow!("invalid-username-encoding"))?
            .into_owned();
        ensure!(
            !username.is_empty() && username.len() <= 1023,
            "invalid-username-encoding"
        );
        if !authz.is_empty() {
            let az = authz
                .strip_prefix("a=")
                .ok_or_else(|| anyhow::anyhow!("malformed-request"))?;
            let az = unescape_name(az)?;
            ensure!(az == format!("{username}@{domain}"), "invalid-authzid");
        }
        let nonce = attrs[1].1;
        ensure!(
            !nonce.is_empty()
                && nonce.len() <= 1024
                && nonce
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b) && b != b','),
            "malformed-request"
        );
        let record = lookup(&username, hash_name)?;
        let eligible = record.is_some();
        // Return an ordinary challenge for unknown/disabled accounts. Never accept its proof.
        let credentials = record.unwrap_or_else(|| ScramCredentials {
            salt: uuid::Uuid::new_v4().to_string().into_bytes(),
            iterations: 10000,
            stored_key: hash.digest(uuid::Uuid::new_v4().as_bytes()),
            server_key: hash.digest(uuid::Uuid::new_v4().as_bytes()),
        });
        ensure!(
            credentials.stored_key.len() == hash.len()
                && credentials.server_key.len() == hash.len(),
            "invalid-credentials"
        );
        ensure!(
            credentials.iterations > 0
                && credentials.iterations <= 1_000_000
                && !credentials.salt.is_empty(),
            "invalid-credentials"
        );
        let nonce = format!("{nonce}{server_nonce}");
        let mut challenge = format!(
            "r={nonce},s={},i={}",
            B64.encode(&credentials.salt),
            credentials.iterations
        );
        if let Some(mut mechs) = options.ssdp_mechanisms {
            mechs.sort();
            mechs.dedup();
            let mut text = mechs.join("\u{1e}");
            if let Some(mut cb) = options.ssdp_channel_bindings {
                cb.sort();
                cb.dedup();
                text.push('\u{1f}');
                text.push_str(&cb.join("\u{1e}"));
            }
            challenge.push_str(&format!(",h={}", B64.encode(hash.digest(text.as_bytes()))));
        }
        Ok((
            Self {
                username,
                hash,
                credentials,
                first_bare: bare.into(),
                server_first: challenge.clone(),
                nonce,
                binding,
                eligible,
            },
            challenge,
        ))
    }
    /// Consumes the exchange so a proof can never be submitted twice.
    pub fn finish(self, response: &[u8]) -> Result<ScramSuccess> {
        ensure!(response.len() <= 8192, "malformed-request");
        let response = std::str::from_utf8(response)?;
        let attrs = attributes(response)?;
        ensure!(
            attrs.len() >= 3
                && attrs[0].0 == "c"
                && attrs[1].0 == "r"
                && attrs.last().unwrap().0 == "p",
            "malformed-request"
        );
        let binding = B64.decode(attrs[0].1)?;
        ensure!(
            bool::from(binding.ct_eq(&self.binding)),
            "channel-bindings-dont-match"
        );
        ensure!(attrs[1].1 == self.nonce, "nonce-mismatch");
        let proof = B64.decode(attrs.last().unwrap().1)?;
        ensure!(proof.len() == self.hash.len(), "malformed-request");
        let without = response
            .rsplit_once(",p=")
            .ok_or_else(|| anyhow::anyhow!("malformed-request"))?
            .0;
        let auth_message = format!("{},{},{}", self.first_bare, self.server_first, without);
        let signature = self
            .hash
            .mac(&self.credentials.stored_key, auth_message.as_bytes());
        let client_key: Vec<u8> = proof.iter().zip(signature).map(|(a, b)| a ^ b).collect();
        let recovered = self.hash.digest(&client_key);
        ensure!(
            bool::from(recovered.ct_eq(&self.credentials.stored_key)) && self.eligible,
            "invalid-client-proof"
        );
        let server_sig = self
            .hash
            .mac(&self.credentials.server_key, auth_message.as_bytes());
        Ok(ScramSuccess {
            username: self.username,
            server_final: format!("v={}", B64.encode(server_sig)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn credentials(hash: Hash, password: &str, salt: &[u8], iterations: u32) -> ScramCredentials {
        let mut salted = vec![0; hash.len()];
        match hash {
            Hash::Sha1 => {
                pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, iterations, &mut salted)
            }
            Hash::Sha256 => {
                pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut salted)
            }
        }
        ScramCredentials {
            salt: salt.to_vec(),
            iterations,
            stored_key: hash.digest(&hash.mac(&salted, b"Client Key")),
            server_key: hash.mac(&salted, b"Server Key"),
        }
    }
    #[test]
    fn rfc5802_sha1_vector() {
        let salt = B64.decode("QSXCR+Q6sek8bf92").unwrap();
        let c = credentials(Hash::Sha1, "pencil", &salt, 4096);
        let (exchange, challenge) = Scram::start_nonce(
            "SCRAM-SHA-1",
            b"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
            "example.com",
            |_, _| Ok(Some(c)),
            Options::default(),
            "3rfcNHYJY1ZVvWVs7j",
        )
        .unwrap();
        assert_eq!(
            challenge,
            "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
        );
        let success=exchange.finish(b"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=").unwrap();
        assert_eq!(success.username, "user");
        assert_eq!(success.server_final, "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");
    }
    #[test]
    fn sha256_independent_python_vector() {
        // Generated independently with Python hashlib.pbkdf2_hmac/hmac, password pencil.
        let c = credentials(Hash::Sha256, "pencil", b"test salt", 4096);
        let (exchange, challenge) = Scram::start_nonce(
            "SCRAM-SHA-256",
            b"n,,n=user,r=clientnonce",
            "example.com",
            |_, _| Ok(Some(c)),
            Options::default(),
            "servernonce",
        )
        .unwrap();
        assert_eq!(challenge, "r=clientnonceservernonce,s=dGVzdCBzYWx0,i=4096");
        let success = exchange
            .finish(
                b"c=biws,r=clientnonceservernonce,p=azcZj1W9+zOyKcsNxPTVP8SgNvdyoJICB///1hzW17Y=",
            )
            .unwrap();
        assert_eq!(
            success.server_final,
            "v=sfQ9BDV6Z/TTbpW9vXGpn0fUZ0N9+zgUnhGHEylidY4="
        );
    }
    #[test]
    fn reject_malformed_and_downgrade() {
        for initial in [
            "n,,m=required,n=user,r=nonce",
            "n,,n=user,n=other,r=nonce",
            "n,,n=user,r=",
            "n,a=other@example.com,n=user,r=nonce",
            "p=tls-exporter,,n=user,r=nonce",
            "n,,n=user=ZZ,r=nonce",
        ] {
            assert!(
                Scram::start(
                    "SCRAM-SHA-256",
                    initial.as_bytes(),
                    "example.com",
                    |_, _| Ok(None),
                    Options::default()
                )
                .is_err(),
                "{initial}"
            );
        }
        assert!(
            Scram::start(
                "SCRAM-SHA-256",
                b"y,,n=user,r=nonce",
                "example.com",
                |_, _| Ok(None),
                Options {
                    channel_binding: Some(ChannelBinding {
                        name: "tls-exporter".into(),
                        data: vec![1; 32]
                    }),
                    ..Options::default()
                }
            )
            .is_err()
        );
    }
    #[test]
    fn wrong_proof_nonce_binding_and_duplicates() {
        for response in [
            "c=biws,r=nonceserver,p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "c=biws,r=wrong,p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "c=eSws,r=nonceserver,p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "c=biws,r=nonceserver,r=nonceserver,p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ] {
            let c = credentials(Hash::Sha256, "password", b"salt", 4096);
            let (state, _) = Scram::start_nonce(
                "SCRAM-SHA-256",
                b"n,,n=user,r=nonce",
                "example.com",
                |_, _| Ok(Some(c)),
                Options::default(),
                "server",
            )
            .unwrap();
            assert!(state.finish(response.as_bytes()).is_err());
        }
    }
    #[test]
    fn plus_channel_binding_and_ssdp_are_authenticated() {
        let options = Options {
            channel_binding: Some(ChannelBinding {
                name: "tls-exporter".into(),
                data: vec![7; 32],
            }),
            ssdp_mechanisms: Some(vec!["PLAIN".into(), "SCRAM-SHA-256-PLUS".into()]),
            ssdp_channel_bindings: Some(vec!["tls-exporter".into()]),
        };
        let c = credentials(Hash::Sha256, "pencil", b"salt", 4096);
        let (state, challenge) = Scram::start_nonce(
            "SCRAM-SHA-256-PLUS",
            b"p=tls-exporter,,n=user,r=nonce",
            "example.com",
            |_, _| Ok(Some(c)),
            options,
            "server",
        )
        .unwrap();
        let expected_hash = B64.encode(Sha256::digest(
            b"PLAIN\x1eSCRAM-SHA-256-PLUS\x1ftls-exporter",
        ));
        assert!(challenge.ends_with(&format!(",h={expected_hash}")));
        let mut binding = b"p=tls-exporter,,".to_vec();
        binding.extend_from_slice(&[7; 32]);
        let final_without = format!("c={},r=nonceserver", B64.encode(binding));
        let auth = format!("n=user,r=nonce,{challenge},{final_without}");
        let mut salted = [0; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"pencil", b"salt", 4096, &mut salted);
        let client_key = Hash::Sha256.mac(&salted, b"Client Key");
        let signature = Hash::Sha256.mac(&Sha256::digest(&client_key), auth.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(signature)
            .map(|(a, b)| a ^ b)
            .collect();
        assert!(
            state
                .finish(format!("{final_without},p={}", B64.encode(proof)).as_bytes())
                .is_ok()
        );
    }
}
