//! RFC 5929 `tls-server-end-point` for an already validated leaf certificate.
//!
//! This only reads the outer Certificate/AlgorithmIdentifier envelope, not X.509
//! names, extensions, keys, or signatures. Certificate validation belongs to TLS.
//! RFC 9266 adds `tls-exporter`; it does not redefine this certificate digest.

use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hash {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// Hash the exact DER leaf certificate according to its outer signature algorithm.
/// Unsupported algorithms (including EdDSA) and malformed envelopes return errors;
/// there is deliberately no fallback to an arbitrary digest.
pub fn server_end_point(cert_der: &[u8]) -> Result<Vec<u8>> {
    let mut input = Der(cert_der);
    let mut certificate = Der(input.take(0x30)?);
    input.finish()?;
    certificate.take(0x30)?; // TBSCertificate is opaque to this envelope parser.
    let algorithm = certificate.take(0x30)?;
    let signature = certificate.take(0x03)?;
    ensure!(
        signature.len() > 1 && signature[0] == 0,
        "invalid certificate signature BIT STRING"
    );
    certificate.finish()?;
    let (oid, params) = algorithm_identifier(algorithm)?;
    let hash = if oid == b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a" {
        pss_hash(params)?
    } else {
        // RSA PKCS#1 v1.5 signature identifiers.
        let hash = match oid {
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04" => Hash::Md5,
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05" | b"\x2b\x0e\x03\x02\x1d" => Hash::Sha1,
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e" => Hash::Sha224,
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b" => Hash::Sha256,
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c" => Hash::Sha384,
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d" => Hash::Sha512,
            // DSA and ECDSA signature identifiers.
            b"\x2a\x86\x48\xce\x38\x04\x03" | b"\x2a\x86\x48\xce\x3d\x04\x01" => Hash::Sha1,
            b"\x60\x86\x48\x01\x65\x03\x04\x03\x01" | b"\x2a\x86\x48\xce\x3d\x04\x03\x01" => {
                Hash::Sha224
            }
            b"\x60\x86\x48\x01\x65\x03\x04\x03\x02" | b"\x2a\x86\x48\xce\x3d\x04\x03\x02" => {
                Hash::Sha256
            }
            b"\x60\x86\x48\x01\x65\x03\x04\x03\x03" | b"\x2a\x86\x48\xce\x3d\x04\x03\x03" => {
                Hash::Sha384
            }
            b"\x60\x86\x48\x01\x65\x03\x04\x03\x04" | b"\x2a\x86\x48\xce\x3d\x04\x03\x04" => {
                Hash::Sha512
            }
            _ => bail!("unsupported certificate signature algorithm for tls-server-end-point"),
        };
        null_or_absent(params)?;
        hash
    };
    Ok(match hash {
        Hash::Md5 | Hash::Sha1 | Hash::Sha256 => Sha256::digest(cert_der).to_vec(),
        Hash::Sha224 => Sha224::digest(cert_der).to_vec(),
        Hash::Sha384 => Sha384::digest(cert_der).to_vec(),
        Hash::Sha512 => Sha512::digest(cert_der).to_vec(),
    })
}

type AlgorithmIdentifier<'a> = (&'a [u8], Option<(u8, &'a [u8])>);

fn algorithm_identifier(bytes: &[u8]) -> Result<AlgorithmIdentifier<'_>> {
    let mut der = Der(bytes);
    let oid = der.take(0x06)?;
    ensure!(!oid.is_empty(), "empty algorithm OID");
    // Reject noncanonical/truncated base-128 OID components.
    let mut start = true;
    for &byte in oid {
        ensure!(!start || byte != 0x80, "noncanonical algorithm OID");
        start = byte & 0x80 == 0;
    }
    ensure!(start, "truncated algorithm OID");
    let params = if der.0.is_empty() {
        None
    } else {
        Some(der.any()?)
    };
    der.finish()?;
    Ok((oid, params))
}

fn null_or_absent(params: Option<(u8, &[u8])>) -> Result<()> {
    ensure!(
        params.is_none() || params == Some((0x05, &[])),
        "invalid algorithm parameters"
    );
    Ok(())
}

fn hash_algorithm(bytes: &[u8]) -> Result<Hash> {
    let (oid, params) = algorithm_identifier(bytes)?;
    null_or_absent(params)?;
    Ok(match oid {
        b"\x2b\x0e\x03\x02\x1a" => Hash::Sha1,
        b"\x60\x86\x48\x01\x65\x03\x04\x02\x04" => Hash::Sha224,
        b"\x60\x86\x48\x01\x65\x03\x04\x02\x01" => Hash::Sha256,
        b"\x60\x86\x48\x01\x65\x03\x04\x02\x02" => Hash::Sha384,
        b"\x60\x86\x48\x01\x65\x03\x04\x02\x03" => Hash::Sha512,
        _ => bail!("unsupported RSA-PSS hash algorithm"),
    })
}

fn explicit_sequence(bytes: &[u8]) -> Result<&[u8]> {
    let mut der = Der(bytes);
    let value = der.take(0x30)?;
    der.finish()?;
    Ok(value)
}

fn pss_hash(params: Option<(u8, &[u8])>) -> Result<Hash> {
    let Some((0x30, bytes)) = params else {
        bail!("missing or invalid RSA-PSS parameters")
    };
    let mut der = Der(bytes);
    let mut hash = Hash::Sha1;
    let mut mgf_hash = Hash::Sha1;
    let mut previous = 0x9f;
    while !der.0.is_empty() {
        let (tag, value) = der.any()?;
        ensure!(
            (0xa0..=0xa3).contains(&tag) && tag > previous,
            "invalid RSA-PSS parameter order"
        );
        previous = tag;
        match tag {
            0xa0 => hash = hash_algorithm(explicit_sequence(value)?)?,
            0xa1 => {
                let (oid, params) = algorithm_identifier(explicit_sequence(value)?)?;
                ensure!(
                    oid == b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08",
                    "unsupported RSA-PSS mask generation algorithm"
                );
                let Some((0x30, hash_params)) = params else {
                    bail!("invalid MGF1 parameters")
                };
                mgf_hash = hash_algorithm(hash_params)?;
            }
            0xa2 | 0xa3 => {
                let mut integer = Der(value);
                let bytes = integer.take(0x02)?;
                integer.finish()?;
                ensure!(
                    !bytes.is_empty() && bytes[0] & 0x80 == 0,
                    "invalid RSA-PSS integer"
                );
                ensure!(
                    bytes.len() == 1 || bytes[0] != 0 || bytes[1] & 0x80 != 0,
                    "noncanonical RSA-PSS integer"
                );
                if tag == 0xa3 {
                    ensure!(bytes == [1], "unsupported RSA-PSS trailer field");
                }
            }
            _ => unreachable!(),
        }
    }
    // RFC 5929 leaves signatures using multiple hash functions undefined.
    ensure!(hash == mgf_hash, "RSA-PSS uses multiple hash functions");
    Ok(hash)
}

/// Nonrecursive, zero-copy DER TLV reader. Length arithmetic is bounded by input.
struct Der<'a>(&'a [u8]);
impl<'a> Der<'a> {
    fn any(&mut self) -> Result<(u8, &'a [u8])> {
        ensure!(self.0.len() >= 2, "truncated DER header");
        let tag = self.0[0];
        ensure!(tag & 0x1f != 0x1f && tag != 0, "unsupported DER tag");
        let first = self.0[1];
        let mut offset = 2;
        let length = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            ensure!(
                count > 0 && count <= std::mem::size_of::<usize>(),
                "invalid DER length"
            );
            ensure!(
                count <= self.0.len() - offset && self.0[offset] != 0,
                "truncated or noncanonical DER length"
            );
            let mut length = 0usize;
            for &byte in &self.0[offset..offset + count] {
                length = length
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(usize::from(byte)))
                    .ok_or_else(|| anyhow::anyhow!("DER length overflow"))?;
            }
            offset += count;
            ensure!(length >= 128, "noncanonical DER length");
            length
        };
        ensure!(length <= self.0.len() - offset, "truncated DER value");
        let (value, rest) = self.0[offset..].split_at(length);
        self.0 = rest;
        Ok((tag, value))
    }
    fn take(&mut self, expected: u8) -> Result<&'a [u8]> {
        let (tag, value) = self.any()?;
        ensure!(tag == expected, "unexpected DER tag");
        Ok(value)
    }
    fn finish(&self) -> Result<()> {
        ensure!(self.0.is_empty(), "trailing DER data");
        Ok(())
    }
}
