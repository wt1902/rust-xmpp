#[path = "../src/tls_binding.rs"]
mod tls_binding;

use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use std::{path::Path, process::Command};
use tls_binding::server_end_point;

fn openssl(dir: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("openssl must be installed for TLS certificate tests");
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn certificate(dir: &Path, digest: &str, pss: bool) -> Vec<u8> {
    let mut args = vec![
        "req",
        "-new",
        "-x509",
        "-key",
        "key.pem",
        "-subj",
        "/CN=binding.test",
        "-days",
        "1",
        "-outform",
        "DER",
        "-out",
        "cert.der",
        digest,
    ];
    if pss {
        args.extend([
            "-sigopt",
            "rsa_padding_mode:pss",
            "-sigopt",
            "rsa_pss_saltlen:digest",
        ]);
    }
    openssl(dir, &args);
    std::fs::read(dir.join("cert.der")).unwrap()
}

#[test]
fn rsa_signature_digest_and_weak_hash_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    openssl(
        dir.path(),
        &[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            "key.pem",
        ],
    );
    for digest in ["-md5", "-sha1", "-sha224", "-sha256", "-sha384", "-sha512"] {
        let cert = certificate(dir.path(), digest, false);
        let expected = match digest {
            "-sha224" => Sha224::digest(&cert).to_vec(),
            "-sha384" => Sha384::digest(&cert).to_vec(),
            "-sha512" => Sha512::digest(&cert).to_vec(),
            _ => Sha256::digest(&cert).to_vec(),
        };
        assert_eq!(server_end_point(&cert).unwrap(), expected, "{digest}");
    }
    for digest in ["-sha1", "-sha224", "-sha256", "-sha384", "-sha512"] {
        let cert = certificate(dir.path(), digest, true);
        let expected = match digest {
            "-sha224" => Sha224::digest(&cert).to_vec(),
            "-sha384" => Sha384::digest(&cert).to_vec(),
            "-sha512" => Sha512::digest(&cert).to_vec(),
            _ => Sha256::digest(&cert).to_vec(),
        };
        assert_eq!(server_end_point(&cert).unwrap(), expected, "PSS {digest}");
    }
}

#[test]
fn ecdsa_uses_certificate_signature_hash() {
    let dir = tempfile::tempdir().unwrap();
    openssl(
        dir.path(),
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "key.pem",
        ],
    );
    let cert = certificate(dir.path(), "-sha384", false);
    assert_eq!(
        server_end_point(&cert).unwrap(),
        Sha384::digest(&cert).to_vec()
    );
    for end in 0..cert.len() {
        assert!(
            server_end_point(&cert[..end]).is_err(),
            "accepted truncation at {end}"
        );
    }
    let mut trailing = cert;
    trailing.push(0);
    assert!(server_end_point(&trailing).is_err());
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut result = vec![tag, value.len() as u8];
    result.extend(value);
    result
}
fn envelope(algorithm: &[u8]) -> Vec<u8> {
    let mut contents = tlv(0x30, &[]);
    contents.extend(tlv(0x30, algorithm));
    contents.extend(tlv(0x03, &[0, 1]));
    tlv(0x30, &contents)
}

#[test]
fn unknown_and_eddsa_algorithms_fail_closed() {
    // Ed25519/Ed448 do not get a guessed SHA-256 binding.
    for oid in [&[0x2b, 0x65, 0x70][..], &[0x2b, 0x65, 0x71], &[0x2a, 3, 4]] {
        assert!(server_end_point(&envelope(&tlv(0x06, oid))).is_err());
    }
}

#[test]
fn malformed_der_and_pss_parameters_fail_closed() {
    for bytes in [
        vec![],
        vec![0x30, 0x80, 0, 0],
        vec![0x30, 0x81, 0],
        vec![0x30, 0xff],
        vec![0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ] {
        assert!(server_end_point(&bytes).is_err());
    }
    let pss_oid = tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a");
    assert!(server_end_point(&envelope(&pss_oid)).is_err());
    let mut defaults = pss_oid.clone();
    defaults.extend(tlv(0x30, &[]));
    let cert = envelope(&defaults);
    assert_eq!(
        server_end_point(&cert).unwrap(),
        Sha256::digest(&cert).to_vec()
    );
    let hash = tlv(0x30, &tlv(0x06, b"\x60\x86\x48\x01\x65\x03\x04\x02\x02"));
    let sha384 = tlv(0xa0, &hash);
    // SHA384 with default MGF1-SHA1 has multiple hash functions.
    let mut mismatch = pss_oid.clone();
    mismatch.extend(tlv(0x30, &sha384));
    assert!(server_end_point(&envelope(&mismatch)).is_err());
    for params in [
        vec![0xa4, 0],
        vec![0xa0, 0],
        vec![0xa2, 3, 2, 1, 0xff],
        vec![0xa3, 3, 2, 1, 2],
        [sha384.clone(), sha384].concat(),
    ] {
        let mut algorithm = pss_oid.clone();
        algorithm.extend(tlv(0x30, &params));
        assert!(server_end_point(&envelope(&algorithm)).is_err());
    }
    let mut invalid_oid = tlv(0x06, &[0x80, 0x2a]);
    invalid_oid.extend([5, 0]);
    assert!(server_end_point(&envelope(&invalid_oid)).is_err());
}
