#!/usr/bin/env python3
"""A damaged MAM redo baseline must not take down the live message session.

Usage: python3 tests/mam_broken_baseline_network.py target/release/rust-xmpp

Reproduces the production symptom reported with Monal/Luma: the native archive at
`data/<host>/archive/<user>.list` no longer matches the anchor recorded in its
`.rredo` journal ("archive redo baseline changed in place"). On every message the
previous build drained the session or stalled delivery for seconds, so the client
timed out MAM and its message was delayed.

Prosody has no `.rredo` sidecar: it simply appends to the native `.list`. This
test seeds an archive for `load-0`, corrupts its redo baseline offline to force
that recovery error, then verifies that:
  * a fresh message is still routed load-0 -> load-1 quickly,
  * BOTH sessions survive (ping round-trip), no `connection-closed`,
  * the runtime self-repairs: on the first access it retires the untrusted
    journal, adopts the synced native as authoritative (exactly what Prosody
    would treat as the archive), and continues appending on a fresh journal
    without requiring an offline `storage-checkpoint` handoff,
  * MAM history reads succeed on the recovered archive.
"""

import argparse
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from _wire_client import Client, local

REDO_MAGIC = b"XARRED01"
REDO_HEADER = 96
BODY = "must-survive-broken-baseline"


def start(binary, config, port, log):
    server = subprocess.Popen(
        [binary, "serve", str(config), "--experimental"], stdout=log, stderr=log
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        assert server.poll() is None, "server stopped during startup"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return server
        except OSError:
            time.sleep(0.05)
    server.kill()
    server.wait()
    raise AssertionError("server did not start")


def stop(server):
    server.terminate()
    try:
        code = server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()
        raise AssertionError("SIGTERM did not complete orderly shutdown")
    assert code == 0, f"SIGTERM shutdown exited {code}"


def corrupt_baseline(path):
    """Force the `archive redo baseline changed in place` recovery error.

    Rebuilds a rotated-style journal header leaving the native file untouched:
    the header records the native length as a non-empty baseline but stores a
    wrong anchor. `recover_redo` then rejects it exactly as when an external
    writer rewrote the native file in place after the journal rotated.
    """
    native = path.read_bytes()
    length = len(native)
    assert length > 0, "seed produced an empty native MAM archive"
    header = bytearray(REDO_HEADER)
    header[:8] = REDO_MAGIC
    header[8:16] = length.to_bytes(8, "little")
    header[16:32] = b"\0" * 16  # dev/ino are only a cache identity, not validated
    tail = native[-min(length, 4096) :]
    real_anchor = hashlib.sha256(tail).digest()
    wrong = bytearray(real_anchor)
    wrong[0] ^= 0xFF
    header[32:64] = wrong
    header[64:96] = hashlib.sha256(header[:64]).digest()
    path.with_suffix(".rredo").write_bytes(header)
    assert hashlib.sha256(header[:64]).digest() == header[64:96], (
        "rebuilt header checksum"
    )
    assert header[32:64] != real_anchor, "anchor did not diverge from native"


def run(binary):
    with tempfile.TemporaryDirectory(prefix="xmpp-mam-broken-") as tmp:
        root = Path(tmp)
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                str(root / "key.pem"),
                "-out",
                str(root / "cert.pem"),
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        config = root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "global": {
                        "data_path": str(root / "data"),
                        "interfaces": ["127.0.0.1"],
                        "c2s_ports": [port],
                        "s2s_ports": [],
                        "http_ports": [],
                        "https_ports": [],
                        "modules_enabled": [
                            "tls",
                            "saslauth",
                            "smacks",
                            "ping",
                            "mam",
                            "carbons",
                        ],
                        "smacks_hibernation_time": 600,
                        "archive_expires_after": "never",
                        "default_archive_policy": True,
                        "ssl": {
                            "key": str(root / "key.pem"),
                            "certificate": str(root / "cert.pem"),
                        },
                    },
                    "hosts": {
                        "localhost": {
                            "options": {
                                "authentication": "internal_hashed",
                                "password_hash": "SHA-256",
                            }
                        }
                    },
                }
            )
        )
        for number in range(2):
            subprocess.run(
                [
                    binary,
                    "create-user",
                    str(config),
                    f"load-{number}",
                    "--password-stdin",
                ],
                input="load-test-password\n",
                text=True,
                check=True,
                capture_output=True,
            )

        with (root / "server.log").open("w+") as log:
            server = None
            try:
                # Seed: leave a real, valid MAM entry for load-0 so its archive
                # carries a genuine .list + .rredo pair with a non-zero baseline.
                server = start(binary, config, port, log)
                alice = Client(
                    port, root / "cert.pem", "load-0", "load-test-password", "desktop"
                )
                bob = Client(
                    port, root / "cert.pem", "load-1", "load-test-password", "desktop"
                )
                alice.available()
                bob.available()
                alice.send(
                    f"<message to='{bob.jid}' type='chat' id='seed'><body>seed</body></message>"
                )
                bob.body("seed")
                alice.sync()
                stop(server)
                server = None
                for client in (alice, bob):
                    client.close()
            finally:
                if server is not None and server.poll() is None:
                    server.kill()
                    server.wait()

        # The sender localpart is percent-encoded on disk (`load-0` -> `load%2d0`).
        sender_archive = root / "data" / "localhost" / "archive" / "load%2d0.list"
        assert sender_archive.exists(), "seed did not create load-0 MAM archive"
        assert sender_archive.with_suffix(".rredo").exists(), (
            "seed did not attach load-0 redo journal"
        )
        corrupt_baseline(sender_archive)
        damaged_journal = sender_archive.with_suffix(".rredo").read_bytes()

        with (root / "server.log").open("a") as log:
            server = None
            try:
                server = start(binary, config, port, log)
                alice = Client(
                    port, root / "cert.pem", "load-0", "load-test-password", "desktop"
                )
                bob = Client(
                    port, root / "cert.pem", "load-1", "load-test-password", "desktop"
                )
                alice.available()
                bob.available()
                # A damaged MAM baseline must not drop the dispatch: deliver and
                # keep both sessions alive.
                alice.send(
                    f"<message to='{bob.jid}' type='chat' id='live'><body>{BODY}</body></message>"
                )
                bob.body(BODY)
                # Ping round-trips prove neither session was closed by the archive fault.
                alice.sync()
                bob.sync()
                alice.send(
                    f"<message to='{bob.jid}' type='chat' id='second'><body>second</body></message>"
                )
                bob.body("second")
                alice.sync()
                bob.sync()
            finally:
                if server is not None and server.poll() is None:
                    server.kill()
                    server.wait()

        log_text = (root / "server.log").read_text()
        assert not any(
            "connection-closed" in l and "protocol-or-transport-error" in l
            for l in log_text.splitlines()
        ), "a session was closed by the archive fault"
        assert not any("session-error-label" in l for l in log_text.splitlines()), (
            "unhandled archive fault labelled a session error"
        )

        # Prosody-compatible self-repair: the first access after the corruption
        # retired the untrusted journal and the archive was appended to on a fresh
        # journal. No `mam-archive-skipped` should have been logged because the
        # event delivery succeeded on the recovered native.
        assert not any("mam-archive-skipped" in l for l in log_text.splitlines())

        # A fresh journal must have replaced the damaged one (the archive kept
        # accepting records). Its baseline now matches the current native.
        journal = sender_archive.with_suffix(".rredo")
        assert journal.exists(), "runtime did not recreate a fresh redo journal"
        assert journal.read_bytes() != damaged_journal, (
            "runtime kept the damaged journal instead of retiring it"
        )
        fresh = journal.read_bytes()
        assert len(fresh) >= REDO_HEADER
        assert fresh[:8] == REDO_MAGIC
        # The fresh journal is valid: its header digest checks out, so recovery
        # will accept it as the authoritative pairing with the current native.
        assert hashlib.sha256(fresh[:64]).digest() == fresh[64:96], (
            "recreated journal header is not self-consistent"
        )

        # MAM history on the recovered, now-authoritative native must serve reads.
        phase3_offset = len((root / "server.log").read_text().splitlines())
        with (root / "server.log").open("a") as log:
            server = None
            try:
                server = start(binary, config, port, log)
                alice = Client(
                    port, root / "cert.pem", "load-0", "load-test-password", "desktop"
                )
                bob = Client(
                    port, root / "cert.pem", "load-1", "load-test-password", "desktop"
                )
                alice.available()
                bob.available()
                # A MAM query to load-0's own archive must serve history.
                alice.send(
                    f"<iq type='set' id='mam' to='load-0@localhost'>"
                    f"<query xmlns='urn:xmpp:mam:2'/>"
                    f"<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'>"
                    f"<value>urn:xmpp:mam:2</value></field></x></iq>"
                )
                result_iq = alice.iq("mam")
                assert (
                    result_iq.find(
                        ".//{urn:ietf:params:xml:ns:xmpp-stanzas}internal-server-error"
                    )
                    is None
                ), ET.tostring(result_iq)
                # A new message still archives cleanly on the recovered journal.
                alice.send(
                    f"<message to='{bob.jid}' type='chat' id='post-repair'><body>post-repair</body></message>"
                )
                bob.body("post-repair")
                alice.sync()
            finally:
                if server is not None and server.poll() is None:
                    server.kill()
                    server.wait()

        post_log = (root / "server.log").read_text().splitlines()[phase3_offset:]
        fresh_errors = [
            l for l in post_log if "archive redo baseline changed in place" in l
        ]
        assert not fresh_errors, (
            "archive fault returned after self-repair:\n" + "\n".join(fresh_errors)
        )

        # Offline handoff stays safe: checkpoint of an already-repaired archive is
        # idempotent (retires an absent journal) and still reports a handoff.
        result = subprocess.run(
            [binary, "storage-checkpoint", str(config)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "Durable native archive handoff:" in result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/rust-xmpp")
    args = parser.parse_args()
    run(args.binary)
    print("PASS: damaged MAM redo baseline does not drop live message delivery")


if __name__ == "__main__":
    main()
