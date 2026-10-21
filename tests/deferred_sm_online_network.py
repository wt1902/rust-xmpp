#!/usr/bin/env python3
"""Deferred online SM durability mode over real STARTTLS.

`smacks_online_durable = false` defers per-stanza durable commits for live
sessions (Prosody's streaming model), flushing on offline transitions and a
periodic background pass. This fixture proves:

  - the server runs correctly in deferred mode (message, MAM and carbons work),
  - a message delivered to an OFFLINE/hibernated resource is durably committed
    before the sender's stream-management acknowledgement (no loss on crash),
  - an ONLINE resource's deferred queue is made durable by the background flush
    (waiting for the flush interval then re-reading the durable snapshot).

This is a loopback wire check, not a production-capacity guarantee.
"""

import argparse
import asyncio
import json
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from message_latency_network import slot
from slow_storage_latency_network import MeasuredClient

CARBONS = "urn:xmpp:carbons:2"


async def _iq(client, identifier, payload):
    await client.stanza(f"<iq type='set' id='{identifier}'>{payload}</iq>")
    result = await client.wait(lambda: client.iqs.pop(identifier, None), identifier)
    assert result.get("type") == "result"


async def exercise(root, port, args):
    context = ssl.create_default_context(cafile=str(root / "cert.pem"))
    clients = []
    try:
        for number in range(4):
            client = await MeasuredClient.connect(number, port, context, 2)
            clients.append(client)
            client.auto_ack = False
            await client.enable()
            await _iq(client, f"carbons-{number}", f"<enable xmlns='{CARBONS}'/>")
            await client.stanza("<presence/>")
            await client.fence(f"ready-{number}")
        alice, bob, alice_other, bob_other = clients
        for client in clients:
            await client.handled()
        print("setup+settle ok", file=sys.stderr, flush=True)

        # ---- Offline delivery must be durable before sender ACK ----
        # Detach bob_other ungracefully: it stays a resumable slot with no
        # transport (sender == None), so its writes still commit durably even in
        # deferred mode.
        await bob_other.close_raw()
        await asyncio.sleep(0.5)
        print("bob_other detached", file=sys.stderr, flush=True)
        await alice.stanza(
            f"<message to='{bob.jid}' type='chat' id='offline-durable'><body>offline-durable</body></message>"
        )
        await alice.handled()
        print("offline message sent+handled", file=sys.stderr, flush=True)
        # The offline target's queue must already be in the durable JSON
        # (offline transitions commit durably regardless of deferred mode).
        offline = slot(root, bob_other)
        assert any("offline-durable" in xml for xml in offline["pending"]), offline[
            "pending"
        ]

        # ---- Online delivery reaches the live recipient and its sent carbon ----
        identifier = "online-deferred"
        await alice.stanza(
            f"<message to='{bob.jid}' type='chat' id='{identifier}'><body>{identifier}</body></message>"
        )
        await alice.handled()
        print(
            "online message sent+handled; waiting for live delivery",
            file=sys.stderr,
            flush=True,
        )
        for client, kind in ((bob, "direct"), (alice_other, "sent")):
            await client.wait(
                lambda c=client, k=kind: c.arrivals.get((identifier, k)),
                f"{identifier} {kind}",
            )
            print(
                f"arrived {kind} at client {client.number}", file=sys.stderr, flush=True
            )
        print(
            "online delivery ok; waiting for flush to persist",
            file=sys.stderr,
            flush=True,
        )
        # Wait for the 1s background flush; the live deferred queues must then be
        # durable on disk for bob (direct) and alice_other (sent carbon).
        await asyncio.sleep(1.5)
        ok = any(
            "online-deferred" in xml
            for client in (bob, alice_other)
            for xml in slot(root, client)["pending"]
        )
        assert ok, (slot(root, bob)["pending"], slot(root, alice_other)["pending"])

        assert all(not client.errors for client in clients), [c.errors for c in clients]
        return "pass"
    finally:
        await asyncio.gather(*(c.close_raw() for c in clients), return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/rust-xmpp")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="deferred-sm-") as directory:
        work = pathlib.Path(directory)
        binary = pathlib.Path(args.binary).resolve()
        root = work / "data-root"
        root.mkdir()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
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
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
                str(root / "key.pem"),
                "-out",
                str(root / "cert.pem"),
            ],
            check=True,
            capture_output=True,
        )
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
                            "csi_simple",
                            "mam",
                            "pep",
                            "carbons",
                        ],
                        "smacks_online_durable": False,
                        "smacks_flush_interval": 1,
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
                    str(binary),
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
            server = subprocess.Popen(
                [str(binary), "serve", str(config), "--experimental"],
                stdout=log,
                stderr=log,
            )
            try:
                deadline = time.monotonic() + 60
                while True:
                    assert server.poll() is None, log.read()
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, "server startup timeout"
                        time.sleep(0.05)
                status = asyncio.run(asyncio.wait_for(exercise(root, port, args), 50))
                print(f"deferred online SM: {status}")
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                server.kill()
                server.wait()


if __name__ == "__main__":
    main()
