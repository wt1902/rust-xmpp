#!/usr/bin/env python3
"""Measure real STARTTLS direct/MUC delivery with durable SM and CSI.

Usage: python3 tests/message_latency_network.py --binary target/release/rust-xmpp
Reports loopback median/p95/max, not a production latency guarantee. There are
no millisecond performance assertions: bounded delivery, exact counts, SM
counters and durable CSI buffering/urgent flush are the regression assertions.
The source executable is copied before testing so concurrent rebuilds are safe.
"""
import argparse
import asyncio
import collections
import datetime
import hashlib
import json
import pathlib
import shutil
import socket
import ssl
import statistics
import subprocess
import tempfile
import time

from muc_sm_load_network import Client, MUC, start
from muc_restart_network import stop


class TimedBodies(collections.Counter):
    def __init__(self):
        super().__init__()
        self.arrivals = {}

    def __setitem__(self, key, value):
        self.arrivals.setdefault(key, time.perf_counter())
        super().__setitem__(key, value)


def distribution(values):
    values = sorted(value * 1000 for value in values)
    return {'samples': len(values), 'median_ms': statistics.median(values),
            'p95_ms': values[min(len(values) - 1, int(len(values) * .95))],
            'max_ms': values[-1], 'samples_ms': values}


async def bounded(operation):
    # A functional timeout, deliberately much wider than a performance budget.
    return await asyncio.wait_for(operation, 20)


async def body(client, text):
    await bounded(client.wait(lambda: client.bodies[text] == 1, text))
    return client.bodies.arrivals[text]


def slot(root, client):
    paths = list((root / 'data').rglob(client.token + '.json'))
    assert len(paths) == 1, 'missing or duplicate durable SM record'
    return json.loads(paths[0].read_text())


async def queued(root, client, text):
    # Observe persisted queue state instead of assuming a short socket timeout
    # proves buffering. Bob sends no input/acks that could flush CSI here.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        record = slot(root, client)
        if any(text in xml for xml in record['csi']['queue']):
            assert client.bodies[text] == 0, 'buffered message leaked onto wire'
            return
        assert client.bodies[text] == 0, 'inactive CSI failed to hold headline'
        await asyncio.sleep(.01)
    raise AssertionError('headline did not enter durable CSI queue')


async def csi_state(root, client, state):
    # Alternate first so persisted state proves this exact control was handled,
    # including resetting any temporary flushing window. A ping on the receiver
    # would itself cause CSI activity and invalidate the buffering experiment.
    for target in (state != 'inactive', state == 'inactive'):
        await client.send(f"<{'inactive' if target else 'active'} xmlns='urn:xmpp:csi:0'/>")
        deadline = time.monotonic() + 20
        while slot(root, client)['csi']['inactive'] != target:
            assert time.monotonic() < deadline, 'CSI state was not durably handled'
            await asyncio.sleep(.001)


async def exercise(root, port, rounds, archive, history_records):
    context = ssl.create_default_context(cafile=str(root / 'cert.pem'))
    clients = []
    report = {'mam_enabled': archive, 'sm_enabled': True, 'rounds': rounds,
              'seeded_muc_archive_records': history_records if archive else 0}
    try:
        for number in range(2):
            client = await bounded(Client.connect(number, port, context, 2))
            clients.append(client)
            client.bodies = TimedBodies()
            # Explicit acks between samples avoid racing inbound ack activity
            # with inactive-CSI assertions. SM remains enabled throughout.
            client.auto_ack = False
            await bounded(client.enable())
            await client.stanza('<presence/>')
            await bounded(client.fence(f'connected-{number}'))
            await client.ack()
        alice, bob = clients
        room = 'latency@rooms.localhost'
        for client in clients:
            await client.stanza(f"<presence to='{room}/Nick-{client.number}'><x xmlns='{MUC}'><history maxstanzas='0'/></x></presence>")
            await bounded(client.wait(lambda c=client: c.presences.get(f'{room}/Nick-{c.number}'), 'MUC self presence'))
            assert client.presences[f'{room}/Nick-{client.number}'].get('type') != 'error'
        for client in clients:
            await bounded(client.fence(f'joined-{client.number}'))
            await client.ack()

        for state in ('active', 'inactive'):
            measurements = collections.defaultdict(list)
            for turn in range(rounds):
                # Reset CSI immediately before each sample: an important output
                # opens a configured temporary flushing window for later output.
                await csi_state(root, bob, state)
                text = f'{state}-direct-{turn}'
                begun = time.perf_counter()
                await alice.stanza(f"<message to='{bob.jid}' type='chat'><body>{text}</body></message>")
                arrived = await body(bob, text)
                measurements['direct_peer'].append(arrived - begun)
                reply = text + '-reply'
                await bob.stanza(f"<message to='{alice.jid}' type='chat'><body>{reply}</body></message>")
                measurements['direct_application_rtt'].append(await body(alice, reply) - begun)
                await csi_state(root, bob, state)
                text = f'{state}-muc-{turn}'
                begun = time.perf_counter()
                await alice.stanza(f"<message to='{room}' type='groupchat'><body>{text}</body></message>")
                echo, peer = await asyncio.gather(body(alice, text), body(bob, text))
                measurements['muc_sender_echo'].append(echo - begun)
                measurements['muc_peer'].append(peer - begun)
                for client in clients:
                    await client.ack()
            report[state] = {name: distribution(values) for name, values in measurements.items()}

        # A low-priority headline is actually held; a normal chat body must
        # release it in order even while the receiver remains CSI inactive.
        await csi_state(root, bob, 'inactive')
        held, urgent = 'queued-before-urgent', 'urgent-flush-body'
        await alice.stanza(f"<message to='{bob.jid}' type='headline'><body>{held}</body></message>")
        await bounded(alice.fence('headline-routed'))
        await queued(root, bob, held)
        begun = time.perf_counter()
        await alice.stanza(f"<message to='{bob.jid}' type='chat'><body>{urgent}</body></message>")
        held_at, urgent_at = await asyncio.gather(body(bob, held), body(bob, urgent))
        assert held_at <= urgent_at, 'urgent flush reordered queued output'
        report['urgent_flush'] = distribution([urgent_at - begun])
        report['headline_durably_buffered'] = True

        # Explicit activation must independently drain low-priority output.
        await bob.ack()
        await csi_state(root, bob, 'inactive')
        held = 'queued-before-active'
        await alice.stanza(f"<message to='{bob.jid}' type='headline'><body>{held}</body></message>")
        await bounded(alice.fence('activation-headline-routed'))
        await queued(root, bob, held)
        await bob.send("<active xmlns='urn:xmpp:csi:0'/>")
        await body(bob, held)
        report['activation_drained_queue'] = True
        for client in clients:
            await bounded(client.fence(f'final-{client.number}'))
            await client.ack()
            await bounded(client.handled())
            assert not client.errors, client.errors
            assert all(count == 1 for count in client.bodies.values()), 'duplicate wire delivery'
        archives = list((root / 'data' / 'localhost' / 'archive').glob('*.list'))
        records = sum(sum(line.startswith('item(') for line in path.open()) for path in archives)
        assert (records > 0) == archive, ('MAM toggle did not affect actual archive storage', records)
        report['personal_archive_records'] = records
        muc_archive = root / 'data' / 'rooms%2elocalhost' / 'muc_log' / 'latency.list'
        muc_records = sum(line.startswith('item(') for line in muc_archive.open()) if muc_archive.exists() else 0
        assert muc_records == (history_records + 2 * rounds if archive else 0), ('MUC archive seed/append mismatch', muc_records)
        report['muc_archive_records'] = muc_records
        report['wire_body_deliveries'] = sum(sum(client.bodies.values()) for client in clients)
        assert report['wire_body_deliveries'] == rounds * 8 + 3
        report['status'] = 'pass'
        return report
    finally:
        await asyncio.gather(*(client.close_raw() for client in clients), return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/release/rust-xmpp')
    parser.add_argument('--rounds', type=int, default=20)
    parser.add_argument('--history-records', type=int, nargs='+', default=[0],
                        help='MUC native archive sizes to seed before starting each isolated server')
    parser.add_argument('--output', help='optional JSON measurement report')
    args = parser.parse_args()
    assert args.rounds > 0
    assert all(count >= 0 for count in args.history_records)
    with tempfile.TemporaryDirectory(prefix='xmpp-message-latency-') as directory:
        work = pathlib.Path(directory)
        binary = work / 'rust-xmpp'
        shutil.copy2(pathlib.Path(args.binary).resolve(), binary)
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                  'scope': 'loopback STARTTLS; isolated fixture; no production latency claim', 'cases': []}
        cases = [(False, 0)] + [(True, count) for count in args.history_records]
        for archive, history_records in cases:
            root = work / (f'mam-on-{history_records}' if archive else 'mam-off')
            root.mkdir()
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                            '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                            '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(root/'key.pem'),
                            '-out', str(root/'cert.pem')], check=True, capture_output=True)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            modules = ['tls', 'saslauth', 'smacks', 'csi_simple', 'ping', 'disco']
            if archive:
                modules.append('mam')
            config = root / 'config.json'
            config.write_text(json.dumps({'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'],
                'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [],
                'modules_enabled': modules, 'default_archive_policy': True, 'archive_expires_after': 'never',
                'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}},
                'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256'}},
                          'rooms.localhost': {'component': 'muc', 'options': {'muc_room_locking': False,
                              'modules_enabled': ['muc_mam'] if archive else [],
                              'muc_log_expires_after': 604800}}}}))
            for number in range(2):
                subprocess.run([str(binary), 'create-user', str(config), f'load-{number}', '--password-stdin'],
                               input='load-test-password\n', text=True, check=True, capture_output=True)
            if archive and history_records:
                # Native Prosody `.list` fixture, matching archive_mam.rs. All
                # timestamps are recent, so retention scans must retain them.
                # Seeding occurs before any server opens this isolated store.
                archive_path = root / 'data' / 'rooms%2elocalhost' / 'muc_log' / 'latency.list'
                archive_path.parent.mkdir(parents=True, exist_ok=True)
                now = time.time()
                stamp = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                with archive_path.open('w') as output:
                    for number in range(history_records):
                        output.write("item({name='message';attr={xmlns='jabber:client';type='groupchat';"
                                     f"from='latency@rooms.localhost/Seed';stamp='{stamp}'" + "};"
                                     f"key='seed-{number}';when={now};with='message<groupchat';"
                                     "{name='body';attr={};'seed history'}});\n")
            with (root/'server.log').open('w+') as log:
                server = start(str(binary), config, port, log)
                try:
                    report['cases'].append(asyncio.run(exercise(root, port, args.rounds, archive, history_records)))
                finally:
                    stop(server)
        result = json.dumps(report, indent=2) + '\n'
        if args.output:
            pathlib.Path(args.output).write_text(result)
        print(result, end='')


if __name__ == '__main__':
    main()
