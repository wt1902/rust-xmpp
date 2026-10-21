#!/usr/bin/env python3
"""Separate personal-chat wire delivery, handled SM ACK and client receipt timing.

Native personal MAM/roster fixtures, real loopback STARTTLS, durable SM/CSI.
A forced CSI dwell is reported explicitly and is not a server performance sample.
The default exercises both the runtime defaults (urgent encrypted/receipt payloads)
and an explicit empty importance list (native policy). Use --expect-held for the
old binary; --csi-policy default limits a baseline run to its default policy.
"""
import argparse
import asyncio
import collections
import hashlib
import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from message_latency_network import bounded, csi_state, distribution, slot
from muc_sm_load_network import Client, CLIENT, SM, start
from muc_restart_network import stop


class ObservedReader:
    """Observe complete wire stanzas while retaining the existing client's parser."""
    def __init__(self, reader, client):
        self.reader, self.client = reader, client
        self.parser = ET.XMLPullParser(events=('start', 'end'))
        self.parser.feed("<root xmlns='jabber:client'>")
        self.root = next(self.parser.read_events())[1]
        self.depth = 0

    def __getattr__(self, name):
        return getattr(self.reader, name)

    async def read(self, size):
        chunk = await self.reader.read(size)
        self.parser.feed(chunk)
        for event, node in self.parser.read_events():
            self.depth += 1 if event == 'start' else -1
            if event == 'end' and self.depth == 0:
                now = time.perf_counter()
                if node.tag == f'{{{CLIENT}}}message' and node.get('id'):
                    self.client.message_times[node.get('id')].append(now)
                if node.tag == f'{{{SM}}}a':
                    self.client.ack_times[int(node.get('h'))] = now
                self.root.remove(node)
        return chunk


class MeasuredClient(Client):
    def __init__(self, *args):
        super().__init__(*args)
        self.message_times = collections.defaultdict(list)
        self.ack_times = {}
        self.reader = ObservedReader(self.reader, self)


async def seen(client, identifier):
    await bounded(client.wait(lambda: client.message_times[identifier], identifier))
    assert len(client.message_times[identifier]) == 1
    return client.message_times[identifier][0]


async def send_measured(sender, receiver, identifier, payload, typ='chat'):
    begun = time.perf_counter()
    await sender.stanza(f"<message to='{receiver.jid}' type='{typ}' id='{identifier}'>{payload}</message>")
    await bounded(sender.handled())
    ack_at = sender.ack_times[sender.inputs]
    return begun, ack_at


async def exercise(root, port, args, policy):
    clients = []
    try:
        context = ssl.create_default_context(cafile=str(root/'cert.pem'))
        for n in range(2):
            client = await bounded(MeasuredClient.connect(n, port, context, 2))
            clients.append(client)
            client.auto_ack = False
            await bounded(client.enable())
            await client.stanza('<presence/>')
            await bounded(client.fence(f'connected-{n}'))
            await client.ack()
        alice, bob = clients
        results = {}
        for state in ('active', 'inactive'):
            values = collections.defaultdict(list)
            for turn in range(args.rounds):
                await csi_state(root, alice, 'active')
                await csi_state(root, bob, state)
                identifier = f'{state}-body-{turn}'
                begun, ack_at = await send_measured(alice, bob, identifier, '<body>personal test</body>')
                delivery = await seen(bob, identifier)
                receipt_id = identifier + '-receipt'
                # Receipt generation belongs to the receiving client; the server
                # does not synthesize XEP-0184 receipts on SM acknowledgement.
                receipt_sent = time.perf_counter()
                await bob.stanza(f"<message to='{alice.jid}' type='chat' id='{receipt_id}'><received xmlns='urn:xmpp:receipts' id='{identifier}'/></message>")
                receipt = await seen(alice, receipt_id)
                values['delivery'].append(delivery-begun)
                values['sender_sm_handled'].append(ack_at-begun)
                values['client_receipt_end_to_end'].append(receipt-begun)
                values['receipt_return_leg'].append(receipt-receipt_sent)
                for client in clients:
                    await client.ack()
            results[state] = {name: distribution(v) for name, v in values.items()}

        payloads = {
            'receipt_only': "<received xmlns='urn:xmpp:receipts' id='earlier-message'/>",
            'omemo_legacy_only': "<encrypted xmlns='eu.siacs.conversations.axolotl'><header sid='1'><iv>AA==</iv></header><payload>AA==</payload></encrypted>",
            'omemo_2_only': "<encrypted xmlns='urn:xmpp:omemo:2'><header sid='1'><iv>AA==</iv></header><payload>AA==</payload></encrypted>",
            'omemo_with_eme': "<encrypted xmlns='eu.siacs.conversations.axolotl'><payload>AA==</payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='eu.siacs.conversations.axolotl'/>",
        }
        payloads.update({f'marker_{name}':
            f"<{name} xmlns='urn:xmpp:chat-markers:0' id='earlier-message'/>"
            for name in ('received', 'displayed', 'acknowledged')})
        payloads['low_priority_headline'] = '<body>held low priority</body>'
        for name, payload in payloads.items():
            for state in ('active', 'inactive'):
                await csi_state(root, alice, 'active')
                await csi_state(root, bob, state)
                identifier = name + '-' + state
                begun, ack_at = await send_measured(alice, bob, identifier, payload,
                    'headline' if name == 'low_priority_headline' else 'chat')
                deadline = time.monotonic() + 20
                while True:
                    buffered = any(identifier in xml for xml in slot(root, bob)['csi']['queue'])
                    if buffered or bob.message_times[identifier]:
                        break
                    assert time.monotonic() < deadline, identifier
                    await asyncio.sleep(.001)
                expect_held = state == 'inactive' and (
                    name == 'low_priority_headline' or (
                        name != 'omemo_with_eme' and (policy == 'native' or args.expect_held)))
                assert buffered == expect_held, (policy, identifier, buffered, expect_held)
                activation = None
                if buffered:
                    assert not bob.message_times[identifier]
                    await asyncio.sleep(args.csi_dwell)
                    assert not bob.message_times[identifier], 'CSI unexpectedly emitted held payload'
                    activation = time.perf_counter()
                    await bob.send("<active xmlns='urn:xmpp:csi:0'/>")
                delivered = await seen(bob, identifier)
                results[identifier] = {'delivery_ms': (delivered-begun)*1000,
                    'sender_sm_handled_ms': (ack_at-begun)*1000,
                    'durably_csi_buffered': buffered,
                    'forced_dwell_seconds': args.csi_dwell if buffered else 0,
                    'after_activation_ms': (delivered-activation)*1000 if activation else None}
                for client in clients:
                    await client.ack()

        await csi_state(root, bob, 'active')
        # Keep receiving/draining but deliberately withhold recipient ACKs.
        for n in range(args.backlog):
            await alice.stanza(f"<message to='{bob.jid}' type='chat' id='backlog-{n}'><body>unacked backlog</body></message>")
            await seen(bob, f'backlog-{n}')
        if args.backlog:
            await seen(bob, f'backlog-{args.backlog-1}')
        await bounded(alice.handled())
        pending = len(slot(root, bob)['pending'])
        begun, ack_at = await send_measured(alice, bob, 'after-backlog', '<body>after backlog</body>')
        delivery = await seen(bob, 'after-backlog')
        results['sm_backlog'] = {'seeded_messages': args.backlog, 'durable_pending_before_sample': pending,
            'delivery_ms': (delivery-begun)*1000, 'sender_sm_handled_ms': (ack_at-begun)*1000}
        for client in clients:
            await client.ack()
            assert not client.errors, client.errors
        results['status'] = 'pass'
        return results
    finally:
        await asyncio.gather(*(c.close_raw() for c in clients), return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/release/rust-xmpp')
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--history-records', type=int, default=100000)
    parser.add_argument('--roster-sizes', type=int, nargs='+', default=[0, 5000, 10000])
    parser.add_argument('--backlog', type=int, default=500)
    parser.add_argument('--csi-dwell', type=float, default=2)
    parser.add_argument('--csi-policy', choices=('default', 'native', 'both'), default='both',
                        help='native explicitly configures csi_important_payloads=[]; both verifies override')
    parser.add_argument('--expect-held', action='store_true',
                        help='baseline binaries: expect native holds even when option is absent')
    parser.add_argument('--output')
    args = parser.parse_args()
    assert args.rounds > 0 and args.history_records >= 0
    assert all(count >= 0 for count in args.roster_sizes)
    assert 0 <= args.backlog < 4000 and args.csi_dwell >= 0
    with tempfile.TemporaryDirectory(prefix='xmpp-personal-latency-') as directory:
        work = pathlib.Path(directory)
        binary = work/'rust-xmpp'
        shutil.copy2(pathlib.Path(args.binary).resolve(), binary)
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'scope': 'loopback STARTTLS; fixture only; forced CSI dwell explicitly separated', 'cases': []}
        policies = ('default', 'native') if args.csi_policy == 'both' else (args.csi_policy,)
        for roster_size, policy in ((n, p) for n in args.roster_sizes for p in policies):
            root = work/f'roster-{roster_size}-{policy}'
            root.mkdir()
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem')], check=True, capture_output=True)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            config = root/'config.json'
            config.write_text(json.dumps({'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'],
                'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [],
                'modules_enabled': ['tls', 'saslauth', 'smacks', 'csi_simple', 'ping', 'mam', 'roster'],
                'default_archive_policy': 'roster' if roster_size else True, 'archive_expires_after': 'never',
                'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}},
                'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256'}}}}))
            if policy == 'native':
                configured = json.loads(config.read_text())
                configured['global']['csi_important_payloads'] = []
                config.write_text(json.dumps(configured))
            for n in range(2):
                subprocess.run([str(binary), 'create-user', str(config), f'load-{n}', '--password-stdin'],
                    input='load-test-password\n', text=True, check=True, capture_output=True)
                archive = root/'data'/'localhost'/'archive'/f'load%2d{n}.list'
                archive.parent.mkdir(parents=True, exist_ok=True)
                now = time.time()
                with archive.open('w') as output:
                    for i in range(args.history_records):
                        output.write("item({name='message';attr={xmlns='jabber:client';type='chat'};"
                            f"key='seed-{i}';when={now};with='load-{1-n}@localhost';"
                            "{name='body';attr={};'native personal history'}});\n")
                if roster_size:
                    roster = root/'data'/'localhost'/'roster'/f'load%2d{n}.dat'
                    roster.parent.mkdir(parents=True, exist_ok=True)
                    with roster.open('w') as output:
                        output.write("return { [false]={version=1};\n")
                        output.write(f"['load-{1-n}@localhost']={{subscription='none'}};\n")
                        for i in range(roster_size-1):
                            output.write(f"['contact-{i}@example.invalid']={{subscription='none'}};\n")
                        output.write('}\n')
            with (root/'server.log').open('w+') as log:
                server = start(str(binary), config, port, log)
                try:
                    results = asyncio.run(exercise(root, port, args, policy))
                    counts = [sum(line.startswith('item(') for line in path.open())
                        for path in sorted((root/'data'/'localhost'/'archive').glob('*.list'))]
                    expected = args.history_records + 4*args.rounds + 10 + args.backlog + 1
                    assert counts == [expected, expected], (counts, expected)
                    results['final_personal_mam_records_per_user'] = counts
                    results.update({'csi_policy': policy, 'baseline_expect_held': args.expect_held,
                        'roster_contacts_per_user': roster_size,
                        'seeded_personal_mam_records_per_user': args.history_records,
                        'archive_policy': 'roster' if roster_size else 'always'})
                    report['cases'].append(results)
                    if args.output:
                        pathlib.Path(args.output).write_text(json.dumps(report, indent=2)+'\n')
                    print(f'personal latency: roster={roster_size} csi={policy} pass', flush=True)
                finally:
                    stop(server)
        result = json.dumps(report, indent=2)+'\n'
        if args.output:
            pathlib.Path(args.output).write_text(result)
        print(result, end='')


if __name__ == '__main__':
    main()
