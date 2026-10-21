#!/usr/bin/env python3
"""Fixture-only slow durable IO: two accounts, four TLS/SM resources, MAM/PEP.

Builds only a tiny C LD_PRELOAD interposer; uses an isolated copy of --binary.
Every intercepted fsync/fdatasync still executes. Directory syncs under the
fixture data root are delayed too and counted separately. No mount changes.
Timing includes durable work, with client ACKs withheld during each sample.
"""
import argparse
import asyncio
import collections
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

from muc_sm_load_network import Client, CLIENT, SM
from muc_restart_network import stop
from message_latency_network import slot

CARBONS = 'urn:xmpp:carbons:2'
PUBSUB = 'http://jabber.org/protocol/pubsub'


PHASE_FIELDS = ('pre_routing_ms', 'sender_mam_ms', 'recipient_mam_ms',
    'delivery_ms', 'carbons_ms', 'offline_push_ms', 'handled_ms')
SLOW_FIELDS = {'duration_ms', 'route', 'target_count', 'carbon_count', *PHASE_FIELDS}


def slow_events(path, delay, rounds, allow_legacy=False):
    events = []
    for line in path.read_text().splitlines():
        if 'event="message-processing-slow"' not in line:
            continue
        fields = dict(re.findall(r'(?:^|\s)"([^"\s]+)"="([^"\n]*)"', line))
        legacy = allow_legacy and set(fields) == {'duration_ms', 'route'}
        assert legacy or set(fields) == SLOW_FIELDS, ('unexpected slow-event fields', sorted(fields))
        assert not any(value in line for value in
            ('slow fixture ', 'body-settled-', 'body-avatar_pending-', '<body')), 'payload leaked into slow diagnostics'
        event = {key: value if key == 'route' else int(value) for key,value in fields.items()}
        assert event['duration_ms'] >= 250 and event['route'] == 'local', event
        if not legacy:
            assert all(event[key] >= 0 for key in PHASE_FIELDS), event
            assert sum(event[key] for key in PHASE_FIELDS) <= event['duration_ms']+len(PHASE_FIELDS), event
            assert event['target_count'] == 1 and event['carbon_count'] == 2, event
        events.append(event)
    # At >=100ms the retained durable commits alone exceed the 250ms threshold.
    # Smaller optional delays may legitimately produce no warning.
    if delay >= 100:
        assert len(events) == 2*rounds, ('missing/extra slow diagnostics',len(events),2*rounds)
    return events


class WireReader:
    def __init__(self, reader, owner):
        self.reader, self.owner = reader, owner
        self.parser = ET.XMLPullParser(events=('start', 'end'))
        self.parser.feed("<root xmlns='jabber:client'>")
        self.root = next(self.parser.read_events())[1]
        self.depth = 0

    def __getattr__(self, name):
        return getattr(self.reader, name)

    async def read(self, size):
        data = await self.reader.read(size)
        self.parser.feed(data)
        for event, node in self.parser.read_events():
            self.depth += 1 if event == 'start' else -1
            if event != 'end' or self.depth:
                continue
            now = time.monotonic_ns()
            if node.tag == f'{{{CLIENT}}}message':
                for message in node.iter(f'{{{CLIENT}}}message'):
                    if message.get('id'):
                        kind = 'direct'
                        for carbon in ('sent', 'received'):
                            if node.find(f'{{{CARBONS}}}{carbon}') is not None:
                                kind = carbon
                        self.owner.arrivals[(message.get('id'), kind)].append(now)
            if node.tag == f'{{{SM}}}a':
                self.owner.ack_times[int(node.get('h'))] = now
            self.root.remove(node)
        return data


class MeasuredClient(Client):
    def __init__(self, *args):
        super().__init__(*args)
        self.arrivals = collections.defaultdict(list)
        self.ack_times = {}
        self.reader = WireReader(self.reader, self)


async def iq(client, identifier, payload):
    await client.stanza(f"<iq type='set' id='{identifier}'>{payload}</iq>")
    result = await client.wait(lambda: client.iqs.pop(identifier, None), identifier)
    assert result.get('type') == 'result', ET.tostring(result)


def sync_rows(path):
    return [json.loads(row) for row in path.read_text().splitlines()] if path.exists() else []


def counts(rows):
    result = collections.Counter(f"{row['store']}:{row['kind']}:{row['op']}" for row in rows)
    assert all(row['result'] == 0 for row in rows), 'real sync failed'
    return {'total': len(rows), 'by_store_kind_op': dict(sorted(result.items()))}


async def exercise(root, port, args, log):
    context = ssl.create_default_context(cafile=str(root/'cert.pem'))
    clients = []
    report = []
    try:
        for number in range(4):
            client = await MeasuredClient.connect(number, port, context, 2)
            clients.append(client)
            client.auto_ack = False
            await client.enable()
            await iq(client, f'carbons-{number}', f"<enable xmlns='{CARBONS}'/>")
            await client.stanza('<presence/>')
            await client.fence(f'ready-{number}')
        alice, bob, alice_other, bob_other = clients
        avatar = 'urn:xmpp:avatar:metadata'
        # Self-account subscriptions make avatar events reach sibling resources.
        await iq(alice, 'avatar-initial', f"<pubsub xmlns='{PUBSUB}'><publish node='{avatar}'><item id='initial'><metadata xmlns='{avatar}'/></item></publish></pubsub>")
        for client in (alice, alice_other):
            await iq(client, f'subscribe-{client.number}', f"<pubsub xmlns='{PUBSUB}'><subscribe node='{avatar}' jid='{client.jid}'/></pubsub>")
        for phase in ('settled', 'avatar_pending'):
            for turn in range(args.rounds):
                # Fence all previous ACK work before taking operation counts.
                for client in clients:
                    await client.ack()
                    await client.fence(f'before-{phase}-{turn}-{client.number}')
                    await client.handled()
                before = len(sync_rows(log))
                start_ns = time.monotonic_ns()
                if phase == 'avatar_pending':
                    # Publication remains ahead of the body on this stream; no
                    # client ACK is sent for its IQ result or PEP notifications.
                    await alice.stanza(f"<iq type='set' id='publish-{turn}'><pubsub xmlns='{PUBSUB}'><publish node='{avatar}'><item id='sample-{turn}'><metadata xmlns='{avatar}'><info id='fixture-avatar' bytes='1' type='image/png'/></metadata></item></publish></pubsub></iq>")
                identifier = f'body-{phase}-{turn}'
                begun = time.monotonic_ns()
                await alice.stanza(f"<message to='{bob.jid}' type='chat' id='{identifier}'><body>slow fixture {identifier}</body></message>")
                await alice.handled()
                events = []
                for client, kind in ((bob, 'direct'), (alice_other, 'sent'), (bob_other, 'received')):
                    await client.wait(lambda c=client,k=kind: c.arrivals[(identifier,k)], identifier+' '+kind)
                    arrivals = client.arrivals[(identifier, kind)]
                    assert len(arrivals) == 1, (identifier, kind, arrivals)
                    events.append((kind, (arrivals[0]-begun)/1e6))
                end_ns = time.monotonic_ns()
                rows = sync_rows(log)[before:]
                assert rows, 'interposer recorded no data-root sync operations'
                assert all(row['end_ns']-row['begin_ns'] >= args.current_delay_ms*1000000
                    for row in rows), 'configured sync delay was not applied'
                snapshots = [slot(root,c) for c in clients]
                for index in (1,2,3):
                    assert sum(identifier in xml for xml in snapshots[index]['pending']) == 1, (identifier,index)
                if phase == 'avatar_pending':
                    assert all(any(avatar in xml and 'event' in xml for xml in snapshots[index]['pending'])
                        for index in (0,2)), 'avatar PEP notifications were not durably pending'
                report.append({'phase': phase, 'round': turn,
                    'delivery_ms': dict(events),
                    'sender_sm_handled_ms': (alice.ack_times[alice.inputs]-begun)/1e6,
                    'publication_plus_delivery_ms': (end_ns-start_ns)/1e6,
                    'sync': counts(rows),
                    'pending_per_resource': [len(snapshot['pending']) for snapshot in snapshots]})
        assert all(not client.errors for client in clients), [c.errors for c in clients]
        # Both ends archive each personal body exactly once, despite carbons.
        archive_counts = [sum(line.startswith('item(') for line in path.open())
            for path in sorted((root/'data'/'localhost'/'archive').glob('*.list'))]
        expected = args.history_records + 2*args.rounds
        assert archive_counts == [expected, expected], (archive_counts, expected)
        return {'samples': report, 'mam_records_per_account': archive_counts,
            'status': 'pass'}
    finally:
        await asyncio.gather(*(c.close_raw() for c in clients), return_exceptions=True)


def check_shim_scope(work, shim):
    """Prove that both sync APIs preserve success and exclude non-data files."""
    root = work/'shim-scope-data'
    root.mkdir()
    log = work/'shim-scope.jsonl'
    code = """import os,pathlib,sys
root,outside=map(pathlib.Path,sys.argv[1:])
for path in (root/'inside',outside):
    with path.open('wb') as stream:
        stream.write(b'fixture')
        stream.flush()
        os.fsync(stream.fileno())
        os.fdatasync(stream.fileno())
fd=os.open(root,os.O_RDONLY)
os.fsync(fd)
os.close(fd)
"""
    env = dict(os.environ, LD_PRELOAD=str(shim), XMPP_SLOW_SYNC_ROOT=str(root),
        XMPP_SLOW_SYNC_LOG=str(log), XMPP_SLOW_SYNC_MS='0')
    subprocess.run([sys.executable,'-c',code,str(root),str(work/'outside')],
        env=env,check=True,capture_output=True)
    rows = sync_rows(log)
    assert len(rows) == 3, rows
    assert collections.Counter((r['op'],r['kind']) for r in rows) == {
        ('fsync','file'):1, ('fdatasync','file'):1, ('fsync','directory'):1}
    assert all(row['result'] == 0 for row in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/release/rust-xmpp')
    parser.add_argument('--delay-ms', type=int, nargs='+', default=[0, 100])
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--history-records', type=int, default=100)
    parser.add_argument('--output')
    parser.add_argument('--allow-legacy-phase-logs', action='store_true',
        help='baseline binaries only: permit old duration/route diagnostics without phase metrics')
    args = parser.parse_args()
    assert args.rounds > 0 and args.history_records >= 0
    assert all(0 <= delay <= 10000 for delay in args.delay_ms)
    with tempfile.TemporaryDirectory(prefix='xmpp-slow-storage-') as directory:
        work = pathlib.Path(directory)
        binary = work/'rust-xmpp'
        shutil.copy2(pathlib.Path(args.binary).resolve(), binary)
        shim = work/'slow_sync.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
            str(pathlib.Path(__file__).parent/'fixtures'/'slow_sync.c'), '-o', str(shim), '-ldl'], check=True)
        check_shim_scope(work, shim)
        report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'scope': 'loopback STARTTLS; four SM resources/two accounts; MAM + pending avatar metadata PEP; fixture-only fsync/fdatasync including data directories; real sync retained; operation windows include background SM heartbeat',
            'cases': []}
        for delay in args.delay_ms:
            root = work/f'delay-{delay}'
            root.mkdir()
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem')], check=True, capture_output=True)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1',0))
                port = probe.getsockname()[1]
            config = root/'config.json'
            config.write_text(json.dumps({'global': {'data_path': str(root/'data'), 'interfaces':['127.0.0.1'],
                'c2s_ports':[port], 's2s_ports':[], 'http_ports':[], 'https_ports':[],
                'modules_enabled':['tls','saslauth','smacks','csi_simple','ping','mam','pep','carbons'],
                'archive_expires_after':'never', 'default_archive_policy':True,
                'ssl':{'key':str(root/'key.pem'),'certificate':str(root/'cert.pem')}},
                'hosts':{'localhost':{'options':{'authentication':'internal_hashed','password_hash':'SHA-256'}}}}))
            for number in range(2):
                subprocess.run([str(binary),'create-user',str(config),f'load-{number}','--password-stdin'],
                    input='load-test-password\n',text=True,check=True,capture_output=True)
                archive = root/'data'/'localhost'/'archive'/f'load%2d{number}.list'
                archive.parent.mkdir(parents=True,exist_ok=True)
                with archive.open('w') as stream:
                    for index in range(args.history_records):
                        stream.write("item({name='message';attr={xmlns='jabber:client';type='chat'};"
                            f"key='seed-{index}';when={time.time()};with='load-{1-number}@localhost';"
                            "{name='body';attr={};'history'}});\n")
            sync_log = root/'sync.jsonl'
            env = dict(os.environ, LD_PRELOAD=str(shim), XMPP_SLOW_SYNC_ROOT=str(root/'data'),
                XMPP_SLOW_SYNC_LOG=str(sync_log), XMPP_SLOW_SYNC_MS=str(delay))
            with (root/'server.log').open('w+') as log:
                server = subprocess.Popen([str(binary),'serve',str(config),'--experimental'],env=env,stdout=log,stderr=log)
                try:
                    deadline = time.monotonic()+60
                    while True:
                        assert server.poll() is None, log.read()
                        try:
                            with socket.create_connection(('127.0.0.1',port),timeout=.1):
                                break
                        except OSError:
                            assert time.monotonic()<deadline, 'server startup timeout'
                            time.sleep(.05)
                    args.current_delay_ms = delay
                    case = asyncio.run(exercise(root,port,args,sync_log))
                    case['delay_ms_per_sync'] = delay
                    events = slow_events(root/'server.log',delay,args.rounds,args.allow_legacy_phase_logs)
                    case['server_message_processing_slow_events'] = events
                    case['server_message_processing_slow_ms'] = [event['duration_ms'] for event in events]
                    report['cases'].append(case)
                finally:
                    stop(server)
            if args.output:
                pathlib.Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
            print(f'slow storage: delay={delay}ms pass',flush=True)
        print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
