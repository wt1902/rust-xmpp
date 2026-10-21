#!/usr/bin/env python3
"""SIGKILL after sender SM acknowledgement under real delayed durable IO.

Four STARTTLS resources/two accounts, MAM, carbons and unacknowledged avatar
PEP. Inspect authoritative recipient journals and both archives before any
reauthentication; then resume all resources and verify replay and counters.
Uses the latency fixture's fsync/fdatasync interposer, retaining real syncs.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from muc_sm_load_network import SM
from muc_restart_network import stop
from sm_restart_network import durable_slot
from slow_storage_latency_network import (
    CARBONS, PUBSUB, MeasuredClient, check_shim_scope, counts, iq, sync_rows,
)


def start(binary, config, port, log, env):
    server = subprocess.Popen([str(binary), 'serve', str(config), '--experimental'],
                              env=env, stdout=log, stderr=log)
    deadline = time.monotonic()+60
    while time.monotonic() < deadline:
        assert server.poll() is None, 'server stopped during startup'
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return server
        except OSError:
            time.sleep(.05)
    server.kill()
    server.wait()
    raise AssertionError('server startup timeout')


def committed_archive(path):
    """Reconstruct native MAM bytes using its authoritative checksummed redo."""
    native = path.read_bytes()
    data = path.with_suffix('.rredo').read_bytes()
    assert len(data) >= 96 and data[:8] == b'XARRED01', 'invalid MAM redo header'
    assert hashlib.sha256(data[:64]).digest() == data[64:96], 'invalid MAM redo header checksum'
    baseline = int.from_bytes(data[8:16], 'little')
    assert baseline <= len(native), 'missing MAM native baseline'
    committed, offset = native[:baseline], 96
    while offset < len(data):
        if len(data)-offset < 72:
            break
        size = int.from_bytes(data[offset:offset+8], 'little')
        assert hashlib.sha256(data[offset:offset+8]).digest() == data[offset+8:offset+40], 'invalid MAM redo length checksum'
        assert 0 < size <= 16*1024*1024, 'invalid MAM redo frame size'
        end = offset+72+size
        if end > len(data):
            break
        payload = data[offset+72:end]
        assert hashlib.sha256(payload).digest() == data[offset+40:offset+72], 'invalid MAM redo frame checksum'
        committed += payload
        offset = end
    # Sender handled acknowledgement must not depend on a native suffix that
    # lacks a complete, durable redo frame.
    assert native == committed, 'native MAM suffix is not committed in redo'
    return committed.decode()


def assert_committed(root, expected, identifiers, avatar):
    snapshots = [durable_slot(root, old['token']) for old in expected]
    for index, (record, old) in enumerate(zip(snapshots, expected)):
        assert record['jid'] == old['jid'], (index, record)
        assert record['handled'] == old['handled'], (index, record['handled'], old)
        assert record['acked'] == old['acked'], (index, record['acked'], old)
        assert record['sent']-record['acked'] == len(record['pending']), (index, record)
        if index in (1, 2, 3):
            for identifier in identifiers:
                assert sum(identifier in xml for xml in record['pending']) == 1, (index, identifier, record)
        if index in (0, 2):
            assert any(avatar in xml and 'event' in xml and 'crash-avatar' in xml
                       for xml in record['pending']), ('PEP missing before reauthentication', index, record)
    paths = sorted((root/'data'/'localhost'/'archive').glob('*.list'))
    assert len(paths) == 2, paths
    for path in paths:
        rows = [row for row in committed_archive(path).splitlines() if row.startswith('item(')]
        assert len(rows) == len(identifiers), (path.name, len(rows), identifiers)
        for identifier in identifiers:
            assert sum(identifier in row for row in rows) == 1, ('acknowledged body missing/duplicated in MAM', path.name, identifier)
    return snapshots


async def exercise(root, binary, config, port, log, env, sync_log, args):
    context = ssl.create_default_context(cafile=str(root/'cert.pem'))
    clients, server = [], None
    avatar = 'urn:xmpp:avatar:metadata'
    try:
        server = await asyncio.to_thread(start, binary, config, port, log, env)
        for number in range(4):
            client = await MeasuredClient.connect(number, port, context, 2)
            clients.append(client)
            client.auto_ack = False
            await client.enable()
            await iq(client, f'carbons-{number}', f"<enable xmlns='{CARBONS}'/>")
            await client.stanza('<presence/>')
            await client.fence(f'ready-{number}')
        alice, bob, alice_other, _ = clients
        await iq(alice, 'avatar-initial', f"<pubsub xmlns='{PUBSUB}'><publish node='{avatar}'><item id='initial'><metadata xmlns='{avatar}'/></item></publish></pubsub>")
        for client in (alice, alice_other):
            await iq(client, f'subscribe-{client.number}', f"<pubsub xmlns='{PUBSUB}'><subscribe node='{avatar}' jid='{client.jid}'/></pubsub>")
        # Ack every setup stanza, then fence acknowledgement persistence. No
        # resource sends another ACK until after the crash replay assertions.
        for client in clients:
            await client.fence(f'setup-{client.number}')
            await client.ack()
            await client.handled()
        before = len(sync_rows(sync_log))
        await iq(alice, 'avatar-pending', f"<pubsub xmlns='{PUBSUB}'><publish node='{avatar}'><item id='crash-avatar'><metadata xmlns='{avatar}'><info id='fixture-avatar' bytes='1' type='image/png'/></metadata></item></publish></pubsub>")
        identifiers = [f'crash-body-{number}' for number in range(args.messages)]
        for identifier in identifiers:
            await alice.stanza(f"<message to='{bob.jid}' type='chat' id='{identifier}'><body>{identifier}</body></message>")
            await alice.handled()
        expected = [{'token': c.token, 'jid': c.jid, 'acked': c.acked, 'handled': c.inputs}
                    for c in clients]
        # No receiver fence/delivery wait between sender's final <a/> and kill:
        # the acknowledged sender operation itself must make the data durable.
        server.send_signal(signal.SIGKILL)
        assert await asyncio.to_thread(server.wait, 10) == -signal.SIGKILL
        snapshots = assert_committed(root, expected, identifiers, avatar)
        rows = sync_rows(sync_log)[before:]
        summary = counts(rows)
        assert rows and all(row['end_ns']-row['begin_ns'] >= args.delay_ms*1000000 for row in rows)
        assert {'sm', 'mam', 'pep'}.issubset({row['store'] for row in rows}), summary
        assert any(row['kind'] == 'directory' for row in rows), summary
        await asyncio.gather(*(c.close_raw() for c in clients), return_exceptions=True)
        clients.clear()
        server = await asyncio.to_thread(start, binary, config, port, log, env)
        # Startup must recover the same queues before a single SASL login.
        recovered = assert_committed(root, expected, identifiers, avatar)
        for old, new in zip(snapshots, recovered):
            assert old['pending'] == new['pending']
        for number, old in enumerate(expected):
            client = await MeasuredClient.connect(number, port, context, 2, bind=False)
            clients.append(client)
            client.auto_ack = False
            client.received = client.acked = old['acked']
            client.inputs, client.token = old['handled'], old['token']
            await client.send(f"<resume xmlns='{SM}' previd='{client.token}' h='{client.acked}'/>")
            result = await client.control('resumed')
            assert result.get('previd') == client.token
            assert int(result.get('h')) == old['handled'], (number, result.attrib, old)
            kind = {1: 'direct', 2: 'sent', 3: 'received'}.get(number)
            if kind:
                for identifier in identifiers:
                    await client.wait(lambda c=client,i=identifier,k=kind: c.arrivals[(i,k)], 'durable replay '+identifier)
                    assert len(client.arrivals[(identifier,kind)]) == 1, (number, identifier, client.arrivals)
            await client.fence(f'after-resume-{number}')
            # The fence follows every replay, so the exact output counter also
            # detects missing/extra PEP, carbon or IQ replay, beyond body counts.
            assert client.received == snapshots[number]['sent']+1, (number, client.received, snapshots[number]['sent'])
            await client.ack()
            await client.handled()
            record = durable_slot(root, client.token)
            assert record['acked'] == client.received and not record['pending'], (number, record)
            assert not client.errors, client.errors
        # Native handoff is explicitly offline: release the server's data/store
        # locks before asking the CLI to durably export and remove journals.
        await asyncio.to_thread(stop, server)
        server = None
        final_slots = {c.token: durable_slot(root, c.token) for c in clients}
        final_archives = {p: committed_archive(p) for p in
                          (root/'data'/'localhost'/'archive').glob('*.list')}
        checkpoint = [str(binary), 'storage-checkpoint', str(config)]
        await asyncio.to_thread(subprocess.run, checkpoint, env=env, check=True, capture_output=True, text=True)
        assert not list((root/'data').rglob('*.wal')), 'SM WAL survived offline checkpoint'
        assert not list((root/'data').rglob('*.rredo')), 'MAM redo survived offline checkpoint'
        exported = {}
        for token, authoritative in final_slots.items():
            paths = list((root/'data').rglob(token+'.json'))
            assert len(paths) == 1, ('checkpoint lost SM export', token)
            exported[token] = json.loads(paths[0].read_text())
            previous = dict(authoritative)
            current = dict(exported[token])
            previous.pop('deadline_ms')
            current.pop('deadline_ms')
            assert current == previous, ('checkpoint changed authoritative SM fields', token, current, previous)
        assert all(p.read_text() == content for p, content in final_archives.items()), 'checkpoint changed committed MAM records'
        await asyncio.to_thread(subprocess.run, checkpoint, env=env, check=True, capture_output=True, text=True)
        assert not list((root/'data').rglob('*.wal')) and not list((root/'data').rglob('*.rredo'))
        for token, previous in exported.items():
            paths = list((root/'data').rglob(token+'.json'))
            assert len(paths) == 1 and json.loads(paths[0].read_text()) == previous, 'second checkpoint changed SM export'
        assert all(p.read_text() == content for p, content in final_archives.items()), 'second checkpoint changed MAM records'
        return {'status': 'pass', 'delay_ms_per_sync': args.delay_ms,
                'acknowledged_messages': len(identifiers), 'mam_records_per_account': [len(identifiers)]*2,
                'resumed_resources': len(clients), 'replayed_personal_deliveries': 3*len(identifiers),
                'offline_checkpoint': {'exported_sessions': len(exported), 'native_archives': len(final_archives),
                                       'journals_removed': True, 'second_invocation_idempotent': True},
                'pending_before_reauthentication': [len(record['pending']) for record in snapshots],
                'sync_between_publication_and_sigkill': summary}
    finally:
        if server is not None and server.poll() is None:
            failing = sys.exc_info()[0] is not None
            try:
                await asyncio.to_thread(stop, server)
            except BaseException:
                if not failing:
                    raise
        await asyncio.gather(*(c.close_raw() for c in clients), return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/release/rust-xmpp')
    parser.add_argument('--delay-ms', type=int, default=100)
    parser.add_argument('--messages', type=int, default=3)
    parser.add_argument('--output', default='/tmp/slow-storage-crash.json')
    args = parser.parse_args()
    assert 0 <= args.delay_ms <= 10000 and args.messages > 0
    with tempfile.TemporaryDirectory(prefix='xmpp-slow-storage-crash-') as directory:
        root = Path(directory)
        binary = root/'rust-xmpp'
        shutil.copy2(Path(args.binary).resolve(), binary)
        shim = root/'slow_sync.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(Path(__file__).parent/'fixtures'/'slow_sync.c'), '-o', str(shim), '-ldl'], check=True)
        check_shim_scope(root, shim)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem')], check=True, capture_output=True)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        config = root/'config.json'
        config.write_text(json.dumps({'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'],
            'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [],
            'smacks_hibernation_time': 600,
            'modules_enabled': ['tls', 'saslauth', 'smacks', 'csi_simple', 'ping', 'mam', 'pep', 'carbons'],
            'archive_expires_after': 'never', 'default_archive_policy': True,
            'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}},
            'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256'}}}}))
        for number in range(2):
            subprocess.run([str(binary), 'create-user', str(config), f'load-{number}', '--password-stdin'],
                           input='load-test-password\n', text=True, check=True, capture_output=True)
        sync_log = root/'sync.jsonl'
        env = dict(os.environ, LD_PRELOAD=str(shim), XMPP_SLOW_SYNC_ROOT=str(root/'data'),
                   XMPP_SLOW_SYNC_LOG=str(sync_log), XMPP_SLOW_SYNC_MS=str(args.delay_ms))
        with (root/'server.log').open('w+') as log:
            try:
                report = asyncio.run(exercise(root, binary, config, port, log, env, sync_log, args))
            except BaseException as error:
                # Preserve the first failing run's evidence outside the
                # TemporaryDirectory before cleanup; never replace its error
                # with a later shutdown or diagnostics failure.
                try:
                    log.flush()
                    output = Path(args.output)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    evidence = Path(tempfile.mkdtemp(prefix=output.stem+'-failure-', dir=output.parent))
                    shutil.copy2(root/'server.log', evidence/'server.log')
                    if sync_log.exists():
                        shutil.copy2(sync_log, evidence/'sync.jsonl')
                    Path(args.output).write_text(json.dumps({'status': 'fail',
                        'failure': repr(error), 'delay_ms_per_sync': args.delay_ms,
                        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                        'evidence': str(evidence)}, indent=2)+'\n')
                except Exception as diagnostic_error:
                    print(f'Could not preserve failure evidence: {diagnostic_error}', file=sys.stderr)
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
        report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report['scope'] = 'loopback STARTTLS; real delayed fsync/fdatasync; sender SM acknowledgement then SIGKILL; authoritative queues and MAM checked before reauthentication; at-least-once replay'
        result = json.dumps(report, indent=2)+'\n'
        if args.output:
            Path(args.output).write_text(result)
        print(result, end='')


if __name__ == '__main__':
    main()
