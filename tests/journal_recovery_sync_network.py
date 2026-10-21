#!/usr/bin/env python3
"""Fail recovery journal syncs explicitly; never publish a false durable handoff.

Uses independent real TLS fixtures for .wal and .rredo so archive native inode
identity remains genuine. SIGKILL leaves complete valid journals. The scoped
test interposer returns EIO only for the selected suffix beneath fixture data.
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
import tempfile
import time

from muc_restart_network import stop
from sm_restart_network import durable_slot
from slow_storage_latency_network import CARBONS, MeasuredClient, check_shim_scope, iq, sync_rows
from slow_storage_crash_network import committed_archive, start


async def seed(root, binary, config, port, log, env):
    context = ssl.create_default_context(cafile=str(root/'cert.pem'))
    clients, server = [], None
    identifier = 'recovery-sync-body'
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
        alice, bob, _, _ = clients
        await alice.stanza(f"<message to='{bob.jid}' type='chat' id='{identifier}'><body>{identifier}</body></message>")
        await alice.handled()
        for client, kind in zip(clients[1:], ('direct', 'sent', 'received')):
            await client.wait(lambda c=client,k=kind: c.arrivals[(identifier,k)], 'message/carbon before crash')
        server.send_signal(signal.SIGKILL)
        assert await asyncio.to_thread(server.wait, 10) == -signal.SIGKILL
        records = {client.token: durable_slot(root, client.token) for client in clients}
        assert len(records) == 4
        for client in clients[1:]:
            assert sum(identifier in xml for xml in records[client.token]['pending']) == 1
        archives = {p: committed_archive(p) for p in (root/'data'/'localhost'/'archive').glob('*.list')}
        assert len(archives) == 2
        assert all(sum(identifier in row for row in content.splitlines()) == 1 for content in archives.values())
        return records, archives
    finally:
        if server is not None and server.poll() is None:
            await asyncio.to_thread(stop, server)
        await asyncio.gather(*(c.close_raw() for c in clients), return_exceptions=True)


def journal_bytes(root, suffix):
    return {p: p.read_bytes() for p in (root/'data').rglob('*'+suffix)}


def assert_serve_rejects(binary, config, port, log, env):
    server = subprocess.Popen([str(binary), 'serve', str(config), '--experimental'],
                              env=env, stdout=log, stderr=log)
    listened = False
    try:
        deadline = time.monotonic()+15
        while server.poll() is None and time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.05):
                    listened = True
                    break
            except OSError:
                time.sleep(.01)
        assert not listened, 'SM recovery sync failure exposed a listener'
        assert server.wait(timeout=5) != 0, 'SM recovery sync failure reported successful serve'
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()


def scope_fault(work, shim):
    root = work/'fault-scope'
    root.mkdir()
    code = """import errno,json,os,pathlib,sys
root,outside,suffix=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),sys.argv[3]
statuses=[]
for path in (root/('inside'+suffix),root/'unmatched.txt',outside):
 with path.open('wb') as stream:
  stream.write(b'fixture');stream.flush()
  for sync in (os.fsync,os.fdatasync):
   try:sync(stream.fileno());statuses.append(0)
   except OSError as error:statuses.append(error.errno)
assert statuses==[errno.EIO,errno.EIO,0,0,0,0],statuses
"""
    for suffix in ('.wal', '.rredo'):
        log = work/('scope-'+suffix[1:]+'.jsonl')
        env = dict(os.environ, LD_PRELOAD=str(shim), XMPP_SLOW_SYNC_ROOT=str(root),
                   XMPP_SLOW_SYNC_LOG=str(log), XMPP_SLOW_SYNC_MS='0', XMPP_SYNC_FAIL_SUFFIX=suffix)
        subprocess.run(['python3', '-c', code, str(root), str(work/('outside'+suffix)), suffix],
                       env=env, check=True, capture_output=True)
        rows = sync_rows(log)
        assert len(rows) == 4 and sum(row['injected'] for row in rows) == 2


def run_case(work, binary, shim, suffix):
    root = work/suffix[1:]
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
        'modules_enabled': ['tls', 'saslauth', 'smacks', 'ping', 'mam', 'carbons'],
        'smacks_hibernation_time': 600, 'archive_expires_after': 'never', 'default_archive_policy': True,
        'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}},
        'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256'}}}}))
    for number in range(2):
        subprocess.run([str(binary), 'create-user', str(config), f'load-{number}', '--password-stdin'],
                       input='load-test-password\n', text=True, check=True, capture_output=True)
    sync_log = root/'sync.jsonl'
    env = dict(os.environ, LD_PRELOAD=str(shim), XMPP_SLOW_SYNC_ROOT=str(root/'data'),
               XMPP_SLOW_SYNC_LOG=str(sync_log), XMPP_SLOW_SYNC_MS='0')
    env.pop('XMPP_SYNC_FAIL_SUFFIX', None)
    with (root/'server.log').open('w+') as log:
        records, archives = asyncio.run(seed(root, binary, config, port, log, env))
        journals = journal_bytes(root, suffix)
        assert journals, 'network fixture did not leave requested journals'
        fault_env = dict(env, XMPP_SYNC_FAIL_SUFFIX=suffix)
        before = len(sync_rows(sync_log))
        command = [str(binary), 'storage-checkpoint', str(config)]
        result = subprocess.run(command, env=fault_env, capture_output=True, text=True)
        assert result.returncode != 0, f'{suffix} recovery skipped journal sync and falsely reported successful handoff'
        assert 'Durable native archive handoff:' not in result.stdout, 'failed checkpoint advertised handoff success'
        attempts = [row for row in sync_rows(sync_log)[before:] if row.get('injected')]
        assert attempts and all(row['result'] == -1 for row in attempts), 'recovery did not attempt faulted journal sync'
        assert journal_bytes(root, suffix) == journals, 'failed checkpoint removed or changed authoritative journal'
        if suffix == '.wal':
            before_serve = len(sync_rows(sync_log))
            assert_serve_rejects(binary, config, port, log, fault_env)
            assert any(row.get('injected') and row['store'] == 'sm'
                       for row in sync_rows(sync_log)[before_serve:]), 'serve failed without attempting SM recovery sync'
            assert journal_bytes(root, suffix) == journals, 'failed serve changed authoritative SM journals'
        subprocess.run(command, env=env, check=True, capture_output=True, text=True)
        assert not journal_bytes(root, '.wal') and not journal_bytes(root, '.rredo'), 'successful handoff left journals'
        for token, record in records.items():
            paths = list((root/'data').rglob(token+'.json'))
            assert len(paths) == 1
            exported = json.loads(paths[0].read_text())
            assert {k:v for k,v in exported.items() if k != 'deadline_ms'} == {
                k:v for k,v in record.items() if k != 'deadline_ms'}, 'handoff changed acknowledged SM state'
        assert all(path.read_text() == content for path, content in archives.items()), 'handoff lost acknowledged MAM body'
        return {'suffix': suffix, 'status': 'pass', 'checkpoint_rejected_sync_failure': True,
                'journals_preserved_on_failure': len(journals),
                'serve_rejected_before_listeners': suffix == '.wal',
                'clean_retry_preserved_sessions': len(records), 'clean_retry_preserved_archives': len(archives)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/release/rust-xmpp')
    parser.add_argument('--output', default='/tmp/journal-recovery-sync.json')
    parser.add_argument('--suffix', nargs='+', choices=['.wal', '.rredo'], default=['.wal', '.rredo'])
    args = parser.parse_args()
    report = {'status': 'running', 'cases': []}
    try:
        with tempfile.TemporaryDirectory(prefix='xmpp-journal-recovery-sync-') as directory:
            work = Path(directory)
            binary = work/'rust-xmpp'
            shutil.copy2(Path(args.binary).resolve(), binary)
            report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            shim = work/'slow_sync.so'
            subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                str(Path(__file__).parent/'fixtures'/'slow_sync.c'), '-o', str(shim), '-ldl'], check=True)
            check_shim_scope(work, shim)
            scope_fault(work, shim)
            for suffix in args.suffix:
                report['cases'].append(run_case(work, binary, shim, suffix))
            report['status'] = 'pass'
    except BaseException as error:
        report.update(status='fail', failure=str(error))
        raise
    finally:
        Path(args.output).write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
