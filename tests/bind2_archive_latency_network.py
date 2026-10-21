#!/usr/bin/env python3
"""Measure real TLS/SASL2 Bind2 reconnects with a large personal MAM history.

Usage: python3 tests/bind2_archive_latency_network.py --binary BINARY \
    --records 100000 --output REPORT.json

Seeds valid native records before startup, then checks exact first/last metadata
on every fresh connection. Latency measurements have no performance threshold.
The executable is copied before use so concurrent rebuilds cannot replace it.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import socket
import statistics
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from sasl2_bind import BIND2, SASL2, Client

MAM = 'urn:xmpp:mam:2'
BASE_TIME = 1767225600


def stamp(seconds):
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def distribution(values):
    ordered = sorted(values)
    return {'samples_ms': values, 'median_ms': statistics.median(values),
            'p95_ms': ordered[min(len(ordered) - 1, int(len(ordered) * .95))],
            'max_ms': ordered[-1]}


def exercise(binary, root, records, samples):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                    '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                    '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(root/'key.pem'),
                    '-out', str(root/'cert.pem')], check=True, capture_output=True)
    config = root/'config.json'
    config.write_text(json.dumps({'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'],
        'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [],
        'modules_enabled': ['tls', 'saslauth', 'sasl2', 'sasl2_bind2', 'mam', 'carbons', 'csi_simple', 'smacks'],
        'default_archive_policy': True, 'archive_expires_after': 'never'},
        'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256',
            'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}}}}))
    subprocess.run([str(binary), 'create-user', str(config), 'alice', '--password-stdin'],
                   input='secret\n', text=True, check=True, capture_output=True)
    archive = root/'data'/'localhost'/'archive'/'alice.list'
    archive.parent.mkdir(parents=True, exist_ok=True)
    with archive.open('w') as output:
        for number in range(records):
            output.write("item({name='message';attr={xmlns='jabber:client';type='chat';"
                         f"from='bob@localhost';stamp='{stamp(BASE_TIME + number)}'" + "};"
                         f"key='seed-{number}';when={BASE_TIME + number};with='bob@localhost';"
                         "{name='body';attr={};'seed personal history'}});\n")
    expected = {'start': {'id': 'seed-0', 'timestamp': stamp(BASE_TIME)},
                'end': {'id': f'seed-{records - 1}', 'timestamp': stamp(BASE_TIME + records - 1)}}
    archive_bytes = archive.stat().st_size
    index_before_start = archive.with_suffix('.lidx').exists()
    assert not index_before_start, 'seed unexpectedly has a native index'
    auth_ms, connect_ms, metadata_ms = [], [], []
    metadata_samples, iq_metadata_samples = [], []
    with (root/'server.log').open('w+') as log:
        server = subprocess.Popen([str(binary), 'serve', str(config), '--experimental'], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while True:
                assert server.poll() is None, 'server stopped before readiness'
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, 'server did not start'
                    time.sleep(.05)
            for sample in range(samples):
                # Each sample reconnects and authenticates the same account.
                # Client verifies the advertised SASL2/Bind2 inline features.
                connected = time.perf_counter()
                client = Client(port, root/'cert.pem')
                client.sock.settimeout(30)
                try:
                    begun = time.perf_counter()
                    response = client.auth(f"<bind xmlns='{BIND2}'><tag>HistoryReconnect</tag></bind>")
                    arrived = time.perf_counter()
                    auth_ms.append((arrived - begun) * 1000)
                    connect_ms.append((arrived - connected) * 1000)
                    jid = response.find('{' + SASL2 + '}authorization-identifier')
                    assert jid is not None and jid.text.startswith('alice@localhost/HistoryReconnect/'), 'missing bound JID'
                    bound = response.find('{' + BIND2 + '}bound')
                    assert bound is not None, 'missing Bind2 bound result'
                    metadata = bound.find('{' + MAM + '}metadata')
                    assert metadata is not None, 'missing MAM metadata'
                    actual = {}
                    for edge in ('start', 'end'):
                        node = metadata.find('{' + MAM + '}' + edge)
                        assert node is not None, f'missing MAM {edge}'
                        actual[edge] = dict(node.attrib)
                    assert actual == expected, (actual, expected)
                    assert len(list(metadata)) == 2, 'unexpected MAM metadata children'
                    metadata_samples.append(actual)
                    # Session is immediately bound; the post-success features
                    # must not ask this client to perform legacy resource bind.
                    assert b'xmpp-bind' not in client.until(b'</stream:features>')
                    query_id = f'metadata-{sample}'
                    begun = time.perf_counter()
                    client.send(f"<iq type='get' id='{query_id}'><metadata xmlns='{MAM}'/></iq>")
                    iq = ET.fromstring(client.until(b'</iq>'))
                    metadata_ms.append((time.perf_counter() - begun) * 1000)
                    assert iq.get('type') == 'result' and iq.get('id') == query_id, 'metadata IQ failed'
                    iq_metadata = iq.find('{' + MAM + '}metadata')
                    assert iq_metadata is not None, 'metadata IQ payload missing'
                    iq_actual = {}
                    for edge in ('start', 'end'):
                        node = iq_metadata.find('{' + MAM + '}' + edge)
                        assert node is not None, f'missing metadata IQ {edge}'
                        iq_actual[edge] = dict(node.attrib)
                    assert iq_actual == expected, (iq_actual, expected)
                    assert len(list(iq_metadata)) == 2, 'unexpected metadata IQ children'
                    iq_metadata_samples.append(iq_actual)
                finally:
                    client.close()
            assert archive.stat().st_size == archive_bytes, 'reconnect modified seeded history'
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
    return {'status': 'pass', 'seeded_personal_archive_records': records, 'archive_bytes': archive_bytes,
            'archive_expires_after': 'never', 'index_present_before_start': index_before_start,
            'reconnect_samples': samples, 'expected_metadata': expected, 'observed_metadata': metadata_samples,
            'mam_metadata_iq': distribution(metadata_ms), 'observed_iq_metadata': iq_metadata_samples,
            'sasl2_bind2_success': distribution(auth_ms), 'tcp_starttls_to_bind2_success': distribution(connect_ms)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--records', type=int, default=100000)
    parser.add_argument('--samples', type=int, default=10)
    parser.add_argument('--output')
    args = parser.parse_args()
    assert args.records > 0 and args.samples > 0
    source = Path(args.binary).resolve()
    with tempfile.TemporaryDirectory(prefix='xmpp-bind2-archive-latency-') as directory:
        root = Path(directory)
        binary = root/'rust-xmpp'
        shutil.copy2(source, binary)
        report = {'binary_source': str(source), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                  'scope': 'real loopback TCP/STARTTLS/SASL2 Bind2; isolated personal MAM fixture; no production latency claim',
                  'timing': 'raw ordered samples; auth timer starts before authenticate and ends at parsed success; full timer includes TCP/STARTTLS/features; metadata IQ timer runs from send to parsed result',
                  'result': exercise(binary, root, args.records, args.samples)}
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        Path(args.output).write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
