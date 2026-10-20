#!/usr/bin/env python3
"""Legacy Android first-item PEP parsing over real loopback STARTTLS.

Usage: python3 tests/pep_order_network.py target/debug/rust-xmpp
Monocles IqGenerator.retrieveDeviceIds requests every item without max_items;
IqParser.getItem returns only the first item, then deviceIds reads its list.
An older empty record must not hide the latest populated device list.
"""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

from push_discovery import Client
from pep_client_network import LEGACY, PUBSUB, fetch, publish, result

NODE = LEGACY + '.devicelist'
DEVICE_IDS = ('2073401123', '2073401456', '2073401789')


def check_android_fetch(client, expected):
    response = result(fetch(client, NODE, identifier='own-device-list'))
    # Match IqParser.getItem: do not search all descendants or merge item lists.
    items = response.find(f'{{{PUBSUB}}}pubsub/{{{PUBSUB}}}items')
    assert items is not None, ET.tostring(response)
    first = items.find(f'{{{PUBSUB}}}item')
    assert first is not None and first.get('id') == 'current', ET.tostring(response)
    device_list = first.find(f'{{{LEGACY}}}list')
    assert device_list is not None, ET.tostring(response)
    device_ids = {device.get('id') for device in device_list
                  if device.tag == f'{{{LEGACY}}}device'}
    assert device_ids == expected, ET.tostring(response)
    # Retain the old record to exercise real multi-item ordering, not truncation.
    assert [item.get('id') for item in items] == ['current', 'older'], ET.tostring(response)


def check_info_log(path, expected_reads):
    deadline = time.monotonic() + 5
    while True:
        text = path.read_text() if path.exists() else ''
        records = [json.loads(line) for line in text.splitlines()]
        reads = []
        for record in records:
            if record.get('event') != 'pubsub-iq-result':
                continue
            fields = {field['key']: field['value'] for field in record['fields']}
            if fields.get('action') == 'items':
                reads.append((record, fields))
        if len(reads) >= expected_reads:
            break
        assert time.monotonic() < deadline, 'missing PEP info log records'
        time.sleep(.02)
    assert len(reads) == expected_reads, 'unexpected PEP retrieval count'
    for record, fields in reads:
        assert record['level'] == 'info', record
        for key, value in {'status': 'result', 'items_count': '2',
                           'first_content_kind': 'omemo-devices',
                           'first_device_count': '2',
                           'target_scope': 'self-account'}.items():
            assert fields.get(key) == value, (key, fields)
    assert all(device not in text for device in DEVICE_IDS), 'device ID leaked in info logs'
    assert LEGACY not in text, 'raw PEP node leaked in info logs'


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-pep-order-') as tmp:
        root = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        config = root/'config.json'
        config.write_text(json.dumps({'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [], 'modules_enabled': ['tls', 'saslauth', 'pep'], 'log_format': 'json', 'log': {'info': str(root/'structured.jsonl')}}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256', 'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}}}}))
        subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'], input='secret\n', text=True, check=True, stdout=subprocess.DEVNULL)
        for restart in (False, True):
            info_log = root/'structured.jsonl'
            if info_log.exists():
                info_log.unlink()
            with (root/'server.log').open('w+') as log:
                server = subprocess.Popen([binary, 'serve', str(config), '--experimental'], stdout=log, stderr=log)
                client = None
                try:
                    for _ in range(100):
                        assert server.poll() is None, 'server stopped'
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                break
                        except OSError:
                            time.sleep(.05)
                    else:
                        raise AssertionError('server did not start')
                    client = Client(port, root/'cert.pem')
                    features, identities = client.disco('own-pep', 'alice@localhost')
                    assert ('pubsub', 'pep') in identities and PUBSUB + '#persistent-items' in features
                    if not restart:
                        # Existing device-list nodes can retain multiple differently named
                        # records. The older item is intentionally a valid empty list.
                        result(publish(client, NODE, 'older', f"<list xmlns='{LEGACY}'/>", {'pubsub#max_items': '3'}))
                        result(publish(client, NODE, 'current', f"<list xmlns='{LEGACY}'><device id='2073401123'/><device id='2073401456'/></list>"))
                        check_android_fetch(client, set(DEVICE_IDS[:2]))
                        # Monocles publishes id=current, then reads its own node without
                        # an item selector. Replacement must remain the first record.
                        result(publish(client, NODE, 'current', f"<list xmlns='{LEGACY}'><device id='2073401123'/><device id='2073401789'/></list>"))
                    check_android_fetch(client, {DEVICE_IDS[0], DEVICE_IDS[2]})
                    check_info_log(info_log, 1 if restart else 2)
                finally:
                    if client is not None:
                        client.sock.close()
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()
                    if sys.exc_info()[0] is not None:
                        log.seek(0)
                        print(log.read(), file=sys.stderr)
    print('PASS: Android first-item device-list parsing sees latest publish and replacement before and after restart')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()))
