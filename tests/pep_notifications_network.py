#!/usr/bin/env python3
"""Real STARTTLS regression for private PEP notification diagnostics.

Usage: python3 tests/pep_notifications_network.py target/release/rust-xmpp
Exercises generated notifications, payload suppression and matching IQ results.
The fixtures demonstrate diagnostic coverage, not a production root cause.
"""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from _wire_client import Client

PUBSUB = 'http://jabber.org/protocol/pubsub'
EVENT = PUBSUB + '#event'
OWNER = PUBSUB + '#owner'
LEGACY = 'eu.siacs.conversations.axolotl'
OMEMO2 = 'urn:xmpp:omemo:2'
PRIVATE_ITEM = 'private-diagnostic-item-607b'
PRIVATE_KEY = 'PRIVATE-KEY-MATERIAL-952a'
VALID_ID = '1937264819'
BAD_ID = 'private-invalid-id-65d2'


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def fields(record):
    return {f['key']: f['value'] for f in record['fields']}


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def wait_event(path, start, expected):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        events = [r for r in records(path)[start:]
                  if r.get('event') == 'notification-generated']
        for event in events:
            actual = fields(event)
            if all(actual.get(k) == v for k, v in expected.items()):
                require(event.get('module') == 'pep', 'wrong notification log module')
                require(event.get('connection') is None, 'notification log acquired an account context')
                return
        time.sleep(.02)
    raise AssertionError('required private notification diagnostic was not generated')


def iq(client, identifier, payload, typ='set'):
    client.send(f"<iq type='{typ}' id='{identifier}'>{payload}</iq>")
    return client.iq(identifier)


def publish(client, node, payload, identifier):
    return iq(client, identifier, f"<pubsub xmlns='{PUBSUB}'><publish node='{node}'><item id='{PRIVATE_ITEM}'>{payload}</item></publish></pubsub>")


def notification(client, node):
    # Client.take preserves unrelated IQs/messages and handles either wire order.
    message = client.take(lambda e: e.tag == '{jabber:client}message'
                          and e.find(f'{{{EVENT}}}event/{{{EVENT}}}items') is not None
                          and e.find(f'{{{EVENT}}}event/{{{EVENT}}}items').get('node') == node)
    require(message.get('from') == 'alice@localhost', 'notification sender must be account bare JID')
    wrapper = message.find(f'{{{EVENT}}}event/{{{EVENT}}}items')
    items = wrapper.findall(f'{{{EVENT}}}item')
    require(len(items) == 1, 'expected exactly one wire notification item')
    return items[0]


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-pep-notifications-') as tmp:
        root = Path(tmp)
        cert = root / 'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-keyout', str(root / 'key.pem'), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        log_path = root / 'structured.jsonl'
        config = root / 'config.json'
        config.write_text(json.dumps({'global': {
            'data_path': str(root / 'data'), 'interfaces': ['127.0.0.1'],
            'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [],
            'modules_enabled': ['tls', 'saslauth', 'pep'],
            'log_format': 'json', 'log': {'debug': str(log_path)}},
            'hosts': {'localhost': {'options': {
                'authentication': 'internal_hashed', 'password_hash': 'SHA-256',
                'ssl': {'key': str(root / 'key.pem'), 'certificate': str(cert)}}}}}))
        subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'],
                       input='secret\n', text=True, check=True, capture_output=True)
        with (root / 'process.log').open('w') as output:
            process = subprocess.Popen([binary, 'serve', str(config), '--experimental'],
                                       stdout=output, stderr=output)
            client = None
            try:
                for _ in range(100):
                    require(process.poll() is None, 'fixture server stopped')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError('fixture server did not listen')
                client = Client(port, cert, 'alice', 'secret', resource='notification-test')
                for index, (node, namespace, element, protocol) in enumerate([
                        (LEGACY + '.devicelist', LEGACY, 'list', 'legacy'),
                        (OMEMO2 + ':devices', OMEMO2, 'devices', 'omemo2')]):
                    payload = f"<{element} xmlns='{namespace}'><device id='{VALID_ID}'/><device id='{VALID_ID}'/><device id='{BAD_ID}'/><key>{PRIVATE_KEY}</key></{element}>"
                    publish(client, node, payload, f'initial-{index}')
                    start = len(records(log_path))
                    iq(client, f'subscribe-{index}', f"<pubsub xmlns='{PUBSUB}'><subscribe node='{node}' jid='{client.jid}'/></pubsub>")
                    item = notification(client, node)
                    require(item.find(f'{{{namespace}}}{element}') is not None,
                            'replayed wire notification lost the published device payload')
                    wait_event(log_path, start, {'node_kind': 'omemo-devices', 'device_protocol': protocol,
                               'valid_device_count': '1', 'invalid_device_count': '1',
                               'content_present': 'true', 'items_count': '1'})

                    # Successful IQ retrieval and payloadless notifications can coexist.
                    form = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#deliver_payloads'><value>false</value></field></x>"
                    iq(client, f'configure-{index}', f"<pubsub xmlns='{OWNER}'><configure node='{node}'>{form}</configure></pubsub>")
                    start = len(records(log_path))
                    publish(client, node, payload, f'payloadless-{index}')
                    require(len(notification(client, node)) == 0,
                            'deliver_payloads=false did not suppress wire payload')
                    wait_event(log_path, start, {'node_kind': 'omemo-devices', 'device_protocol': 'other',
                               'valid_device_count': '0', 'invalid_device_count': '0',
                               'content_present': 'false', 'items_count': '1'})
                    response = iq(client, f'fetch-{index}', f"<pubsub xmlns='{PUBSUB}'><items node='{node}'/></pubsub>", typ='get')
                    require(response.find(f'{{{PUBSUB}}}pubsub/{{{PUBSUB}}}items/{{{PUBSUB}}}item/{{{namespace}}}{element}') is not None,
                            'payload suppression unexpectedly removed stored IQ payload')

                diagnostics = [r for r in records(log_path)
                               if r.get('event') in ('pubsub-iq-result', 'notification-generated')]
                serialized = json.dumps(diagnostics)
                for secret in (PRIVATE_ITEM, PRIVATE_KEY, VALID_ID, BAD_ID):
                    require(secret not in serialized, 'private fixture value leaked into PEP diagnostics')
                iq_rows = [fields(r) for r in diagnostics if r['event'] == 'pubsub-iq-result']
                for protocol in ('legacy', 'omemo2'):
                    require(any(f.get('action') == 'items' and f.get('device_protocol') == protocol
                                and f.get('valid_device_count') == '1'
                                and f.get('invalid_device_count') == '1' for f in iq_rows),
                            'successful IQ device parser diagnostic missing')
            finally:
                if client is not None:
                    client.close()
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    print('PASS: STARTTLS PEP replay/live diagnostics, legacy/OMEMO2, payloadless notifications with intact IQ payloads, and private values excluded')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()))
