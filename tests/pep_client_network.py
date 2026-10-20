#!/usr/bin/env python3
"""Monocles/Conversations PEP request sequences over real loopback STARTTLS.

Usage: python3 tests/pep_client_network.py target/debug/rust-xmpp
Payload shapes follow Monocles IqGenerator and AxolotlService: missing own
bundle must return item-not-found (other errors latch isPepBroken), publishes
omit `to`, and open-access preconditions recover through owner configuration.
Key bytes are opaque transport fixtures, not usable cryptographic bundles.
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

PUBSUB = 'http://jabber.org/protocol/pubsub'
OWNER = PUBSUB + '#owner'
ERROR = PUBSUB + '#errors'
DATA = 'jabber:x:data'
STANZAS = 'urn:ietf:params:xml:ns:xmpp-stanzas'
LEGACY = 'eu.siacs.conversations.axolotl'
OMEMO = 'urn:xmpp:omemo:2'
BUNDLES = OMEMO + ':bundles'


def form(kind, fields):
    values = {'FORM_TYPE': PUBSUB + '#' + kind, **fields}
    return "<x xmlns='jabber:x:data' type='submit'>" + ''.join(
        f"<field var='{key}'><value>{value}</value></field>"
        for key, value in values.items()) + '</x>'


def result(response):
    assert response.get('type') == 'result', ET.tostring(response)
    return response


def condition(response, namespace, name):
    assert response.get('type') == 'error', ET.tostring(response)
    assert next(response.iter(f'{{{namespace}}}{name}'), None) is not None, ET.tostring(response)


def fetch(client, node, item=None, identifier='fetch', target='alice@localhost'):
    selector = '' if item is None else f"<item id='{item}'/>"
    return client.iq(identifier, f"<pubsub xmlns='{PUBSUB}'><items node='{node}'>{selector}</items></pubsub>", target)


def publish(client, node, item, payload, options=None, identifier='publish'):
    options_xml = '' if options is None else '<publish-options>' + form('publish-options', options) + '</publish-options>'
    # IqGenerator.publish deliberately does not set a destination.
    return client.iq(identifier, f"<pubsub xmlns='{PUBSUB}'><publish node='{node}'><item id='{item}'>{payload}</item></publish>{options_xml}</pubsub>", typ='set')


def check_items(client):
    for device in ('123', '456'):
        response = result(fetch(client, BUNDLES, device, 'bundle-' + device))
        items = list(response.iter(f'{{{PUBSUB}}}item'))
        assert [item.get('id') for item in items] == [device], ET.tostring(response)
        bundle = next(response.iter(f'{{{OMEMO}}}bundle'))
        assert bundle.find(f'{{{OMEMO}}}spk').text == 'ZmFrZS1rZXk=' + device, ET.tostring(response)
    for node, namespace, element in ((LEGACY + '.devicelist', LEGACY, 'list'), (OMEMO + ':devices', OMEMO, 'devices')):
        response = result(fetch(client, node))
        devices = next(response.iter(f'{{{namespace}}}{element}'))
        assert {d.get('id') for d in devices} == {'123', '456'}, ET.tostring(response)


def sequence(client):
    # AxolotlService's first own-bundle fetch must never become service-unavailable.
    condition(fetch(client, BUNDLES, '123'), STANZAS, 'item-not-found')
    for node in (LEGACY + '.bundles:123', 'urn:missing:pep'):
        condition(fetch(client, node), STANZAS, 'item-not-found')
    for device in ('123', '456'):
        bundle = f"<bundle xmlns='{OMEMO}'><spk id='1'>ZmFrZS1rZXk={device}</spk><spks>c2ln</spks><ik>aWs=</ik><prekeys><pk id='1'>cGs=</pk></prekeys></bundle>"
        # OMEMO2 shares a node between devices; retain both records explicitly.
        options = {'pubsub#access_model': 'open', 'pubsub#max_items': 'max'}
        result(publish(client, BUNDLES, device, bundle, options))
    for node, namespace, element in ((LEGACY + '.devicelist', LEGACY, 'list'), (OMEMO + ':devices', OMEMO, 'devices')):
        payload = f"<{element} xmlns='{namespace}'><device id='123'/><device id='456'/></{element}>"
        # Existing/migrated presence node: Monocles retries after pushing config.
        response = publish(client, node, 'current', payload, {'pubsub#access_model': 'open'})
        if response.get('type') == 'error':
            condition(response, ERROR, 'precondition-not-met')
            response = result(client.iq('get-config', f"<pubsub xmlns='{OWNER}'><configure node='{node}'/></pubsub>"))
            x = next(response.iter(f'{{{DATA}}}x'))
            x.set('type', 'submit')
            field = next(f for f in x if f.get('var') == 'pubsub#access_model')
            field.find(f'{{{DATA}}}value').text = 'open'
            result(client.iq('set-config', f"<pubsub xmlns='{OWNER}'><configure node='{node}'>" + ET.tostring(x, encoding='unicode') + '</configure></pubsub>', typ='set'))
            result(publish(client, node, 'current', payload, {'pubsub#access_model': 'open'}))
    check_items(client)
    # A missing item on an existing bundle node must also be benign to clients.
    condition(fetch(client, BUNDLES, '999'), STANZAS, 'item-not-found')
    # A PEP routing fix must keep another user's node protected.
    condition(client.iq('other-publish', f"<pubsub xmlns='{PUBSUB}'><publish node='{BUNDLES}'><item id='123'><bundle xmlns='{OMEMO}'/></item></publish></pubsub>", 'bob@localhost', 'set'), STANZAS, 'forbidden')


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-pep-clients-') as tmp:
        root = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for migrated in (False, True):
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            data = root / ('migrated' if migrated else 'fresh')
            config = root / 'config.json'
            config.write_text(json.dumps({'global': {'data_path': str(data), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [], 'modules_enabled': ['tls', 'saslauth', 'pep']}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256', 'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}}}}))
            for user in ('alice', 'bob'):
                subprocess.run([binary, 'create-user', str(config), user, '--password-stdin'], input='secret\n', text=True, check=True, stdout=subprocess.DEVNULL)
            if migrated:
                # Native-like metadata includes fields which previously failed whole-form resubmission.
                store = data / 'localhost' / 'pep' / 'alice.dat'
                store.parent.mkdir(parents=True, exist_ok=True)
                store.write_text('return { ' + ', '.join(f'["{node}"] = {{ config = {{ access_model = "presence", max_items = 1, persist_items = true, notification_type = "normal", itemreply = "publisher", payload_type = "{LEGACY}" }} }}' for node in (LEGACY + '.devicelist', OMEMO + ':devices')) + ' }\n')
            for restart in (False, True):
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
                        assert ('pubsub', 'pep') in identities and PUBSUB + '#publish-options' in features, (features, identities)
                        if restart:
                            check_items(client)
                        else:
                            sequence(client)
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
    print('PASS: TLS Monocles/Conversations PEP first-run, no-to publishing, owner config recovery, migrated metadata, device item selectors and restart persistence')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()))
