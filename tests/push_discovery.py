#!/usr/bin/env python3
"""TLS wire regression for XEP-0357 account discovery and registrations.

Usage: python3 tests/push_discovery.py target/debug/rust-xmpp
Uses only Python's standard library and openssl; creates isolated server/data.
Actual notification serialization/delivery lifecycle is covered by tests/push.rs.
"""
import base64
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

DISCO = 'http://jabber.org/protocol/disco#info'
PUSH = 'urn:xmpp:push:0'
STREAM = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>"


class Client:
    def __init__(self, port, cert):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.buffer = b''
        self.send(STREAM)
        self.until(b'</stream:features>')
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        assert b'proceed' in self.until(b'>')
        self.sock = ssl.create_default_context(cafile=str(cert)).wrap_socket(self.sock, server_hostname='localhost')
        self.send(STREAM)
        self.until(b'</stream:features>')
        credentials = base64.b64encode(b'\0alice\0secret').decode()
        self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{credentials}</auth>")
        assert b'success' in self.until(b'>')
        self.send(STREAM)
        self.until(b'</stream:features>')
        response = self.iq('bind', "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>phone</resource></bind>", typ='set')
        assert response.get('type') == 'result', ET.tostring(response)

    def send(self, xml):
        self.sock.sendall(xml.encode())

    def until(self, marker):
        while marker not in self.buffer:
            chunk = self.sock.recv(65536)
            assert chunk, self.buffer
            self.buffer += chunk
        end = self.buffer.index(marker) + len(marker)
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        return result

    def iq(self, identifier, payload, to=None, typ='get'):
        target = f" to='{to}'" if to is not None else ''
        self.send(f"<iq type='{typ}' id='{identifier}'{target}>{payload}</iq>")
        while True:
            response = ET.fromstring(self.until(b'</iq>'))
            if response.get('id') == identifier:
                return response

    def disco(self, identifier, to=None):
        response = self.iq(identifier, f"<query xmlns='{DISCO}'/>", to)
        assert response.get('type') == 'result', ET.tostring(response)
        query = response.find('{' + DISCO + '}query')
        assert query is not None, ET.tostring(response)
        features = {node.get('var') for node in query.findall('{' + DISCO + '}feature')}
        identities = {(node.get('category'), node.get('type')) for node in query.findall('{' + DISCO + '}identity')}
        assert ('pubsub', 'push') not in identities, identities
        return features, identities


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-push-disco-') as tmp:
        root = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for pep in (False, True):
            for push in (False, True):
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 0))
                    port = probe.getsockname()[1]
                data = root / f'data-pep{pep}-push{push}'
                modules = ['tls', 'saslauth'] + (['pep'] if pep else []) + (['cloud_notify'] if push else [])
                cfg = {'global': {'data_path': str(data), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [], 'modules_enabled': modules}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256', 'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}}}}
                config = root/'config.json'
                config.write_text(json.dumps(cfg))
                for user in ('alice', 'bob'):
                    subprocess.run([binary, 'create-user', str(config), user, '--password-stdin'], input='secret\n', text=True, check=True, stdout=subprocess.DEVNULL)
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
                        features, identities = client.disco('own-account', 'alice@localhost')
                        assert (PUSH in features) == push, (pep, push, features)
                        assert ('account', 'registered') in identities, identities
                        monal_pep_features = {'http://jabber.org/protocol/pubsub#' + name for name in ['filtered-notifications','publish-options','publish','subscribe','create-nodes','delete-items','delete-nodes','persistent-items','retrieve-items','auto-create']}
                        assert ((('pubsub','pep') in identities) and monal_pep_features <= features) == pep, (pep, features, identities)
                        if pep:
                            assert {'http://jabber.org/protocol/pubsub#item-ids','http://jabber.org/protocol/pubsub#multi-items','http://jabber.org/protocol/pubsub#config-node-max'} <= features

                        # Legacy clients query no-to/domain as well. These remain server discovery.
                        for identifier, target in [('implicit-domain', None), ('domain', 'localhost')]:
                            _, identities = client.disco(identifier, target)
                            assert ('server', 'im') in identities, identities
                        other = client.iq('other-account', f"<query xmlns='{DISCO}'/>", 'bob@localhost')
                        assert all(node.get('var') != PUSH for node in other.iter('{' + DISCO + '}feature')), ET.tostring(other)
                        for node in ('phone', 'tablet'):
                            response = client.iq('enable-' + node, f"<enable xmlns='{PUSH}' jid='push.example.test' node='{node}'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='secret'><value>credential-{node}</value></field></x></enable>", 'alice@localhost', 'set')
                            assert response.get('type') == ('result' if push else 'error'), ET.tostring(response)
                        if push:
                            stored = next(data.glob('*/cloud_notify/*.dat'))
                            text = stored.read_text()
                            assert 'phone' in text and 'tablet' in text and 'credential-phone' in text, text
                            response = client.iq('disable-one', f"<disable xmlns='{PUSH}' jid='push.example.test' node='phone'/>", 'alice@localhost', 'set')
                            assert response.get('type') == 'result', ET.tostring(response)
                            text = stored.read_text()
                            assert 'push.example.test<phone' not in text and 'credential-phone' not in text and 'push.example.test<tablet' in text, text
                            response = client.iq('disable-all', f"<disable xmlns='{PUSH}' jid='push.example.test'/>", 'alice@localhost', 'set')
                            assert response.get('type') == 'result', ET.tostring(response)
                            assert not stored.exists() or 'push.example.test' not in stored.read_text()
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
        print('PASS: TLS account/domain discovery with PEP and push enabled/disabled; real push enable, publish options, per-node and service-wide disable')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()))
