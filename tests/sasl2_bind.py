#!/usr/bin/env python3
"""Independent TLS/SASL2 Bind2 network regression. Usage: python3 tests/sasl2_bind.py BINARY."""
import base64
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

SASL2 = 'urn:xmpp:sasl:2'
BIND2 = 'urn:xmpp:bind:0'
SASL = 'urn:ietf:params:xml:ns:xmpp-sasl'
STREAM = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>"


class Client:
    def __init__(self, port, cert):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.buffer = b''
        self.send(STREAM)
        self.until(b'</stream:features>')
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        assert b'proceed' in self.until(b'/>')
        self.sock = ssl.create_default_context(cafile=str(cert)).wrap_socket(self.sock, server_hostname='localhost')
        self.send(STREAM)
        features = self.until(b'</stream:features>')
        features = features[features.index(b'<stream:features'):]
        root = ET.fromstring(b"<root xmlns:stream='http://etherx.jabber.org/streams'>" + features + b'</root>')
        bind = root.find('.//{' + SASL2 + '}authentication/{' + SASL2 + '}inline/{' + BIND2 + '}bind')
        assert bind is not None, features
        advertised = {node.get('var') for node in bind.findall('{' + BIND2 + '}inline/{' + BIND2 + '}feature')}
        assert advertised == {'urn:xmpp:carbons:2', 'urn:xmpp:csi:0', 'urn:xmpp:sm:3'}, advertised

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

    def auth(self, bind='', password='secret', good=True, user='alice', agent='private-device-id'):
        payload = base64.b64encode(('\0' + user + '\0' + password).encode()).decode()
        self.send(f"<authenticate xmlns='{SASL2}' mechanism='PLAIN'><initial-response>{payload}</initial-response><user-agent id='{agent}'/>{bind}</authenticate>")
        return ET.fromstring(self.until(b'</success>' if good else b'</failure>'))

    def close(self):
        self.sock.close()


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-bind2-') as tmp:
        root = Path(tmp)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cfg = {'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [], 'modules_enabled': ['tls', 'saslauth', 'sasl2', 'sasl2_bind2', 'mam', 'carbons', 'csi_simple', 'smacks']}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256', 'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}}}}
        config = root/'config.json'
        config.write_text(json.dumps(cfg))
        subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'], input='secret\n', text=True, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([binary, 'create-user', str(config), 'bob', '--password-stdin'], input='secret\n', text=True, check=True, stdout=subprocess.DEVNULL)
        with (root/'server.log').open('w+') as log:
            server = subprocess.Popen([binary, 'serve', str(config), '--experimental'], stdout=log, stderr=log)
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
                resources = []
                for _ in range(2):
                    c = Client(port, root/'cert.pem')
                    try:
                        response = c.auth(f"<bind xmlns='{BIND2}'><tag>Phone&amp;Tablet</tag><enable xmlns='urn:xmpp:carbons:2'/><inactive xmlns='urn:xmpp:csi:0'/><enable xmlns='urn:xmpp:sm:3' resume='true'/></bind>")
                        jid = response.find('{' + SASL2 + '}authorization-identifier').text
                        assert jid.startswith('alice@localhost/Phone&Tablet/'), jid
                        assert 'private-device-id' not in jid
                        resource = jid.split('/Phone&Tablet/')[1]
                        assert uuid.UUID(resource).version == 4
                        resources.append(resource)
                        bound = response.find('{' + BIND2 + '}bound')
                        assert bound is not None
                        assert bound.find('{urn:xmpp:mam:2}metadata') is not None
                        assert bound.find('{urn:xmpp:carbons:2}enabled') is not None
                        assert bound.find('{urn:xmpp:sm:3}enabled').get('resume') == 'true'
                        assert b'xmpp-bind' not in c.until(b'</stream:features>')
                        # No legacy bind IQ: the session is already usable and SM enabled.
                        c.send("<r xmlns='urn:xmpp:sm:3'/>")
                        assert ET.fromstring(c.until(b'/>')).tag == '{urn:xmpp:sm:3}a'
                    finally:
                        c.close()
                assert resources[0] != resources[1]
                invalid = [f"<bind xmlns='{BIND2}'/><bind xmlns='{BIND2}'/>", f"<bind xmlns='{BIND2}'><tag>a</tag><tag>b</tag></bind>", f"<bind xmlns='{BIND2}'><tag>{'x'*987}</tag></bind>", f"<bind xmlns='{BIND2}'><tag>bad\ue000</tag></bind>", f"<bind xmlns='{BIND2}'><tag><nested/></tag></bind>", f"<bind xmlns='{BIND2}'><enable xmlns='urn:xmpp:sm:3' resume='yes'/></bind>"]
                for request in invalid:
                    c = Client(port, root/'cert.pem')
                    try:
                        response = c.auth(request, good=False)
                        assert response.find('{' + SASL + '}malformed-request') is not None, ET.tostring(response)
                        # Malformed inline requests cannot leave a partially bound session.
                        response = c.auth()
                        assert response.find('{' + BIND2 + '}bound') is None
                        assert response.find('{' + SASL2 + '}authorization-identifier').text == 'alice@localhost'
                        assert b'xmpp-bind' in c.until(b'</stream:features>')
                    finally:
                        c.close()
                c = Client(port, root/'cert.pem')
                try:
                    response = c.auth(f"<bind xmlns='{BIND2}'/>", password='wrong', good=False)
                    assert response.find('{' + SASL + '}not-authorized') is not None
                    assert response.find('{' + BIND2 + '}bound') is None
                    response = c.auth(f"<bind xmlns='{BIND2}'/>")
                    jid = response.find('{' + SASL2 + '}authorization-identifier').text
                    assert uuid.UUID(jid.split('/', 1)[1]).version == 4
                finally:
                    c.close()
                # Device replacement affects only this account and valid UUIDv4 ids.
                connections = []
                device = 'd4565fa7-4d72-4749-b3d3-740edbf87770'
                def bound_client(user, agent):
                    client = Client(port, root/'cert.pem')
                    connections.append(client)
                    response = client.auth(f"<bind xmlns='{BIND2}'><enable xmlns='urn:xmpp:sm:3' resume='true'/></bind>", user=user, agent=agent)
                    jid = response.find('{' + SASL2 + '}authorization-identifier').text
                    assert agent not in jid
                    client.until(b'</stream:features>')
                    return client
                def ping(client):
                    client.send("<r xmlns='urn:xmpp:sm:3'/>")
                    assert ET.fromstring(client.until(b'/>')).tag == '{urn:xmpp:sm:3}a'
                try:
                    other = bound_client('bob', device)
                    old = bound_client('alice', device.upper())
                    invalid_first = bound_client('alice', 'not-a-uuid')
                    invalid_second = bound_client('alice', 'not-a-uuid')
                    ping(invalid_first)
                    fresh = bound_client('alice', device)
                    old.sock.settimeout(2)
                    old.until(b'</stream:stream>')
                    assert old.sock.recv(1) == b'', 'old device stream remained open'
                    for client in [fresh, other, invalid_first, invalid_second]:
                        ping(client)
                finally:
                    for client in connections:
                        client.close()
                print('PASS: SASL2 Bind2 TLS flow, inline SM/CSI/Carbons, private random resource, malformed requests, authentication failure and fallback')
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
                if server.returncode not in (0, -15):
                    log.seek(0)
                    print(log.read(), file=sys.stderr)


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()))
