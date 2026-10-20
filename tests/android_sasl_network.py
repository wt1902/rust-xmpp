#!/usr/bin/env python3
"""Independent Android SCRAM compatibility regression over real STARTTLS.

Usage: python3 tests/android_sasl_network.py BINARY [--expect-060-failure]
The selector mirrors Conversations ChannelBinding.best (Codeberg master,
retrieved 2026-10-20). TLS 1.3 network cases use the certificate binding;
the faithful Android selector's exporter preference is checked separately.
"""
import base64
import hashlib
import hmac
import json
import itertools
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

SASL = 'urn:ietf:params:xml:ns:xmpp-sasl'
SASL2 = 'urn:xmpp:sasl:2'
CB = 'urn:xmpp:sasl-cb:0'
OPEN = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>"


def android_binding(bindings, version):
    if version == 'TLSv1.3' and 'tls-exporter' in bindings:
        return 'tls-exporter'
    if version in ('TLSv1', 'TLSv1.1', 'TLSv1.2') and 'tls-unique' in bindings:
        return 'tls-unique'
    if 'tls-server-end-point' in bindings:
        return 'tls-server-end-point'
    if not bindings:
        return 'tls-exporter' if version == 'TLSv1.3' else 'tls-unique'
    return None


def b64(data):
    return base64.b64encode(data).decode()


class Connection:
    def __init__(self, port, cert, version):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.buffer = b''
        self.send(OPEN)
        self.until(b'</stream:features>')
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        assert b'proceed' in self.until(b'/>')
        context = ssl.create_default_context(cafile=str(cert))
        context.minimum_version = context.maximum_version = version
        self.sock = context.wrap_socket(self.sock, server_hostname='localhost')
        self.send(OPEN)
        raw = self.until(b'</stream:features>')
        raw = raw[raw.index(b'<stream:features'):]
        self.features = ET.fromstring(b"<root xmlns:stream='http://etherx.jabber.org/streams'>" + raw + b'</root>')

    def send(self, value):
        self.sock.sendall(value.encode())

    def until(self, marker):
        while marker not in self.buffer:
            chunk = self.sock.recv(65536)
            assert chunk, self.buffer
            self.buffer += chunk
        end = self.buffer.index(marker) + len(marker)
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        return result

    def stanza(self):
        # SASL stanzas have no unclosed stream prefix after features.
        parser = ET.XMLPullParser(events=('start', 'end'))
        depth = 0
        while True:
            byte = self.until(b'>')
            parser.feed(byte)
            if hasattr(parser, 'flush'):
                parser.flush()
            for event, node in parser.read_events():
                depth += 1 if event == 'start' else -1
                if event == 'end' and depth == 0:
                    return node

    def auth(self, hash_name, sasl2, wrong_binding=False, expect_old=False, ssdp=True):
        ns = SASL2 if sasl2 else SASL
        parent = self.features.find('.//{' + ns + '}' + ('authentication' if sasl2 else 'mechanisms'))
        mechanisms = [n.text for n in parent.findall('{' + ns + '}mechanism')]
        bindings = [n.get('type') for n in self.features.findall('.//{' + CB + '}channel-binding')]
        selected = android_binding(bindings, self.sock.version())
        if expect_old:
            assert bindings == ['tls-exporter'] and selected is None, bindings
        elif self.sock.version() == 'TLSv1.3':
            assert selected == 'tls-exporter', bindings
            # CPython does not expose TLS exporters. Exercise another real PLUS
            # binding on TLS 1.3, while retaining the selector assertion above.
            assert 'tls-server-end-point' in bindings
            selected = 'tls-server-end-point'
        else:
            assert selected == 'tls-server-end-point', bindings
        mechanism = 'SCRAM-' + hash_name + ('-PLUS' if selected else '')
        assert mechanism in mechanisms
        gs2 = ('p=' + selected + ',,') if selected else 'y,,'
        bare = 'n=alice,r=android-independent-client-nonce'
        initial = b64((gs2 + bare).encode())
        if sasl2:
            self.send(f"<authenticate xmlns='{ns}' mechanism='{mechanism}'><initial-response>{initial}</initial-response></authenticate>")
        else:
            self.send(f"<auth xmlns='{ns}' mechanism='{mechanism}'>{initial}</auth>")
        challenge = self.stanza()
        if expect_old:
            assert challenge.tag == '{' + ns + '}failure', ET.tostring(challenge)
            assert challenge.find('{' + SASL + '}not-authorized') is not None
            return
        assert challenge.tag == '{' + ns + '}challenge', ET.tostring(challenge)
        first = base64.b64decode(challenge.text).decode()
        attrs = dict(item.split('=', 1) for item in first.split(','))
        digest = hash_name.lower().replace('-', '')
        expected_ssdp = '\x1e'.join(sorted(mechanisms)) + '\x1f' + '\x1e'.join(sorted(bindings))
        if ssdp:
            assert attrs['h'] == b64(hashlib.new(digest, expected_ssdp.encode()).digest())
        else:
            assert 'h' not in attrs
        assert attrs['r'].startswith(bare.split('r=', 1)[1])
        assert int(attrs['i']) >= 4096
        # openssl req creates a SHA256-signed certificate; RFC 5929 hashes DER.
        binding = hashlib.sha256(self.sock.getpeercert(binary_form=True)).digest()
        if wrong_binding:
            binding = bytes([binding[0] ^ 1]) + binding[1:]
        final = 'c=' + b64(gs2.encode() + binding) + ',r=' + attrs['r']
        salted = hashlib.pbkdf2_hmac(digest, b'secret', base64.b64decode(attrs['s']), int(attrs['i']))
        mac = lambda key, message: hmac.new(key, message, digest).digest()
        client_key = mac(salted, b'Client Key')
        auth = (bare + ',' + first + ',' + final).encode()
        signature = mac(hashlib.new(digest, client_key).digest(), auth)
        proof = bytes(a ^ b for a, b in zip(client_key, signature))
        self.send(f"<response xmlns='{ns}'>{b64((final + ',p=' + b64(proof)).encode())}</response>")
        result = self.stanza()
        if wrong_binding:
            assert result.tag == '{' + ns + '}failure', ET.tostring(result)
            assert result.find('{' + SASL + '}not-authorized') is not None
        else:
            assert result.tag == '{' + ns + '}success', ET.tostring(result)
            payload = result.findtext('{' + ns + '}additional-data') if sasl2 else result.text
            expected = 'v=' + b64(mac(mac(salted, b'Server Key'), auth))
            assert base64.b64decode(payload).decode() == expected


def run(binary, old=False):
    assert android_binding(['tls-exporter'], 'TLSv1.2') is None
    assert android_binding(['tls-exporter'], 'TLSv1.3') == 'tls-exporter'
    for hash_name, ssdp in itertools.product(('SHA-1', 'SHA-256'), (True,) if old else (False, True)):
        with tempfile.TemporaryDirectory(prefix='xmpp-android-sasl-') as tmp:
            root = Path(tmp)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            cfg = {'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port], 'http_ports': [], 'https_ports': [], 's2s_ports': [], 'modules_enabled': ['tls', 'saslauth', 'sasl2'] + (['sasl_ssdp'] if ssdp else [])}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': hash_name, 'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}}}}
            config = root/'config.json'
            config.write_text(json.dumps(cfg))
            subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'], input='secret\n', text=True, check=True, capture_output=True)
            with (root/'server.log').open('w+') as log:
                process = subprocess.Popen([binary, 'serve', str(config), '--experimental'], stdout=log, stderr=log)
                try:
                    for _ in range(100):
                        assert process.poll() is None, 'server stopped'
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                break
                        except OSError:
                            time.sleep(.05)
                    versions = [ssl.TLSVersion.TLSv1_2] if old else [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]
                    for version in versions:
                        for sasl2 in (False, True):
                            for wrong in ([False] if old else [False, True]):
                                connection = Connection(port, root/'cert.pem', version)
                                try:
                                    connection.auth(hash_name, sasl2, wrong, old, ssdp)
                                finally:
                                    connection.sock.close()
                except BaseException:
                    log.flush(); log.seek(0); print(log.read())
                    raise
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait()
    print('PASS: reproduced 0.6.0 TLS1.2 Android y,, rejection' if old else 'PASS: Android TLS1.2 selector, TLS1.2/1.3 SCRAM SHA1/256 PLUS, SASL1/2, SSDP on/off and invalid binding rejection')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()), '--expect-060-failure' in sys.argv[2:])
