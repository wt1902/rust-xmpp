#!/usr/bin/env python3
"""Independent TLS regression for SASL2 inline SM resume. Usage: script BINARY."""
import json
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from sasl2_bind import Client as BindClient, SASL2, BIND2, SASL

SM = 'urn:xmpp:sm:3'


class Client(BindClient):
    def until(self, marker):
        xml = super().until(marker)
        if b'<authentication' in xml:
            features = xml[xml.index(b'<stream:features'):]
            root = ET.fromstring(b"<root xmlns:stream='http://etherx.jabber.org/streams'>" + features + b'</root>')
            assert root.find('.//{' + SASL2 + '}inline/{' + SM + '}sm') is not None, features
        return xml

    def ping(self, ident):
        self.send(f"<iq type='get' id='{ident}' to='localhost'><ping xmlns='urn:xmpp:ping'/></iq>")
        result = self.until(b'</iq>')
        assert b"type='result'" in result and f"id='{ident}'".encode() in result, result
        return result


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-sasl2-resume-') as tmp:
        root = Path(tmp)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cfg = {'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [], 'modules_enabled': ['tls', 'saslauth', 'sasl2', 'sasl2_bind2', 'carbons', 'csi_simple', 'smacks', 'ping']}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256', 'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}}}}
        config = root/'config.json'
        config.write_text(json.dumps(cfg))
        for user in ['alice', 'bob']:
            subprocess.run([binary, 'create-user', str(config), user, '--password-stdin'], input='secret\n', text=True, check=True, stdout=subprocess.DEVNULL)
        clients = []
        def connect():
            client = Client(port, root/'cert.pem')
            clients.append(client)
            return client
        def request(token, h=0):
            return f"<resume xmlns='{SM}' previd='{token}' h='{h}'/>"
        bind = f"<bind xmlns='{BIND2}'><tag>Phone</tag><enable xmlns='{SM}' resume='true'/></bind>"
        def assert_resume(response, token, jid):
            assert response.find(f'{{{SASL2}}}authorization-identifier').text == jid, ET.tostring(response)
            resumed = response.find(f'{{{SM}}}resumed')
            assert resumed is not None and resumed.get('previd') == token, ET.tostring(response)
            assert response.find(f'{{{BIND2}}}bound') is None, ET.tostring(response)
            assert response.find(f'{{{SM}}}failed') is None, ET.tostring(response)
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
                old = connect()
                response = old.auth(bind)
                jid = response.find(f'{{{SASL2}}}authorization-identifier').text
                token = response.find(f'{{{BIND2}}}bound/{{{SM}}}enabled').get('id')
                old.until(b'</stream:features>')
                old.ping('acknowledged')
                old.ping('pending')
                # Wrong credentials must not take over an active session.
                bad = connect()
                failure = bad.auth(request(token) + bind, password='wrong', good=False)
                assert failure.find(f'{{{SASL}}}not-authorized') is not None
                old.send(f"<r xmlns='{SM}'/>")
                assert ET.fromstring(old.until(b'/>')).tag == f'{{{SM}}}a'
                # Wrong owner, unknown id and impossible acknowledgement fail inside
                # success and retain optional Bind2 fallback. Failed requests leave
                # the original session and its pending queue untouched.
                for user, ident, h, fallback in [('bob', token, 0, True), ('alice', 'missing', 0, True), ('alice', token, 99, False)]:
                    failed = connect()
                    response = failed.auth(request(ident, h) + (bind if fallback else ''), user=user)
                    assert response.find(f'{{{SM}}}failed') is not None, ET.tostring(response)
                    assert response.find(f'{{{SM}}}resumed') is None
                    assert (response.find(f'{{{BIND2}}}bound') is not None) == fallback
                    authjid = response.find(f'{{{SASL2}}}authorization-identifier').text
                    assert authjid.startswith(user + '@localhost/') if fallback else authjid == user + '@localhost'
                    features = failed.until(b'</stream:features>')
                    assert (b'xmpp-bind' in features) != fallback
                # Active transport takeover; Bind2 is ignored after successful resume.
                fresh = connect()
                response = fresh.auth(request(token, 1) + bind)
                assert_resume(response, token, jid)
                assert response.find(f'{{{SM}}}resumed').get('h') == '2'
                # auth() parses success first: replay can never precede it. Only the
                # second response remains unacknowledged and must be replayed once.
                replay = fresh.until(b'</iq>')
                assert b"id='pending'" in replay and b'acknowledged' not in replay, replay
                features = fresh.until(b'</stream:features>')
                assert b'xmpp-bind' not in features and b"<sm " not in features, features
                conflict = old.until(b'</stream:stream>')
                assert b'conflict' in conflict, conflict
                fresh.send(f"<a xmlns='{SM}' h='2'/><r xmlns='{SM}'/>")
                assert ET.fromstring(fresh.until(b'/>')).tag == f'{{{SM}}}a'
                # EOF suspension and replay-free second resume, without Bind2.
                fresh.close()
                again = connect()
                response = again.auth(request(token, 2))
                assert_resume(response, token, jid)
                assert b'xmpp-bind' not in again.until(b'</stream:features>')
                again.ping('after-resume')
                malformed = [request(token) * 2, f"<resume xmlns='{SM}' previd='{token}' h='bad'/>", f"<resume xmlns='{SM}' h='0'/>", f"<resume xmlns='{SM}' previd='{token}' h='0'><nested/></resume>"]
                for inline in malformed:
                    client = connect()
                    failure = client.auth(inline, good=False)
                    assert failure.find(f'{{{SASL}}}malformed-request') is not None, ET.tostring(failure)
                    response = client.auth()
                    assert response.find(f'{{{SASL2}}}authorization-identifier').text == 'alice@localhost'
                    client.until(b'</stream:features>')
                again.ping('survives-malformed')
                print('PASS: SASL2 inline SM active/EOF resume, authenticated owner/id/h checks, replay ordering, full JID, Bind2 fallback and malformed requests')
            finally:
                for client in clients:
                    client.close()
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
