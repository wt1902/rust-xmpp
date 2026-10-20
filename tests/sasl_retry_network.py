#!/usr/bin/env python3
"""Real STARTTLS regression for SASL identity preparation and exchange retries.

Usage: python3 tests/sasl_retry_network.py BINARY
"""
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from android_sasl_network import Connection, OPEN, SASL, SASL2, b64

BIND = 'urn:ietf:params:xml:ns:xmpp-bind'


def authenticate(connection, sasl2, mechanism, payload):
    ns = SASL2 if sasl2 else SASL
    encoded = b64(payload.encode())
    if sasl2:
        connection.send(f"<authenticate xmlns='{ns}' mechanism='{mechanism}'><initial-response>{encoded}</initial-response></authenticate>")
    else:
        connection.send(f"<auth xmlns='{ns}' mechanism='{mechanism}'>{encoded}</auth>")


def plain(connection, sasl2, username='alice', authz=''):
    authenticate(connection, sasl2, 'PLAIN', f'{authz}\0{username}\0secret')


def expect_failure(connection, sasl2, condition):
    result = connection.stanza()
    ns = SASL2 if sasl2 else SASL
    assert result.tag == '{' + ns + '}failure', ET.tostring(result)
    assert result.find('{' + SASL + '}' + condition) is not None, ET.tostring(result)


def expect_canonical_bind(connection, sasl2):
    result = connection.stanza()
    ns = SASL2 if sasl2 else SASL
    assert result.tag == '{' + ns + '}success', ET.tostring(result)
    if sasl2:
        assert result.findtext('{' + SASL2 + '}authorization-identifier') == 'alice@localhost', ET.tostring(result)
    else:
        connection.send(OPEN)
    connection.until(b'</stream:features>')
    connection.send(f"<iq xmlns='jabber:client' type='set' id='bind'><bind xmlns='{BIND}'><resource>retry-test</resource></bind></iq>")
    result = connection.stanza()
    assert result.get('type') == 'result' and result.get('id') == 'bind', ET.tostring(result)
    assert result.findtext('.//{' + BIND + '}jid') == 'alice@localhost/retry-test', ET.tostring(result)


def start_scram(connection, sasl2):
    authenticate(connection, sasl2, 'SCRAM-SHA-256', 'n,,n=alice,r=retry-regression-nonce')
    result = connection.stanza()
    ns = SASL2 if sasl2 else SASL
    assert result.tag == '{' + ns + '}challenge', ET.tostring(result)


def check_case(connection, sasl2, case):
    if case in ('uppercase', 'fullwidth'):
        user = 'ALICE' if case == 'uppercase' else 'Ａlice'
        plain(connection, sasl2, user, user + '@localhost')
    elif case == 'invalid-authz':
        plain(connection, sasl2, 'ALICE', 'bob@localhost')
        expect_failure(connection, sasl2, 'not-authorized')
        plain(connection, sasl2)
    elif case == 'abort':
        start_scram(connection, sasl2)
        ns = SASL2 if sasl2 else SASL
        connection.send(f"<abort xmlns='{ns}'/>")
        expect_failure(connection, sasl2, 'aborted')
        plain(connection, sasl2)
    elif case == 'restart':
        start_scram(connection, sasl2)
        plain(connection, sasl2, 'ALICE')
    else:
        raise AssertionError(case)
    expect_canonical_bind(connection, sasl2)


def run(binary):
    cases = ('uppercase', 'fullwidth', 'invalid-authz', 'abort', 'restart')
    with tempfile.TemporaryDirectory(prefix='xmpp-sasl-retry-') as tmp:
        root = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        cfg = {'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port], 'http_ports': [], 'https_ports': [], 's2s_ports': [], 'modules_enabled': ['tls', 'saslauth', 'sasl2']}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256', 'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}}}}
        config = root/'config.json'
        config.write_text(json.dumps(cfg))
        subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'], input='secret\n', text=True, check=True, capture_output=True)
        with (root/'server.log').open('w+') as log:
            process = subprocess.Popen([binary, 'serve', str(config), '--experimental'], stdout=log, stderr=log)
            active = None
            try:
                for _ in range(100):
                    assert process.poll() is None, 'server stopped'
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                    for sasl2 in (False, True):
                        for case in cases:
                            active = (version.name, 'SASL2' if sasl2 else 'SASL1', case)
                            connection = Connection(port, root/'cert.pem', version)
                            try:
                                check_case(connection, sasl2, case)
                            finally:
                                connection.sock.close()
            except BaseException:
                print('FAILED case:', active)
                log.flush(); log.seek(0); print(log.read())
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
    print('PASS: 20 TLS1.2/1.3 SASL1/2 cases: prepared PLAIN identities and canonical binds, invalid authz rejection, SCRAM abort/retry and active exchange restart')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()))
