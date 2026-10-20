#!/usr/bin/env python3
"""Isolated TLS regression for Gajim's XEP-0258/XEP-0077 predicates and operations.

Usage: python3 tests/gajim_discovery_network.py [target/release/rust-xmpp]
Only temporary accounts, certificates, and server data are used.
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

from _wire_client import BIN, Client, OPEN

DISCO = 'http://jabber.org/protocol/disco#info'
REGISTER = 'jabber:iq:register'
LABEL = 'urn:xmpp:sec-label:0'
CATALOGS = ('urn:xmpp:sec-label:catalog:2', 'urn:xmpp:sec-label:catalog:0')
STANZAS = 'urn:ietf:params:xml:ns:xmpp-stanzas'


class Unauthenticated(Client):
    def __init__(self, port, cert):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.buf = b''
        self.queue = []
        self.send(OPEN)
        self.until(b'</stream:features>')
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        assert b'proceed' in self.until(b'/>')
        self.sock = ssl.create_default_context(cafile=str(cert)).wrap_socket(
            self.sock, server_hostname='localhost')
        self.send(OPEN)
        self.features = self.until(b'</stream:features>')


def iq(client, identifier, payload, target='localhost', typ='get', error=False):
    client.send(f"<iq type='{typ}' id='{identifier}' to='{target}'>{payload}</iq>")
    return client.iq(identifier, error=error)


def error_condition(response, expected):
    assert response.find(f'{{jabber:client}}error/{{{STANZAS}}}{expected}') is not None, ET.tostring(response)


def check_authenticated(client, enabled):
    for target in ('localhost', 'alice@localhost'):
        response = iq(client, 'disco-' + target, f"<query xmlns='{DISCO}'/>", target)
        features = {node.get('var') for node in response.iter(f'{{{DISCO}}}feature')}
        for namespace in (LABEL, REGISTER, CATALOGS[0]):
            assert (namespace in features) == enabled, (target, enabled, namespace, features)
    for index, namespace in enumerate(CATALOGS):
        for target in ('localhost', 'alice@localhost'):
            response = iq(client, f'catalog-{index}-{target}',
                          f"<catalog xmlns='{namespace}' to='bob@localhost'/>", target,
                          error=not enabled)
            if not enabled:
                error_condition(response, 'service-unavailable')
                continue
            catalog = response.find(f'{{{namespace}}}catalog')
            assert catalog is not None, ET.tostring(response)
            assert catalog.get('to') == 'bob@localhost', ET.tostring(response)
            entry = catalog.find(f'{{{namespace}}}item') if index == 0 else catalog.find(f'{{{LABEL}}}securitylabel')
            assert entry is not None, ET.tostring(response)
            assert entry.get('selector') == 'Public' and entry.get('default') == 'true', ET.tostring(response)
            label = entry.find(f'{{{LABEL}}}securitylabel') if index == 0 else entry
            assert label.find(f'{{{LABEL}}}label').text == 'PUBLIC', ET.tostring(response)
    response = iq(client, 'account-registration', f"<query xmlns='{REGISTER}'/>", error=not enabled)
    if enabled:
        query = response.find(f'{{{REGISTER}}}query')
        assert query is not None and query.find(f'{{{REGISTER}}}registered') is not None, ET.tostring(response)
        assert query.find(f'{{{REGISTER}}}username').text == 'alice', ET.tostring(response)
        iq(client, 'change-password',
           f"<query xmlns='{REGISTER}'><username>alice</username><password>changed-secret</password></query>", typ='set')
    else:
        error_condition(response, 'service-unavailable')
        response = iq(client, 'change-password-disabled',
                      f"<query xmlns='{REGISTER}'><password>changed-secret</password></query>",
                      typ='set', error=True)
        error_condition(response, 'service-unavailable')


def scenario(binary, root, enabled, allow_registration):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    name = f'enabled-{enabled}-registration-{allow_registration}'
    modules = ['tls', 'saslauth', 'pep', 'disco', 'ping']
    if enabled:
        modules += ['seclabels', 'register']
    cfg = {'global': {
        'data_path': str(root / name), 'interfaces': ['127.0.0.1'],
        'c2s_ports': [port], 'http_ports': [], 'https_ports': [], 's2s_ports': [],
        'modules_enabled': modules, 'allow_registration': allow_registration,
        'security_labels': [{'name': 'Public', 'label': 'PUBLIC', 'default': True}],
    }, 'hosts': {'localhost': {'options': {
        'authentication': 'internal_hashed', 'password_hash': 'SHA-256',
        'ssl': {'key': str(root / 'key.pem'), 'certificate': str(root / 'cert.pem')},
    }}}}
    config = root / f'{name}.json'
    config.write_text(json.dumps(cfg))
    subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'],
                   input='original-secret\n', text=True, check=True, capture_output=True)
    with (root / f'{name}.log').open('w+') as log:
        server = subprocess.Popen([binary, 'serve', str(config), '--experimental'], stdout=log, stderr=log)
        clients = []
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
            client = Client(port, root / 'cert.pem', 'alice', 'original-secret')
            clients.append(client)
            check_authenticated(client, enabled)
            # An actual fresh SASL login proves the password update was persisted.
            logged_in = Client(port, root / 'cert.pem', 'alice',
                               'changed-secret' if enabled else 'original-secret', 'new-login')
            clients.append(logged_in)
            logged_in.sync()
            unauth = Unauthenticated(port, root / 'cert.pem')
            clients.append(unauth)
            registration_enabled = enabled and allow_registration
            assert (b'http://jabber.org/features/iq-register' in unauth.features) == registration_enabled, unauth.features
            response = iq(unauth, 'ibr-form', f"<query xmlns='{REGISTER}'/>", error=not registration_enabled)
            if registration_enabled:
                query = response.find(f'{{{REGISTER}}}query')
                assert query is not None and query.find(f'{{{REGISTER}}}username') is not None, ET.tostring(response)
            else:
                error_condition(response, 'forbidden')
            response = iq(unauth, 'ibr-create',
                          f"<query xmlns='{REGISTER}'><username>newuser</username><password>ibr-secret</password></query>",
                          typ='set', error=not registration_enabled)
            if registration_enabled:
                registered = Client(port, root / 'cert.pem', 'newuser', 'ibr-secret', 'ibr-login')
                clients.append(registered)
                registered.sync()
                # XEP-0077 removal must acknowledge the request and revoke login.
                iq(registered, 'ibr-remove', f"<query xmlns='{REGISTER}'><remove/></query>", typ='set')
                deleted_login = Unauthenticated(port, root / 'cert.pem')
                clients.append(deleted_login)
                credentials = base64.b64encode(b'\0newuser\0ibr-secret').decode()
                deleted_login.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{credentials}</auth>")
                assert b'failure' in deleted_login.until(b'>')
                assert not list((root / name).glob('*/accounts/newuser.dat'))
            else:
                error_condition(response, 'forbidden')
                # Rejection must not create an account on disk.
                assert not list((root / name).glob('*/accounts/newuser.dat'))
            print('PASS:', name)
        except BaseException:
            log.flush()
            log.seek(0)
            print(log.read(), file=sys.stderr)
            raise
        finally:
            for client in clients:
                client.close()
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-gajim-discovery-') as tmp:
        root = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for enabled in (False, True):
            for allow_registration in (False, True):
                scenario(binary, root, enabled, allow_registration)
    print('PASS: Gajim domain/account discovery, both label catalogs, authenticated password changes, IBR registration gates and fresh logins')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else str(BIN))
