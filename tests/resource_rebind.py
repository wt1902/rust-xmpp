#!/usr/bin/env python3
"""Isolated TLS resource-conflict and stream-management replacement regression."""
import json
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
import xml.etree.ElementTree as ET

from _wire_client import BIN, Client, S

BIND = 'urn:ietf:params:xml:ns:xmpp-bind'
SM = 'urn:xmpp:sm:3'
STANZAS = 'urn:ietf:params:xml:ns:xmpp-stanzas'
STREAMS = 'urn:ietf:params:xml:ns:xmpp-streams'


def bind(client, resource='phone', error=False):
    client.send(f"<iq type='set' id='bind'><bind xmlns='{BIND}'><resource>{resource}</resource></bind></iq>")
    result = client.iq('bind', error=error)
    if error:
        assert result.find(f'{{jabber:client}}error/{{{STANZAS}}}conflict') is not None, ET.tostring(result)
        return None
    jid = result.find(f'{{{BIND}}}bind/{{{BIND}}}jid')
    assert jid is not None and jid.text, ET.tostring(result)
    client.jid = jid.text
    return jid.text


def enable_resume(client):
    client.send(f"<enable xmlns='{SM}' resume='true'/>")
    enabled = client.take(lambda n: n.tag == f'{{{SM}}}enabled')
    assert enabled.get('resume') in ('true', '1'), ET.tostring(enabled)
    assert enabled.get('id'), ET.tostring(enabled)
    return enabled.get('id')


def resume(client, token, invalid):
    client.send(f"<resume xmlns='{SM}' previd='{token}' h='0'/>")
    result = client.take(lambda n: n.tag in (f'{{{SM}}}failed', f'{{{SM}}}resumed'))
    if invalid:
        assert result.tag == f'{{{SM}}}failed', ET.tostring(result)
        assert result.find(f'{{{STANZAS}}}item-not-found') is not None, ET.tostring(result)
    else:
        assert result.tag == f'{{{SM}}}resumed' and result.get('previd') == token, ET.tostring(result)
        client.sync()


def check_policy(port, cert, policy, clients):
    def connect(user):
        client = Client(port, cert, user, user + '-secret', bind=False)
        clients.append(client)
        return client

    if policy is None:
        old = connect('carol')
        assert bind(old) == 'carol@localhost/phone'
        token = enable_resume(old)
        # Resume can take over a transport which has not noticed its loss yet.
        new = connect('carol')
        resume(new, token, invalid=False)
        conflict = old.take(lambda n: n.tag == f'{{{S}}}error')
        assert conflict.find(f'{{{STREAMS}}}conflict') is not None, ET.tostring(conflict)
        old.close()
        new.sync()
        time.sleep(.05)
        new.sync()

    for sleeping, user in [(False, 'alice'), (True, 'bob')]:
        old = connect(user)
        expected = f'{user}@localhost/phone'
        assert bind(old) == expected
        old.sync()
        token = enable_resume(old)
        if sleeping:
            # An abrupt TLS transport loss leaves the resumable resource reserved.
            old.close()
            time.sleep(.2)

        new = connect(user)
        replacing = policy in (None, 'kick_old')
        assigned = bind(new, error=policy == 'kick_new')
        if replacing:
            assert assigned == expected, assigned
            if not sleeping:
                conflict = old.take(lambda n: n.tag == f'{{{S}}}error')
                assert conflict.find(f'{{{STREAMS}}}conflict') is not None, ET.tostring(conflict)
                old.close()
            # Closing the displaced transport must not remove the new session.
            new.sync()
            time.sleep(.05)
            new.sync()
            rejected = connect(user)
            resume(rejected, token, invalid=True)
            new.sync()
        elif policy == 'kick_new':
            if sleeping:
                survivor = connect(user)
                resume(survivor, token, invalid=False)
            else:
                old.sync()
            # The rejected stream remains usable and can bind another resource.
            assert bind(new, 'tablet') == f'{user}@localhost/tablet'
            new.sync()
        else:
            if policy == 'increment':
                assert assigned == expected + '#1', assigned
            else:
                resource = assigned.split('/', 1)[1]
                assert assigned.startswith(f'{user}@localhost/') and resource != 'phone', assigned
                assert str(uuid.UUID(resource)) == resource, assigned
            new.sync()
            another = connect(user)
            second = bind(another)
            if policy == 'increment':
                assert second == expected + '#2', second
            else:
                assert second not in (expected, assigned), second
                assert str(uuid.UUID(second.split('/', 1)[1])) == second.split('/', 1)[1], second
            another.sync()
            # Keeping the original resource includes keeping its resumable session.
            if sleeping:
                survivor = connect(user)
                resume(survivor, token, invalid=False)
            else:
                old.sync()


def run_policy(policy):
    # Same isolated certificate/config/account/server fixture as preauth_network.py.
    with tempfile.TemporaryDirectory(prefix='xmpp-rebind-') as tmp:
        root = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        options = {'authentication': 'internal_hashed', 'password_hash': 'SHA-256',
                   'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}
        if policy is not None:
            options['conflict_resolve'] = policy
        cfg = {'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'],
                          'c2s_ports': [port], 'http_ports': [], 'https_ports': [], 's2s_ports': [],
                          'modules_enabled': ['tls', 'saslauth', 'ping', 'smacks']},
               'hosts': {'localhost': {'options': options}}}
        config = root/'config.json'
        config.write_text(json.dumps(cfg))
        for user in ['alice', 'bob', 'carol']:
            subprocess.run([str(BIN), 'create-user', str(config), user, '--password-stdin'],
                           input=user + '-secret\n', text=True, check=True, capture_output=True)
        with (root/'server.log').open('w+') as log:
            server = subprocess.Popen([str(BIN), 'serve', str(config), '--experimental'], stdout=log, stderr=log)
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
                check_policy(port, root/'cert.pem', policy, clients)
                print(f'PASS: TLS conflict_resolve={policy or "default"}, live and hibernating SM resources')
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read())
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


if __name__ == '__main__':
    if len(sys.argv) > 1:
        BIN = Path(sys.argv[1]).resolve()
    for policy in [None, 'kick_old', 'kick_new', 'increment', 'random']:
        run_policy(policy)
