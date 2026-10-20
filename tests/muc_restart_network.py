#!/usr/bin/env python3
"""Live MUC membership recovery across SIGTERM over real loopback STARTTLS.

Usage: python3 tests/muc_restart_network.py target/release/rust-xmpp
The sockets stay open until shutdown, so ordinary disconnect cleanup cannot
substitute for checkpointing the room's live occupants.
"""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

from _wire_client import Client, local

MUC = 'http://jabber.org/protocol/muc'
USER = MUC + '#user'
ROOMS = ('persistent@rooms.localhost', 'temporary@rooms.localhost')


def iq(client, identifier, payload, room, error=False):
    client.send(f"<iq type='set' id='{identifier}' to='{room}'>{payload}</iq>")
    return client.iq(identifier, error=error)


def presence(client, room, nick):
    return client.take(lambda e: local(e) == 'presence' and e.get('from') == f'{room}/{nick}')


def occupant(packet, role, affiliation=None):
    assert packet.get('type') is None, ET.tostring(packet)
    item = packet.find(f'{{{USER}}}x/{{{USER}}}item')
    assert item is not None and item.get('role') == role, ET.tostring(packet)
    if affiliation is not None:
        assert item.get('affiliation') == affiliation, ET.tostring(packet)


def join(client, room, nick):
    client.send(f"<presence to='{room}/{nick}'><x xmlns='{MUC}'><history maxstanzas='0'/></x><show>away</show><status>before restart</status></presence>")
    return presence(client, room, nick)


def not_joined(client, room):
    # A ping fences the initial broadcast presence without timeout-based reads.
    client.sync()
    assert not any(local(e) == 'presence' and e.get('from', '').startswith(room + '/')
                   for e in client.queue), [ET.tostring(e) for e in client.queue]
    client.send(f"<message to='{room}' type='groupchat' id='not-joined'><body>must not route</body></message>")
    response = client.take(lambda e: local(e) == 'message' and e.get('id') == 'not-joined')
    assert response.get('type') == 'error', ET.tostring(response)
    assert response.find('.//{urn:ietf:params:xml:ns:xmpp-stanzas}not-acceptable') is not None, ET.tostring(response)


def start(binary, config, port, log):
    server = subprocess.Popen([binary, 'serve', str(config), '--experimental'], stdout=log, stderr=log)
    for _ in range(100):
        assert server.poll() is None, 'server stopped during startup'
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return server
        except OSError:
            time.sleep(.05)
    server.kill()
    server.wait()
    raise AssertionError('server did not start')


def stop(server):
    server.terminate()
    try:
        code = server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()
        raise AssertionError('SIGTERM did not complete orderly shutdown')
    assert code == 0, f'SIGTERM shutdown exited {code}'


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-muc-restart-') as tmp:
        root = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj',
                        '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        config = root/'config.json'
        config.write_text(json.dumps({'global': {
            'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port],
            's2s_ports': [], 'http_ports': [], 'https_ports': [],
            'modules_enabled': ['tls', 'saslauth', 'ping', 'disco'],
        }, 'hosts': {
            'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256',
                                      'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}},
            'rooms.localhost': {'component': 'muc', 'options': {}},
        }}))
        for user in ('alice', 'bob', 'carol'):
            subprocess.run([binary, 'create-user', str(config), user, '--password-stdin'],
                           input='secret\n', text=True, check=True, capture_output=True)
        clients = []
        server = None
        with (root/'server.log').open('w+') as log:
            try:
                server = start(binary, config, port, log)
                alice = Client(port, root/'cert.pem', 'alice', 'secret', 'desktop')
                bob = Client(port, root/'cert.pem', 'bob', 'secret', 'desktop')
                clients.extend((alice, bob))
                alice.available()
                bob.available()
                for index, room in enumerate(ROOMS):
                    occupant(join(alice, room, 'Alice'), 'moderator', 'owner')
                    fields = ("<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
                              f"<field var='muc#roomconfig_persistentroom'><value>{int(index == 0)}</value></field>")
                    iq(alice, f'configure-{index}', f"<query xmlns='{MUC}#owner'><x xmlns='jabber:x:data' type='submit'>{fields}</x></query>", room)
                    occupant(join(bob, room, 'Bob'), 'participant', 'none')
                    iq(alice, f'moderator-{index}', f"<query xmlns='{MUC}#admin'><item nick='Bob' role='moderator'/></query>", room)
                    bob.take(lambda e: local(e) == 'presence' and e.get('from') == room + '/Bob'
                             and e.find(f'{{{USER}}}x/{{{USER}}}item').get('role') == 'moderator')
                alice.sync()
                bob.sync()
                stop(server)
                server = None
                for client in clients:
                    client.close()
                clients.clear()

                server = start(binary, config, port, log)
                other_resource = Client(port, root/'cert.pem', 'alice', 'secret', 'phone')
                carol = Client(port, root/'cert.pem', 'carol', 'secret', 'desktop')
                clients.extend((other_resource, carol))
                other_resource.available()
                carol.available()
                for room in ROOMS:
                    not_joined(other_resource, room)
                    not_joined(carol, room)

                bob = Client(port, root/'cert.pem', 'bob', 'secret', 'desktop')
                alice = Client(port, root/'cert.pem', 'alice', 'secret', 'desktop')
                clients.extend((bob, alice))
                bob.send('<presence><show>chat</show><status>after restart</status></presence>')
                for room in ROOMS:
                    packet = presence(bob, room, 'Bob')
                    occupant(packet, 'moderator', 'none')
                alice.send('<presence><show>away</show><status>restored owner</status></presence>')
                for room in ROOMS:
                    occupant(presence(alice, room, 'Alice'), 'moderator', 'owner')
                    packet = presence(bob, room, 'Alice')
                    occupant(packet, 'moderator', 'owner')
                    assert packet.find('{jabber:client}show').text == 'away', ET.tostring(packet)
                    assert packet.find('{jabber:client}status').text == 'before restart', ET.tostring(packet)
                    alice.send(f"<presence to='{room}/Alice'><show>chat</show><status>updated after recovery</status></presence>")
                    updated = presence(bob, room, 'Alice')
                    assert updated.find('{jabber:client}status').text == 'updated after recovery', ET.tostring(updated)
                    carol.send(f"<presence to='{room}/Alice'><x xmlns='{MUC}'/></presence>")
                    denied = presence(carol, room, 'Alice')
                    assert denied.get('type') == 'error', ET.tostring(denied)
                    assert denied.find('.//{urn:ietf:params:xml:ns:xmpp-stanzas}conflict') is not None, ET.tostring(denied)
                    text = 'after recovery ' + room
                    alice.send(f"<message to='{room}' type='groupchat'><body>{text}</body></message>")
                    assert bob.body(text).get('from') == room + '/Alice'
                    assert alice.body(text).get('from') == room + '/Alice'
                    # Explicit joins remain valid for another authenticated resource.
                    occupant(join(other_resource, room, 'Phone'), 'moderator', 'owner')
                stop(server)
                server = None
            finally:
                if server is not None and server.poll() is None:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()
                for client in clients:
                    client.close()
                if sys.exc_info()[0] is not None:
                    log.seek(0)
                    print(log.read(), file=sys.stderr)
    print('PASS: STARTTLS MUC SIGTERM restart restores live temporary/persistent rooms, exact full-JID membership, roles, presence and groupchat routing; rejects automatic cross-resource/account claims and nickname theft')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()))
