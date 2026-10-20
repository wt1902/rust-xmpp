#!/usr/bin/env python3
"""SIGKILL MUC durability over real TCP/STARTTLS (no shutdown checkpoint).

Usage: python3 tests/muc_crash_network.py target/release/rust-xmpp
All crashes happen with sockets open, immediately after the relevant wire reply.
The grace test ages only the persisted clock while the server is stopped.
"""
import json
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from _wire_client import Client, local
from muc_restart_network import MUC, USER, iq, occupant, presence, start, not_joined

STANZAS = 'urn:ietf:params:xml:ns:xmpp-stanzas'


def join(client, room, nick, history=0, password=None):
    secret = '' if password is None else f'<password>{escape(password)}</password>'
    client.send(f"<presence to='{room}/{nick}'><x xmlns='{MUC}'>{secret}"
                f"<history maxstanzas='{history}'/></x><show>away</show>"
                '<status>durable presence</status></presence>')
    return presence(client, room, nick)


def configure(client, room, **values):
    fields = "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
    fields += ''.join(f"<field var='muc#roomconfig_{key}'><value>{escape(str(value))}</value></field>"
                      for key, value in values.items())
    return iq(client, 'config', f"<query xmlns='{MUC}#owner'><x xmlns='jabber:x:data' type='submit'>{fields}</x></query>", room)


def role(client, room, nick, value):
    return iq(client, 'role', f"<query xmlns='{MUC}#admin'><item nick='{nick}' role='{value}'/></query>", room)


def denied(packet, condition):
    assert packet.get('type') == 'error', ET.tostring(packet)
    assert packet.find(f'.//{{{STANZAS}}}{condition}') is not None, ET.tostring(packet)


class Server:
    def __init__(self, binary, root, options=None):
        self.binary, self.root = binary, root
        self.clients, self.process = [], None
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj',
                        '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            self.port = probe.getsockname()[1]
        self.config = root/'config.json'
        self.config.write_text(json.dumps({'global': {
            'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [self.port],
            's2s_ports': [], 'http_ports': [], 'https_ports': [],
            'modules_enabled': ['tls', 'saslauth', 'ping', 'disco'],
        }, 'hosts': {
            'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256',
                'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}},
            'rooms.localhost': {'component': 'muc', 'options': {'max_history_messages': 20, **(options or {})}},
        }}))
        for user in ('alice', 'bob', 'carol'):
            subprocess.run([binary, 'create-user', str(self.config), user, '--password-stdin'],
                           input='secret\n', text=True, check=True, capture_output=True)
        self.log = (root/'server.log').open('w+')
        self.restart()

    def client(self, user, resource='desktop', available=True):
        client = Client(self.port, self.root/'cert.pem', user, 'secret', resource)
        self.clients.append(client)
        if available:
            client.available()
        return client

    def restart(self):
        self.process = start(self.binary, self.config, self.port, self.log)

    def crash(self):
        # Never close a client first: disconnect cleanup must not save the state.
        self.process.kill()
        assert self.process.wait(timeout=10) == -signal.SIGKILL
        self.process = None
        for client in self.clients:
            client.close()
        self.clients.clear()

    def close(self):
        if self.process is not None:
            self.crash()
        if sys.exc_info()[0] is not None:
            self.log.seek(0)
            print(self.log.read(), file=sys.stderr)
        self.log.close()


def recovery_and_history(server):
    rooms = ('persistent@rooms.localhost', 'temporary@rooms.localhost')
    alice, phone, bob = server.client('alice'), server.client('alice', 'phone'), server.client('bob')
    for index, room in enumerate(rooms):
        occupant(join(alice, room, 'Alice'), 'moderator', 'owner')
        configure(alice, room, persistentroom=int(index == 0), enablearchiving=0, historylength=20)
        # Exercise both shared-nickname sessions and distinct resource nicknames.
        occupant(join(phone, room, 'Alice' if index == 0 else 'Phone'), 'moderator', 'owner')
        occupant(join(bob, room, 'Bob'), 'participant', 'none')
        role(alice, room, 'Bob', 'moderator')
        for number in range(3):
            body = f'{room} precrash {number}'
            alice.send(f"<message to='{room}' type='groupchat'><body>{body}</body></message>")
            bob.body(body)
    server.crash()
    server.restart()
    wrong = server.client('alice', 'tablet')
    stranger = server.client('carol')
    for room in rooms:
        not_joined(wrong, room)
        not_joined(stranger, room)
        # A dormant exact-resource claim reserves its nick before activation.
        denied(join(stranger, room, 'Alice'), 'conflict')
    bob = server.client('bob')
    for room in rooms:
        occupant(presence(bob, room, 'Bob'), 'moderator', 'none')
    alice = server.client('alice')
    phone = server.client('alice', 'phone')
    for index, room in enumerate(rooms):
        packet = presence(alice, room, 'Alice')
        occupant(packet, 'moderator', 'owner')
        status = packet.find('{jabber:client}status')
        assert status is not None and status.text == 'durable presence', ET.tostring(packet)
        phone_nick = 'Alice' if index == 0 else 'Phone'
        occupant(presence(phone, room, phone_nick), 'moderator', 'owner')
        body = room + ' recovered route'
        phone.send(f"<message to='{room}' type='groupchat'><body>{body}</body></message>")
        assert bob.body(body).get('from') == room + '/' + phone_nick
        assert alice.body(body).get('from') == room + '/' + phone_nick
        occupant(join(stranger, room, 'History', history=20), 'participant', 'none')
        for number in range(3):
            packet = stranger.body(f'{room} precrash {number}')
            assert packet.find('{urn:xmpp:delay}delay') is not None, ET.tostring(packet)
        stranger.body(body)


def mutation_barrier(server, mutation):
    room = mutation + '@rooms.localhost'
    alice, bob = server.client('alice'), server.client('bob')
    occupant(join(alice, room, 'Alice'), 'moderator', 'owner')
    configure(alice, room, persistentroom=1)
    occupant(join(bob, room, 'Bob'), 'participant', 'none')
    if mutation == 'leave':
        bob.send(f"<presence to='{room}/Bob' type='unavailable'/>")
        packet = bob.take(lambda e: local(e) == 'presence' and e.get('from') == room + '/Bob'
                          and e.get('type') == 'unavailable')
        assert packet.find(f'{{{USER}}}x/{{{USER}}}item').get('role') == 'none', ET.tostring(packet)
    elif mutation == 'kick':
        role(alice, room, 'Bob', 'none')
    elif mutation == 'demotion':
        role(alice, room, 'Bob', 'moderator')
        role(alice, room, 'Bob', 'visitor')
    elif mutation == 'password':
        configure(alice, room, roomsecret='new-private-password')
    elif mutation == 'configuration':
        configure(alice, room, membersonly=1)
    else:
        raise AssertionError(mutation)
    # No ping, sleep, extra read or orderly close between acknowledgment and kill.
    server.crash()
    server.restart()
    bob = server.client('bob')
    if mutation in ('leave', 'kick', 'configuration'):
        not_joined(bob, room)
    elif mutation == 'demotion':
        occupant(presence(bob, room, 'Bob'), 'visitor', 'none')
        bob.send(f"<message to='{room}' type='groupchat' id='visitor'><body>forbidden</body></message>")
        packet = bob.take(lambda e: local(e) == 'message' and e.get('id') == 'visitor')
        assert packet.get('type') == 'error', ET.tostring(packet)
    stranger = server.client('carol')
    if mutation == 'password':
        denied(join(stranger, room, 'Carol'), 'not-authorized')
        occupant(join(stranger, room, 'Carol', password='new-private-password'), 'participant', 'none')
    elif mutation == 'configuration':
        denied(join(stranger, room, 'Carol'), 'registration-required')


def checkpoint_clock(server, age=None):
    """Age the committed journal clock without changing membership or config."""
    files = list((server.root/'data').rglob('rust_muc_checkpoint.dat'))
    found = []
    pattern = re.compile(r'(\["saved_at"\]\s*=\s*)(\d+)')
    for path in files:
        text = path.read_text()
        if pattern.search(text):
            found.append(int(pattern.search(text).group(2)))
            if age is not None:
                path.write_text(pattern.sub(lambda m: m.group(1) + str(int(time.time()) - age), text))
    assert found, 'no committed recovery checkpoint timestamp found'
    return found


def restart_grace(server, grace=300):
    room = 'grace@rooms.localhost'
    alice = server.client('alice')
    occupant(join(alice, room, 'Alice'), 'moderator', 'owner')
    configure(alice, room, persistentroom=1)
    server.crash()
    # Make the original admission old enough to distinguish it from restart time.
    checkpoint_clock(server, age=grace - 10)
    original = checkpoint_clock(server)
    for _ in range(2):
        server.restart()
        probe = server.client('carol')
        not_joined(probe, room)
        server.crash()
        assert checkpoint_clock(server) == original, 'restart extended dormant recovery deadline'
    checkpoint_clock(server, age=grace + 1)
    server.restart()
    alice = server.client('alice')
    not_joined(alice, room)
    # Expiration releases nickname reservation; persistent-room ownership remains.
    carol = server.client('carol')
    occupant(join(carol, room, 'Alice'), 'participant', 'none')


def unknown_component_module(server):
    server.crash()
    config = json.loads(server.config.read_text())
    marker = 'unimplemented_muc_crash_test_module'
    config['hosts']['rooms.localhost']['options']['modules_enabled'] = [marker]
    server.config.write_text(json.dumps(config))
    result = subprocess.run([server.binary, 'serve', str(server.config), '--experimental'],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0, 'unknown MUC component module was accepted'
    assert marker in result.stdout + result.stderr, result.stdout + result.stderr


def destroy_tombstone(server):
    room = 'destroyed@rooms.localhost'
    replacement = 'replacement@rooms.localhost'
    reason = 'Closed after migration'
    alice, bob = server.client('alice'), server.client('bob')
    occupant(join(alice, room, 'Alice'), 'moderator', 'owner')
    configure(alice, room, persistentroom=1)
    occupant(join(bob, room, 'Bob'), 'participant', 'none')
    iq(alice, 'destroy', f"<query xmlns='{MUC}#owner'><destroy jid='{replacement}'>"
       f'<reason>{reason}</reason></destroy></query>', room)
    # The IQ result is the durability barrier; no reads or disconnect precede kill.
    server.crash()
    journals = list((server.root/'data').rglob('rust_muc_checkpoint.dat'))
    assert len(journals) == 1, journals
    checkpoint = journals[0].read_text()
    for field in ('["destroyed"]=true', f'["reason"]="{reason}"',
                  f'["newjid"]="{replacement}"'):
        assert field in checkpoint, f'acknowledged tombstone omitted {field}'
    server.restart()
    # Neither an old exact identity nor a new account can recreate the room.
    alice, carol = server.client('alice'), server.client('carol')
    for client in (alice, carol):
        client.sync()
        assert not any(local(packet) == 'presence' and packet.get('from', '').startswith(room + '/')
                       for packet in client.queue), [ET.tostring(packet) for packet in client.queue]
        denied(join(client, room, 'Alice'), 'gone')


def run(binary, selected=()):
    cases = [('recovery-history', recovery_and_history)]
    cases += [(name, lambda server, name=name: mutation_barrier(server, name))
              for name in ('leave', 'kick', 'demotion', 'password', 'configuration')]
    cases.append(('restart-grace', restart_grace))
    cases.append(('custom-grace', lambda server: restart_grace(server, grace=30)))
    cases.append(('unknown-module', unknown_component_module))
    cases.append(('destroy-tombstone', destroy_tombstone))
    for name, test in cases:
        if selected and name not in selected:
            continue
        with tempfile.TemporaryDirectory(prefix='xmpp-muc-crash-' + name + '-') as tmp:
            options = {'muc_recovery_grace_period': 30} if name == 'custom-grace' else None
            server = Server(binary, Path(tmp), options)
            try:
                test(server)
            finally:
                server.close()
        print('PASS:', name, flush=True)
    print('PASS: actual STARTTLS SIGKILL MUC recovery, history, acknowledged barriers and fixed grace')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2:])
