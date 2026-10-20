#!/usr/bin/env python3
"""Real STARTTLS/SASL SM recovery across abrupt and orderly process restarts.

Usage: python3 tests/sm_restart_network.py BINARY
Pending server stanzas are at-least-once: a received but unacknowledged stanza
must replay. This test does not assert exactly-once client stanza processing.
"""
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

from _wire_client import Client, local
from sasl2_bind import Client as InlineClient, SASL2
from muc_restart_network import start, stop, join, iq, occupant

SM = 'urn:xmpp:sm:3'
ROOM = 'durable@rooms.localhost'


def enable(client):
    client.send(f"<enable xmlns='{SM}' resume='true'/>")
    response = client.take(lambda e: e.tag == f'{{{SM}}}enabled')
    assert response.get('resume') == 'true', ET.tostring(response)
    assert response.get('id'), ET.tostring(response)
    return response.get('id')


def handled(client):
    client.send(f"<r xmlns='{SM}'/>")
    return int(client.take(lambda e: e.tag == f'{{{SM}}}a').get('h'))


def ping(client, ident):
    client.send(f"<iq type='get' id='{ident}'><ping xmlns='urn:xmpp:ping'/></iq>")
    return client.iq(ident)


def count_output(client):
    """Track received SM-counted stanzas, including queued room broadcasts."""
    client.received = 0
    original = client.read
    def read():
        packet = original()
        if local(packet) in ('iq', 'presence', 'message'):
            client.received += 1
        return packet
    client.read = read


def resume(port, cert, token, h, clients, user='alice', inline=False, success=True, password='secret'):
    request = f"<resume xmlns='{SM}' previd='{token}' h='{h}'/>"
    if inline:
        raw = InlineClient(port, cert)
        response = raw.auth(request, user=user, password=password)
        result = response.find(f'{{{SM}}}' + ('resumed' if success else 'failed'))
        assert result is not None, ET.tostring(response)
        if success:
            assert response.find(f'{{{SASL2}}}authorization-identifier').text == 'alice@localhost/desktop'
        # Adapt the TLS socket to the independent stanza parser; inline success
        # precedes replay, and the new stream features follow pending stanzas.
        client = Client.__new__(Client)
        client.sock, client.buf, client.queue = raw.sock, raw.buffer, []
        client.jid = 'alice@localhost/desktop'
        clients.append(client)
        if success:
            while b'</stream:features>' not in client.buf:
                client.buf += client.sock.recv(65536)
            before, after = client.buf.split(b'<stream:features', 1)
            _, tail = after.split(b'</stream:features>', 1)
            client.buf = before + tail
    else:
        client = Client(port, cert, user, password, bind=False)
        clients.append(client)
        client.send(request)
        result = client.take(lambda e: e.tag in (f'{{{SM}}}resumed', f'{{{SM}}}failed'))
        assert result.tag == f'{{{SM}}}' + ('resumed' if success else 'failed'), ET.tostring(result)
    if success:
        assert result.get('previd') == token, ET.tostring(result)
    return client, result


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-sm-restart-') as tmp:
        root = Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj',
                        '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        cert = root/'cert.pem'
        config = root/'config.json'
        cfg = {'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'],
                         'c2s_ports': [port], 's2s_ports': [], 'http_ports': [], 'https_ports': [],
                         'smacks_hibernation_time': 30,
                         'modules_enabled': ['tls', 'saslauth', 'sasl2', 'sasl2_bind2', 'carbons',
                                             'csi_simple', 'smacks', 'ping', 'disco', 'register']},
               'hosts': {'localhost': {'options': {'authentication': 'internal_hashed',
                          'password_hash': 'SHA-256', 'ssl': {'key': str(root/'key.pem'),
                          'certificate': str(cert)}}}, 'rooms.localhost': {'component': 'muc', 'options': {}}}}
        config.write_text(json.dumps(cfg))
        for user in ('alice', 'bob'):
            subprocess.run([binary, 'create-user', str(config), user, '--password-stdin'],
                           input='secret\n', text=True, check=True, capture_output=True)
        clients, server = [], None
        with (root/'server.log').open('w+') as log:
            def connect(user='alice', resource='desktop'):
                client = Client(port, cert, user, 'secret', resource)
                clients.append(client)
                return client
            def restart(how):
                nonlocal server
                if how == 'kill':
                    server.send_signal(signal.SIGKILL)
                    assert server.wait(timeout=10) == -signal.SIGKILL
                else:
                    stop(server)
                for client in clients:
                    client.close()
                clients.clear()
                server = start(binary, config, port, log)
            try:
                server = start(binary, config, port, log)
                bob = connect(user='bob')
                bob.available()
                alice = connect()
                token = enable(alice)
                ping(alice, 'acknowledged')
                alice.send(f"<a xmlns='{SM}' h='1'/>")
                ping(alice, 'pending')
                # A handled incoming stanza without a response is preserved too.
                alice.send("<message to='bob@localhost'><body>incoming before crash</body></message>")
                bob.body('incoming before crash')
                assert handled(alice) == 3
                restart('kill')
                for user, ident, h in [('bob', token, 1), ('alice', 'unknown-token', 1), ('alice', token, 99)]:
                    resume(port, cert, ident, h, clients, user=user, success=False)
                alice, result = resume(port, cert, token, 1, clients)
                assert result.get('h') == '3', ET.tostring(result)
                replay = alice.iq('pending')
                assert replay.get('id') == 'pending'
                alice.send(f"<a xmlns='{SM}' h='2'/>")
                assert handled(alice) == 3
                assert not alice.queue, [ET.tostring(e) for e in alice.queue]
                restart('term')
                alice, result = resume(port, cert, token, 2, clients, inline=True)
                assert result.get('h') == '3', ET.tostring(result)
                ping(alice, 'after-orderly')
                assert not alice.queue, [ET.tostring(e) for e in alice.queue]
                alice.send(f"<a xmlns='{SM}' h='3'/>")
                assert handled(alice) == 4
                restart('kill')
                alice, result = resume(port, cert, token, 3, clients)
                assert result.get('h') == '4', ET.tostring(result)
                ping(alice, 'after-second-crash')
                assert not alice.queue, [ET.tostring(e) for e in alice.queue]
                # Only one transport owns a token: the next claim displaces it.
                old = alice
                alice, result = resume(port, cert, token, 4, clients)
                old.sock.settimeout(2)
                assert b'conflict' in old.until(b'</stream:stream>')
                assert handled(alice) == 5
                # Explicitly replacing the same resource invalidates its token.
                replacement = connect()
                resume(port, cert, token, 4, clients, success=False)
                replacement.close()

                # SM resumption itself activates recovered MUC membership. No
                # fresh available presence or MUC join is sent after restart.
                alice = connect(resource='room')
                count_output(alice)
                token = enable(alice)
                occupant(join(alice, ROOM, 'Alice'), 'moderator', 'owner')
                iq(alice, 'unlock', f"<query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'/></query>", ROOM)
                bob = connect(user='bob', resource='room')
                count_output(bob)
                bob_token = enable(bob)
                occupant(join(bob, ROOM, 'Bob'), 'participant', 'none')
                alice.send(f"<message to='{ROOM}' type='groupchat'><body>before room crash</body></message>")
                alice.body('before room crash')
                bob.body('before room crash')
                ping(alice, 'room-fence')
                ping(bob, 'bob-room-fence')
                alice_count, bob_count = alice.received, bob.received
                alice.send(f"<a xmlns='{SM}' h='{alice_count}'/>")
                bob.send(f"<a xmlns='{SM}' h='{bob_count}'/>")
                assert handled(alice) == 4
                assert handled(bob) == 2
                restart('kill')
                alice, result = resume(port, cert, token, alice_count, clients)
                assert result.get('h') == '4'
                # Bob's logical SM session remains joined while his transport
                # is offline. Alice's fanout must queue before Bob authenticates.
                alice.send(f"<message to='{ROOM}' type='groupchat'><body>after room crash</body></message>")
                assert alice.body('after room crash').get('from') == ROOM + '/Alice'
                assert handled(alice) == 5
                # Inspect the committed slot before any Bob authentication.
                # A history replay on rejoining is not offline SM delivery.
                slots = list((root/'data').rglob(bob_token + '.json'))
                assert len(slots) == 1, slots
                record = json.loads(slots[0].read_text())
                assert record['jid'] == 'bob@localhost/room', record
                queued = [ET.fromstring(xml) for xml in record['pending']]
                assert any(packet.get('from') == ROOM + '/Alice'
                           and any(local(node) == 'body' and node.text == 'after room crash'
                                   for node in packet)
                           for packet in queued), ('room fanout missing from Bob durable pending before authentication', record)
                bob, result = resume(port, cert, bob_token, bob_count, clients, user='bob')
                assert result.get('h') == '2'
                packet = bob.body('after room crash')
                assert packet.get('from') == ROOM + '/Alice'
                assert packet.find('.//{urn:xmpp:delay}delay') is None, ET.tostring(packet)
                restart('term')

                # Expired detached sessions stay expired through repeated boot.
                cfg['global']['smacks_hibernation_time'] = 1
                stop(server)
                config.write_text(json.dumps(cfg))
                server = start(binary, config, port, log)
                short = connect(resource='short')
                expired = enable(short)
                short.close()
                time.sleep(1.3)
                restart('kill')
                resume(port, cert, expired, 0, clients, success=False)
                restart('term')
                resume(port, cert, expired, 0, clients, success=False)

                # Account deletion must deliver its successful IQ response
                # before closing the stream and revoke every old resume token.
                stop(server)
                cfg['global']['smacks_hibernation_time'] = 300
                config.write_text(json.dumps(cfg))
                server = start(binary, config, port, log)
                removed = connect(resource='remove-account')
                revoked = enable(removed)
                removed.send("<iq type='set' id='remove-account'><query xmlns='jabber:iq:register'><remove/></query></iq>")
                removed.iq('remove-account')
                stop(server)
                subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'],
                               input='new-secret\n', text=True, check=True, capture_output=True)
                server = start(binary, config, port, log)
                resume(port, cert, revoked, 0, clients, password='new-secret', success=False)
            finally:
                if server is not None and server.poll() is None:
                    stop(server)
                for client in clients:
                    client.close()
                if sys.exc_info()[0] is not None:
                    log.seek(0)
                    print(log.read(), file=sys.stderr)
    print('PASS: TLS legacy/SASL2 durable SM after SIGKILL/SIGTERM, counters, ack pruning, at-least-once pending replay, owner/token/h rejection, transport/resource conflict, MUC activation/offline fanout, grace expiry and account deletion/recreation revocation')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()))
