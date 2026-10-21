#!/usr/bin/env python3
"""Personal delivery must not await a stalled external XEP-0357 gateway.

Real c2s and s2s STARTTLS; Bob hibernates or goes offline with registered push. The
account domain is chat.localhost and the external push service is localhost,
which is not a configured local host. Its standard s2s endpoint is a local
fixture on 127.0.0.1:5269; the special-use localhost name avoids external DNS.
After verified TLS it reads the server's stream but never sends features.
--expect-blocked demonstrates the old bug in a bounded two-second observation;
the default asserts both durable deliveries and Alice's handled SM ACK while
the real gateway transport remains stalled. This is a local regression fixture,
not an APNs/FCM or production-client validation.
"""
import argparse
import asyncio
import hashlib
import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from message_latency_network import slot
import muc_sm_load_network as network
from muc_sm_load_network import SM, start

PUSH = 'urn:xmpp:push:0'
GATEWAY = 'localhost'
DOMAIN = 'chat.localhost'
network.STREAM = network.STREAM.replace("to='localhost'", f"to='{DOMAIN}'")


class Client(network.Client):
    def __init__(self, *args):
        super().__init__(*args)
        self.jid = self.jid.replace('@localhost/', f'@{DOMAIN}/')

    async def fence(self, identifier):
        await self.stanza(f"<iq type='get' to='{DOMAIN}' id='{identifier}'><ping xmlns='urn:xmpp:ping'/></iq>")
        result = await self.wait(lambda: self.iqs.pop(identifier, None), identifier)
        assert result.get('type') == 'result'


def openssl(root, *args):
    subprocess.run(['openssl', *args], cwd=root, check=True, capture_output=True)


def certificates(root):
    openssl(root, 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
            'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj',
            '/CN=Push latency fixture CA', '-addext',
            'basicConstraints=critical,CA:TRUE', '-keyout', 'ca.key', '-out', 'ca.pem')
    openssl(root, 'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-subj', '/CN=localhost', '-keyout', 'key.pem', '-out', 'server.csr')
    (root/'extensions').write_text('basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n'
        'subjectAltName=DNS:localhost,DNS:chat.localhost\n')
    openssl(root, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem',
            '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile',
            'extensions', '-out', 'cert.pem')


async def poll(predicate, description, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(.01)
    raise AssertionError(description)


class Blackhole:
    def __init__(self, root):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(root/'cert.pem', root/'key.pem')
        self.seen = asyncio.Event()
        self.tasks = set()
        self.writers = set()
        self.errors = []
        self.closed = False
        self.snapshot = lambda: None
        self.pending_at_stream = None

    async def accept(self, reader, writer):
        self.tasks.add(asyncio.current_task())
        self.writers.add(writer)
        try:
            stream = await reader.readuntil(b'>')
            if stream.startswith(b'<?xml'):
                stream = await reader.readuntil(b'>')
            assert b'stream:stream' in stream and GATEWAY.encode() in stream
            header = ("<stream:stream xmlns='jabber:server' "
                "xmlns:stream='http://etherx.jabber.org/streams' "
                "from='localhost' to='chat.localhost' version='1.0'>")
            writer.write((header + "<stream:features><starttls "
                "xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/>"
                "</starttls></stream:features>").encode())
            await writer.drain()
            assert b'starttls' in await reader.readuntil(b'>')
            writer.write(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            await writer.drain()
            await writer.start_tls(self.context)
            stream = await reader.readuntil(b'>')
            if stream.startswith(b'<?xml'):
                stream = await reader.readuntil(b'>')
            assert b'stream:stream' in stream and GATEWAY.encode() in stream
            writer.write(header.encode())
            await writer.drain()
            self.pending_at_stream = self.snapshot()
            self.seen.set()
            # Keep transport open; features are never sent and no route completes.
            await reader.read()
            self.closed = True
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            writer.close()
            self.writers.discard(writer)
            self.tasks.discard(asyncio.current_task())

    async def close(self):
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for writer in list(self.writers):
            writer.close()


async def exercise(root, binary, config, port, args, log):
    gateway = Blackhole(root)
    try:
        listener = await asyncio.start_server(gateway.accept, '127.0.0.1', 5269)
    except OSError as error:
        raise RuntimeError(f'push fixture needs an unused {GATEWAY}:5269: {error}') from error
    clients = []
    server = None
    try:
        # rustls-native-certs uses this explicit fixture trust bundle; identity
        # verification still checks the remote JID's DNS SAN during real TLS.
        previous = os.environ.get('SSL_CERT_FILE')
        os.environ['SSL_CERT_FILE'] = str(root/'ca.pem')
        try:
            server = start(str(binary), config, port, log)
        finally:
            if previous is None:
                os.environ.pop('SSL_CERT_FILE', None)
            else:
                os.environ['SSL_CERT_FILE'] = previous
        context = ssl.create_default_context(cafile=str(root/'ca.pem'))
        for number in range(2):
            client = await asyncio.wait_for(Client.connect(number, port, context, 2), 10)
            clients.append(client)
            client.auto_ack = False
            if number == 0 or args.recipient == 'hibernating':
                await client.enable()
            await client.stanza('<presence/>')
            await client.fence(f'ready-{number}')
            if client.token:
                await client.handled()
                await client.ack()
        alice, bob = clients
        await bob.stanza(f"<iq type='set' to='{bob.jid}' id='push-enable'>"
            f"<enable xmlns='{PUSH}' jid='{GATEWAY}' node='phone'/></iq>")
        response = await bob.wait(lambda: bob.iqs.get('push-enable'), 'push registration')
        assert response.get('type') == 'result'
        if bob.token:
            await bob.handled()
            await bob.ack()
            await poll(lambda: bool(slot(root, bob).get('push_identifier')), 'missing durable push binding')
        else:
            registration = list((root/'data').rglob('cloud_notify/*.dat'))
            assert len(registration) == 1 and 'phone' in registration[0].read_text(), 'missing native push registration'
        await bob.close_raw()
        mode = 'hibernating' if bob.token else 'removed'
        await poll(lambda: any('session-disconnected' in line and mode in line
                   and bob.jid in line for line in (root/'server.log').read_text().splitlines()),
                   f'Bob did not enter {mode} state')
        if not bob.token:
            assert len(list((root/'data').rglob('rust_smacks/*.json'))) == 1, 'offline Bob unexpectedly has an SM slot'

        def pending_state():
            if bob.token:
                pending = slot(root, bob)['pending']
            else:
                pending = [path.read_text() for path in (root/'data').rglob('offline/*.list')]
            return {identifier: any(identifier in stanza for stanza in pending)
                    for identifier in ('push-first', 'push-second')}

        gateway.snapshot = pending_state
        before = alice.inputs
        began = time.perf_counter()
        for identifier in ('push-first', 'push-second'):
            await alice.stanza(f"<message to='{bob.jid}' type='chat' id='{identifier}'>"
                f"<body>{identifier}</body></message>")
        await alice.send(f"<r xmlns='{SM}'/>")
        # Observe for the fixed interval even if a faulty implementation emits an
        # early ACK. Durable pending state and a real blocked gateway are required.
        await asyncio.sleep(args.bound)
        present = pending_state()
        acknowledgements = [int(node.get('h')) for node in alice.controls[f'{{{SM}}}a']]
        seen_at_bound = gateway.seen.is_set()
        assert not gateway.errors and not gateway.closed, (gateway.errors, gateway.closed)
        if not args.expect_blocked or bob.token:
            assert present['push-first'], 'first message was not durably delivered before push'
        if args.expect_blocked:
            assert not present['push-second'], 'old blocking behavior was not reproduced'
            assert not acknowledgements, acknowledgements
            assert slot(root, alice)['handled'] == before, 'first message marked handled before blocked push'
        else:
            assert present['push-second'], 'second message blocked behind external push'
            assert acknowledgements == [alice.inputs], acknowledgements
            assert slot(root, alice)['handled'] == alice.inputs
        assert not alice.errors, alice.errors
        assert gateway.seen.is_set(), f'no real post-TLS push attempt: {gateway.errors}'
        assert not gateway.errors and not gateway.closed, (gateway.errors, gateway.closed)
        if not args.expect_blocked:
            assert gateway.pending_at_stream['push-first'], 'push started before first durable recipient delivery'
        elif not bob.token:
            assert not present['push-first'], 'old offline ordering bug was not reproduced'
            assert not gateway.pending_at_stream['push-first']
        return {'status': 'reproduced-blocking' if args.expect_blocked else 'pass',
                'recipient_state': args.recipient,
                'durable_pending_at_gateway_stream': gateway.pending_at_stream,
                'observation_seconds': args.bound, 'elapsed_seconds': time.perf_counter()-began,
                'gateway_post_tls_stream_observed': gateway.seen.is_set(),
                'gateway_post_tls_stream_at_bound': seen_at_bound,
                'blocked_stage': 'post-tls-features' if gateway.seen.is_set() else 'external-route-before-tcp',
                'durable_pending': present,
                'sender_sm_ack_h': acknowledgements, 'sender_inputs': alice.inputs,
                'sender_handled_before': before}
    finally:
        # Kill before closing the blackhole: releasing it could complete the old
        # awaited route and would invalidate this bounded reproducer.
        if server is not None:
            server.kill()
            server.wait(timeout=5)
        listener.close()
        await listener.wait_closed()
        await gateway.close()
        await asyncio.gather(*(client.close_raw() for client in clients), return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/release/rust-xmpp')
    parser.add_argument('--expect-blocked', action='store_true')
    parser.add_argument('--recipient', choices=('hibernating', 'offline'), default='hibernating')
    parser.add_argument('--bound', type=float, default=2)
    parser.add_argument('--output')
    args = parser.parse_args()
    assert 0 < args.bound < 10, 'observation must precede the 30-second federation timeout'
    with tempfile.TemporaryDirectory(prefix='xmpp-push-latency-') as directory:
        root = pathlib.Path(directory)
        binary = root/'rust-xmpp'
        shutil.copy2(pathlib.Path(args.binary).resolve(), binary)
        certificates(root)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        config = root/'config.json'
        config.write_text(json.dumps({'global': {'data_path': str(root/'data'),
            'interfaces': ['127.0.0.1'], 'c2s_ports': [port], 's2s_ports': [],
            'http_ports': [], 'https_ports': [],
            'modules_enabled': ['tls', 'saslauth', 'smacks', 'ping', 'cloud_notify', 's2s'],
            'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}},
            'hosts': {DOMAIN: {'options': {'authentication': 'internal_hashed',
                                              'password_hash': 'SHA-256'}}}}))
        for number in range(2):
            subprocess.run([str(binary), 'create-user', str(config), f'load-{number}',
                '--password-stdin'], input='load-test-password\n', text=True,
                check=True, capture_output=True)
        with (root/'server.log').open('w+') as log:
            try:
                report = asyncio.run(exercise(root, binary, config, port, args, log))
            except BaseException:
                log.seek(0)
                print(log.read())
                raise
        report['binary_version'] = subprocess.run([str(binary), '--version'],
            check=True, capture_output=True, text=True).stdout.strip()
        report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report['scope'] = 'loopback TLS fixture; stalled external XMPP push service; no APNs/FCM'
        result = json.dumps(report, indent=2)+'\n'
        if args.output:
            pathlib.Path(args.output).write_text(result)
        print(result, end='')


if __name__ == '__main__':
    main()
