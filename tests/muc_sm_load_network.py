#!/usr/bin/env python3
"""Exercise durable MUC/SM hot paths over real STARTTLS with bounded fanout.

python3 tests/muc_sm_load_network.py --binary target/release/rust-xmpp --clients 500
Defaults to 100 resources; --clients 500 uses 100 accounts and 10 rooms of 50.
JSON contains observed latency/RSS/CPU, slot counts and exact fanout assertions.
All sockets are drained continuously. SIGKILL precedes socket cleanup; ten
representatives resume with unacknowledged room output and send without rejoin.
This is a loopback smoke measurement, not a production capacity guarantee.
"""
import argparse
import asyncio
import base64
import collections
import hashlib
import json
import pathlib
import signal
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
from load_smoke import Client as BaseClient, STREAM, distribution, process_metrics, proc_pid

SM = 'urn:xmpp:sm:3'
MUC = 'http://jabber.org/protocol/muc'
CLIENT = 'jabber:client'


def start(binary, config, port, log):
    # Recovery of hundreds of durable resources legitimately exceeds the
    # five-second deadline used by the tiny functional restart fixture.
    server = subprocess.Popen([binary, 'serve', str(config), '--experimental'], stdout=log, stderr=log)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        assert server.poll() is None, 'server stopped during startup'
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return server
        except OSError:
            time.sleep(.05)
    server.kill()
    server.wait()
    raise AssertionError('server did not start within 60 seconds')


class Client(BaseClient):
    def __init__(self, number, user, reader, writer):
        super().__init__(number, user, reader, writer)
        self.received = self.inputs = self.acked = 0
        self.token = None
        self.presences = {}
        self.iqs = {}
        self.controls = collections.defaultdict(list)
        self.bodies = collections.Counter()
        self.errors = []
        self.changed = asyncio.Event()
        self.auto_ack = True
        self.task = None
        self.failure = None

    @classmethod
    async def connect(cls, number, port, context, accounts, bind=True):
        reader, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), 60)
        user = f'load-{number % accounts}'
        client = cls(number, user, reader, writer)
        try:
            await client.send(STREAM)
            assert b'starttls' in await client.until(b'</stream:features>')
            await client.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            assert b'proceed' in await client.until(b'/>')
            await writer.start_tls(context, server_hostname='localhost', ssl_handshake_timeout=60)
            await client.send(STREAM)
            await client.until(b'</stream:features>')
            auth = base64.b64encode(f'\0{user}\0load-test-password'.encode()).decode()
            await client.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth}</auth>")
            assert b'success' in await client.until(b'/>')
            await client.send(STREAM)
            await client.until(b'</stream:features>')
            if bind:
                await client.send(f"<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>load-{number}</resource></bind></iq>")
                assert client.jid.encode() in await client.until(b'</iq>')
            client.task = asyncio.create_task(client.drain())
            return client
        except BaseException:
            writer.close()
            raise

    async def stanza(self, text):
        self.inputs = (self.inputs + 1) % (1 << 32)
        await self.send(text)

    async def drain(self):
        parser = ET.XMLPullParser(events=('start', 'end'))
        parser.feed("<root xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>")
        root = next(parser.read_events())[1]
        depth = 0
        try:
            while chunk := await self.reader.read(65536):
                parser.feed(chunk)
                if hasattr(parser, 'flush'):
                    parser.flush()
                for event, node in parser.read_events():
                    depth += 1 if event == 'start' else -1
                    if event != 'end' or depth != 0:
                        continue
                    local = node.tag.split('}')[-1]
                    if node.tag in (f'{{{CLIENT}}}iq', f'{{{CLIENT}}}presence', f'{{{CLIENT}}}message'):
                        self.received = (self.received + 1) % (1 << 32)
                    if node.get('type') == 'error':
                        self.errors.append(ET.tostring(node).decode())
                    if local == 'presence':
                        self.presences[node.get('from')] = node
                    elif local == 'iq':
                        self.iqs[node.get('id')] = node
                    elif local == 'message':
                        for body in node.findall(f'{{{CLIENT}}}body'):
                            self.bodies[body.text] += 1
                    elif node.tag == f'{{{SM}}}r':
                        if self.auto_ack:
                            await self.ack()
                    else:
                        self.controls[node.tag].append(node)
                    root.remove(node)
                    self.changed.set()
            raise EOFError('server closed stream')
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.failure = error
            self.changed.set()

    async def wait(self, predicate, description):
        async def observe():
            while True:
                self.changed.clear()
                result = predicate()
                if isinstance(result, ET.Element) or result:
                    return result
                if self.failure:
                    raise RuntimeError(f'client {self.number}: {description}: {self.failure}')
                await self.changed.wait()
        return await asyncio.wait_for(observe(), 120)

    async def control(self, name):
        key = f'{{{SM}}}{name}'
        await self.wait(lambda: self.controls[key], name)
        return self.controls[key].pop(0)

    async def enable(self):
        await self.send(f"<enable xmlns='{SM}' resume='true'/>")
        node = await self.control('enabled')
        assert node.get('resume') == 'true'
        self.token = node.get('id')
        assert self.token

    async def fence(self, identifier):
        await self.stanza(f"<iq type='get' to='localhost' id='{identifier}'><ping xmlns='urn:xmpp:ping'/></iq>")
        result = await self.wait(lambda: self.iqs.pop(identifier, None), identifier)
        assert result.get('type') == 'result', ET.tostring(result)

    async def ack(self):
        self.acked = self.received
        await self.send(f"<a xmlns='{SM}' h='{self.acked}'/>")

    async def handled(self):
        await self.send(f"<r xmlns='{SM}'/>")
        value = int((await self.control('a')).get('h'))
        assert value == self.inputs, (self.number, value, self.inputs)
        return value

    async def close_raw(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        self.writer.close()
        try:
            await asyncio.wait_for(self.writer.wait_closed(), 3)
        except (OSError, ssl.SSLError, TimeoutError):
            pass


def slots(root):
    paths = list((root / 'data').rglob('rust_smacks/*.json'))
    return {'count': len(paths), 'bytes': sum(p.stat().st_size for p in paths)}


async def exercise(args, root, config, port, log):
    clients = []
    server = await asyncio.to_thread(start, args.binary, config, port, log)
    pid = proc_pid(server.pid)
    samples = []
    running = True
    async def sample():
        while running:
            samples.append(process_metrics(pid))
            await asyncio.sleep(.2)
    sampler = asyncio.create_task(sample())
    gate = asyncio.Semaphore(args.concurrency)
    context = ssl.create_default_context(cafile=str(root / 'cert.pem'))
    report = {'clients': args.clients, 'accounts': args.accounts, 'rooms': args.rooms,
              'message_rounds': args.rounds, 'concurrency': args.concurrency,
              'binary': args.binary, 'binary_sha256': hashlib.sha256(pathlib.Path(args.binary).read_bytes()).hexdigest(),
              'before': process_metrics(pid)}
    begun = time.perf_counter()
    def save(phase):
        report['phase'] = phase
        report['status'] = 'running'
        report['elapsed_seconds'] = round(time.perf_counter() - begun, 3)
        pathlib.Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
        print(f'MUC+SM load: {phase} ({report["elapsed_seconds"]}s)', file=sys.stderr, flush=True)
    try:
        async def setup(number):
            async with gate:
                started = time.perf_counter()
                client = await Client.connect(number, port, context, args.accounts)
                clients.append(client)
                await client.enable()
                await client.stanza('<presence/>')
                await client.fence(f'connected-{number}')
                await client.ack()
                return time.perf_counter() - started
        connect_times = await asyncio.gather(*(setup(i) for i in range(args.clients)))
        clients.sort(key=lambda c: c.number)
        report['connect_seconds'] = round(time.perf_counter() - begun, 3)
        report['connect_latency'] = distribution(connect_times)
        save('connected')
        groups = [[c for c in clients if c.number % args.rooms == room] for room in range(args.rooms)]
        started = time.perf_counter()
        async def join(client):
            async with gate:
                room = f'load-{client.number % args.rooms}@rooms.localhost'
                await client.stanza(f"<presence to='{room}/Nick-{client.number}'><x xmlns='{MUC}'><history maxstanzas='0'/></x></presence>")
                result = await client.wait(lambda: client.presences.get(f'{room}/Nick-{client.number}'), 'self MUC join')
                assert result.get('type') != 'error', ET.tostring(result)
        await asyncio.gather(*(join(c) for c in clients))
        # Each room has exactly N nicknames, including self, on every resource.
        for group in groups:
            for client in group:
                expected = {f'load-{client.number % args.rooms}@rooms.localhost/Nick-{other.number}' for other in group}
                await client.wait(lambda c=client,e=expected: e.issubset(c.presences), 'complete join fanout')
        await asyncio.gather(*(c.fence(f'joined-{c.number}') for c in clients))
        await asyncio.gather(*(c.ack() for c in clients))
        await asyncio.gather(*(c.handled() for c in clients))
        report['join_seconds'] = round(time.perf_counter() - started, 3)
        report['joined'] = process_metrics(pid)
        report['join_presence_deliveries'] = sum(len(g) ** 2 for g in groups)
        report['slots_joined'] = slots(root)
        assert report['slots_joined']['count'] == args.clients, report['slots_joined']
        save('joined')
        delivered = 0
        started = time.perf_counter()
        for turn in range(args.rounds):
            for index, group in enumerate(groups):
                sender = group[turn % len(group)]
                text = f'durable-load-{turn}-{index}'
                await sender.stanza(f"<message type='groupchat' to='load-{index}@rooms.localhost'><body>{text}</body></message>")
            async def receive(client):
                text = f'durable-load-{turn}-{client.number % args.rooms}'
                await client.wait(lambda: client.bodies[text] >= 1, text)
                assert client.bodies[text] == 1, (client.number, text, client.bodies[text])
            await asyncio.gather(*(receive(c) for c in clients))
            delivered += len(clients)
            await asyncio.gather(*(c.fence(f'round-{turn}-{c.number}') for c in clients))
            await asyncio.gather(*(c.ack() for c in clients))
        report['message_seconds'] = round(time.perf_counter() - started, 3)
        report['room_messages_sent'] = args.rounds * args.rooms
        report['room_messages_delivered'] = delivered
        assert delivered == args.clients * args.rounds
        save('fanout_verified')
        assert not [(c.number,c.errors) for c in clients if c.errors]
        # Freeze acknowledgements, then deliberately receive one more message
        # per room without acknowledging it. Its durable replay is mandatory.
        representatives = [group[0] for group in groups]
        for client in clients:
            client.auto_ack = False
        for index, sender in enumerate(representatives):
            await sender.stanza(f"<message type='groupchat' to='load-{index}@rooms.localhost'><body>pending-{index}</body></message>")
        await asyncio.gather(*(c.wait(lambda c=c: c.bodies[f'pending-{c.number % args.rooms}'] == 1, 'pending room message') for c in clients))
        await asyncio.gather(*(c.fence(f'before-kill-{c.number}') for c in clients))
        await asyncio.gather(*(c.handled() for c in clients))
        expected = {c.number: {'token': c.token, 'acked': c.acked, 'handled': c.inputs} for c in representatives}
        report['before_kill'] = process_metrics(pid)
        report['slots_before_kill'] = slots(root)
        save('before_sigkill')
        server.send_signal(signal.SIGKILL)
        assert await asyncio.to_thread(server.wait, 10) == -signal.SIGKILL
        await asyncio.gather(*(c.close_raw() for c in clients))
        clients.clear()
        started = time.perf_counter()
        server = await asyncio.to_thread(start, args.binary, config, port, log)
        pid = proc_pid(server.pid)
        report['restart_seconds'] = round(time.perf_counter() - started, 3)
        async def recover(number):
            async with gate:
                old = expected[number]
                client = await Client.connect(number, port, context, args.accounts, bind=False)
                client.auto_ack = False
                client.received = old['acked']
                client.acked = old['acked']
                client.inputs = old['handled']
                client.token = old['token']
                clients.append(client)
                await client.send(f"<resume xmlns='{SM}' previd='{client.token}' h='{client.acked}'/>")
                result = await client.control('resumed')
                assert result.get('previd') == client.token
                assert int(result.get('h')) == client.inputs, (number, ET.tostring(result),client.inputs)
                room = number % args.rooms
                await client.wait(lambda: client.bodies[f'pending-{room}'] == 1, 'unacknowledged room replay')
                await client.wait(lambda: client.iqs.get(f'before-kill-{number}'), 'unacknowledged IQ replay')
                # No available presence or MUC join is sent after SM resume.
                text = f'after-resume-{room}'
                await client.stanza(f"<message type='groupchat' to='load-{room}@rooms.localhost'><body>{text}</body></message>")
                await client.wait(lambda: client.bodies[text] == 1, 'recovered membership groupchat echo')
                await client.fence(f'after-resume-{number}')
                await client.ack()
                await client.handled()
                assert not client.errors, client.errors
                # No message already acknowledged before SIGKILL may replay.
                assert not any(count for text,count in client.bodies.items() if text and text.startswith('durable-load-')), client.bodies
                return number
        recovered = await asyncio.gather(*(recover(c.number) for c in representatives))
        report['resumed_resources'] = len(recovered)
        report['replayed_pending_room_messages'] = len(recovered)
        report['membership_groupchat_deliveries_after_resume'] = len(recovered)
        report['after_resume'] = process_metrics(pid)
        report['slots_after_resume'] = slots(root)
        report['total_seconds'] = round(time.perf_counter() - begun, 3)
        report['elapsed_seconds'] = report['total_seconds']
        report['peak_rss_kib'] = max((s.get('rss_kib',0) for s in samples), default=0)
        report['status'] = 'pass'
        report['phase'] = 'completed'
        return report
    except BaseException as error:
        report['status'] = 'fail'
        report['failure'] = repr(error)
        report['elapsed_seconds'] = round(time.perf_counter() - begun, 3)
        pathlib.Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
        raise
    finally:
        running = False
        sampler.cancel()
        await asyncio.gather(sampler, return_exceptions=True)
        if server.poll() is None:
            server.terminate()
            try:
                await asyncio.to_thread(server.wait, 20)
            except subprocess.TimeoutExpired:
                server.kill()
                await asyncio.to_thread(server.wait)
        await asyncio.gather(*(c.close_raw() for c in clients), return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/release/rust-xmpp')
    parser.add_argument('--clients', type=int, default=100)
    parser.add_argument('--accounts', type=int, default=100)
    parser.add_argument('--rooms', type=int, default=10)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--concurrency', type=int, default=20)
    parser.add_argument('--output', default='/tmp/muc-sm-load.json')
    args = parser.parse_args()
    args.binary = str(pathlib.Path(args.binary).resolve())
    args.accounts = min(args.accounts,args.clients)
    assert 1 <= args.rooms <= args.clients <= 4000
    assert 1 <= args.accounts <= args.clients and args.rounds > 0 and args.concurrency > 0
    with tempfile.TemporaryDirectory(prefix='xmpp-durable-muc-load-') as tmp:
        root = pathlib.Path(tmp)
        # Release builds/packaging may replace the source binary during a long
        # run; this private executable is the same inode generation on restart.
        shutil.copy2(args.binary, root / 'rust-xmpp')
        args.binary = str(root / 'rust-xmpp')
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                        '-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
                        '-addext','basicConstraints=critical,CA:FALSE','-keyout',str(root/'key.pem'),
                        '-out',str(root/'cert.pem')],check=True,capture_output=True)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0))
            port = probe.getsockname()[1]
        cfg = {'global': {'data_path':str(root/'data'),'interfaces':['127.0.0.1'],
                         'c2s_ports':[port],'s2s_ports':[],'http_ports':[],'https_ports':[],
                         'smacks_hibernation_time':600,'muc_recovery_grace_period':600,
                         'modules_enabled':['tls','saslauth','smacks','disco','ping'],
                         'ssl':{'key':str(root/'key.pem'),'certificate':str(root/'cert.pem')}},
               'hosts': {'localhost':{'options':{'authentication':'internal_hashed','password_hash':'SHA-256'}},
                         'rooms.localhost':{'component':'muc','options':{'muc_room_locking':False,
                             'muc_room_default_history_length':0,'max_history_messages':0}}}}
        config = root/'config.json'
        config.write_text(json.dumps(cfg))
        for number in range(args.accounts):
            subprocess.run([args.binary,'create-user',str(config),f'load-{number}','--password-stdin'],
                           input='load-test-password\n',text=True,check=True,capture_output=True)
        with (root/'server.log').open('w+') as log:
            try:
                report = asyncio.run(exercise(args,root,config,port,log))
            except BaseException:
                log.flush();log.seek(0)
                print(log.read(),file=sys.stderr)
                raise
        pathlib.Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
