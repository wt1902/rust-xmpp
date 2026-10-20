#!/usr/bin/env python3
"""Isolated Linux multi-account TCP/STARTTLS load smoke; stdlib and openssl only.
Reports observations, not production capacity guarantees or memory-leak proof.
"""
import argparse
import asyncio
import base64
import json
import os
import pathlib
import socket
import ssl
import statistics
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

STREAM = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>"


def proc_pid(child_pid):
    """Resolve this direct child's procfs PID when /proc exposes the host namespace."""
    status = pathlib.Path('/proc/self/status').read_text()
    parent = next(int(line.split()[1]) for line in status.splitlines() if line.startswith('Pid:'))
    children = [p.name for p in pathlib.Path('/proc').iterdir() if p.name.isdigit()]
    for candidate in children:
        try:
            fields = dict(line.split(':', 1) for line in pathlib.Path(f'/proc/{candidate}/status').read_text().splitlines() if ':' in line)
        except (OSError, ProcessLookupError):
            continue
        namespaces = fields.get('NSpid', fields['Pid']).split()
        if int(namespaces[-1]) == child_pid and int(fields['PPid'].strip()) == parent and fields['Name'].strip() == 'rust-xmpp':
            return int(candidate)
    raise RuntimeError('cannot resolve owned server process in procfs')


def process_metrics(pid):
    try:
        status = pathlib.Path(f'/proc/{pid}/status').read_text()
        rss = next(int(line.split()[1]) for line in status.splitlines() if line.startswith('VmRSS:'))
        fields = pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        cpu = (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')
        return {'rss_kib': rss, 'cpu_seconds': cpu, 'fd_count': len(list(pathlib.Path(f'/proc/{pid}/fd').iterdir()))}
    except (OSError, StopIteration):
        return {'unavailable': True}


def distribution(values):
    if not values:
        return {}
    values = sorted(values)
    return {'samples': len(values), 'median_ms': round(statistics.median(values)*1000, 3),
            'p95_ms': round(values[min(len(values)-1, int(len(values)*.95))]*1000, 3),
            'max_ms': round(values[-1]*1000, 3)}


class Client:
    def __init__(self, number, user, reader, writer):
        self.number, self.user, self.reader, self.writer = number, user, reader, writer
        self.jid = f"{user}@localhost/load-{number}"

    async def send(self, text):
        self.writer.write(text.encode())
        await self.writer.drain()

    async def until(self, end):
        return await asyncio.wait_for(self.reader.readuntil(end), 60)

    @classmethod
    async def connect(cls, number, port, context, accounts):
        reader, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), 30)
        user = "load" if accounts == 1 else f"load-{number % accounts}"
        client = cls(number, user, reader, writer)
        try:
            await client.send(STREAM)
            assert b'starttls' in await client.until(b'</stream:features>')
            await client.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            assert b'proceed' in await client.until(b'/>')
            await writer.start_tls(context, server_hostname='localhost', ssl_handshake_timeout=30)
            await client.send(STREAM)
            assert b'PLAIN' in await client.until(b'</stream:features>')
            auth = base64.b64encode(f'\0{user}\0load-test-password'.encode()).decode()
            await client.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth}</auth>")
            assert b'success' in await client.until(b'/>')
            await client.send(STREAM)
            assert b'xmpp-bind' in await client.until(b'</stream:features>')
            await client.send(f"<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>load-{number}</resource></bind></iq>")
            reply = await client.until(b'</iq>')
            assert client.jid.encode() in reply, reply
            return client
        except BaseException:
            writer.close()
            raise

    async def ping(self, round_number):
        start = time.perf_counter()
        await self.send(f"<iq type='get' id='ping-{round_number}' to='localhost'><ping xmlns='urn:xmpp:ping'/></iq>")
        reply = ET.fromstring(await self.until(b'</iq>'))
        assert reply.get('type') == 'result' and reply.get('id') == f'ping-{round_number}'
        return time.perf_counter()-start

    async def close(self):
        try:
            await self.send('</stream:stream>')
        except (OSError, ssl.SSLError):
            pass
        self.writer.close()
        try:
            await asyncio.wait_for(self.writer.wait_closed(), 10)
        except (OSError, ssl.SSLError, TimeoutError):
            pass


async def run_load(count, accounts, concurrency, rounds, message_rounds, port, context, pid):
    clients, failures, setup_times, samples = [], [], [], []
    sampling = True

    async def sample():
        while sampling:
            samples.append(process_metrics(pid))
            await asyncio.sleep(.1)

    sampler = asyncio.create_task(sample())
    gate = asyncio.Semaphore(concurrency)
    started = time.perf_counter()

    async def connect(number):
        async with gate:
            start = time.perf_counter()
            try:
                client = await Client.connect(number, port, context, accounts)
                clients.append(client)
                setup_times.append(time.perf_counter()-start)
            except Exception as error:
                failures.append({'phase': 'connect', 'resource': number, 'error': repr(error)})

    before = process_metrics(pid)
    try:
        await asyncio.gather(*(connect(i) for i in range(count)))
        setup_seconds = time.perf_counter()-started
        connected_metrics = process_metrics(pid)
        ping_times = []
        for round_number in range(rounds):
            results = await asyncio.gather(*(c.ping(round_number) for c in clients), return_exceptions=True)
            for client, result in zip(clients, results):
                if isinstance(result, Exception):
                    failures.append({'phase': 'ping', 'resource': client.number, 'error': repr(result)})
                else:
                    ping_times.append(result)
        # Explicit full JIDs avoid presence fanout and deliver exactly one message per resource.
        message_start = time.perf_counter()
        clients.sort(key=lambda c: c.number)
        delivered = 0
        for batch in range(message_rounds):
            for i, client in enumerate(clients):
                target = clients[(i+1) % len(clients)]
                await client.send(f"<message to='{target.jid}' type='chat' id='m-{batch}-{client.number}'><body>load-smoke-{client.number}</body></message>")

            async def receive_message(index, client):
                reply = ET.fromstring(await client.until(b'</message>'))
                expected = clients[(index-1) % len(clients)]
                assert reply.get('id') == f'm-{batch}-{expected.number}', ET.tostring(reply)
                assert reply.get('from') == expected.jid, ET.tostring(reply)
                assert reply.find('{jabber:client}body').text == f'load-smoke-{expected.number}'

            results = await asyncio.gather(*(receive_message(i, c) for i, c in enumerate(clients)), return_exceptions=True)
            for client, result in zip(clients, results):
                if isinstance(result, Exception):
                    failures.append({'phase': 'message', 'batch': batch, 'resource': client.number, 'error': repr(result)})
                else:
                    delivered += 1
        message_seconds = time.perf_counter()-message_start
        steady = process_metrics(pid)
        await asyncio.gather(*(c.close() for c in clients))
        await asyncio.sleep(2)
        after = process_metrics(pid)
        return {'total_load_wall_seconds': round(time.perf_counter()-started, 3), 'requested_resources': count, 'authenticated_bound_resources': len(clients),
                'connection_setup_concurrency': concurrency, 'setup_wall_seconds': round(setup_seconds, 3),
                'setup_latency': distribution(setup_times), 'ping_rounds': rounds, 'ping_round_trip': distribution(ping_times),
                'accounts': accounts, 'message_rounds': message_rounds, 'messages_sent': len(clients)*message_rounds, 'messages_received': delivered, 'message_batch_seconds': round(message_seconds, 3),
                'metrics_before': before, 'metrics_connected': connected_metrics, 'metrics_after_workload': steady,
                'metrics_two_seconds_after_disconnect': after,
                'sampled_peak_rss_kib': max((s['rss_kib'] for s in samples if 'rss_kib' in s), default=None),
                'fd_delta_after_disconnect': after['fd_count']-before['fd_count'] if 'fd_count' in after and 'fd_count' in before else None,
                'failures': failures,
                'scope': f'One loopback host, {accounts} accounts with distinct resources, TLS+PLAIN, ping and directed messages; not a production benchmark or proof of no memory leaks.'}
    finally:
        sampling = False
        await sampler
        await asyncio.gather(*(c.close() for c in clients), return_exceptions=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=str(pathlib.Path(__file__).resolve().parents[1] / 'target/release/rust-xmpp'))
    parser.add_argument('--clients', type=int, default=500)
    parser.add_argument('--archive', action='store_true', help='enable persistent MAM and verify both account archives')
    parser.add_argument('--accounts', type=int, default=1)
    parser.add_argument('--message-rounds', type=int, default=1)
    parser.add_argument('--concurrency', type=int, default=50)
    parser.add_argument('--rounds', type=int, default=3)
    args = parser.parse_args()
    assert 1 <= args.clients <= 4000 and args.concurrency > 0 and args.rounds > 0 and 1 <= args.accounts <= args.clients and args.message_rounds > 0
    with tempfile.TemporaryDirectory(prefix='rust-xmpp-load-smoke-') as directory:
        work = pathlib.Path(directory)
        cert, key = work/'cert.pem', work/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        config = {'global': {'data_path': str(work/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port],
                            's2s_ports': [], 'http_ports': [], 'https_ports': [], 'allow_registration': False,
                            'modules_enabled': ['tls', 'saslauth', 'disco', 'ping'],
                            'ssl': {'certificate': str(cert), 'key': str(key)}},
                  'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256'}}}}
        if args.archive:
            config['global']['modules_enabled'].append('mam')
            config['global']['default_archive_policy'] = True
            config['global']['archive_expires_after'] = 'never'
        path = work/'config.json'
        path.write_text(json.dumps(config))
        for account in range(args.accounts):
            user = 'load' if args.accounts == 1 else f'load-{account}'
            subprocess.run([args.binary, 'create-user', str(path), user, '--password-stdin'], input='load-test-password\n', text=True, capture_output=True, check=True)
        with open(work/'server.log', 'w+') as log:
            process = subprocess.Popen([args.binary, 'serve', str(path), '--experimental'], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError('server exited during startup')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError('startup timed out')
                time.sleep(.2)
                context = ssl.create_default_context(cafile=str(cert))
                report = asyncio.run(run_load(args.clients, args.accounts, args.concurrency, args.rounds, args.message_rounds, port, context, proc_pid(process.pid)))
                if args.archive:
                    archives = list((work/'data'/'localhost'/'archive').glob('*.list'))
                    records = sum(sum(1 for line in archive.open() if line.startswith('item(')) for archive in archives)
                    expected = report['messages_received'] * (1 if args.accounts == 1 else 2)
                    report['mam'] = {'archive_files': len(archives), 'records': records, 'expected_records': expected}
                    assert records == expected, report['mam']
                print(json.dumps(report, indent=2))
                if report['failures'] or report['authenticated_bound_resources'] != args.clients:
                    raise SystemExit(1)
            except BaseException:
                log.flush()
                log.seek(0)
                print('SERVER LOG:\n'+log.read())
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
