#!/usr/bin/env python3
"""Opt-in real XEP-0363 HTTPS large-file regression (default: 10 GiB).

Example: python3 tests/upload_large_network.py --binary /tmp/rust-xmpp
Writes the actual complete payload through TLS to the server's local file
stream storage, then reads every byte back through verified TLS. No source
file, sparse allocation, external server, or body-sized Python buffer is used.
Not part of the default local check because it needs >10 GiB free disk.
"""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from _wire_client import Client, BIN

NS = 'urn:xmpp:http:upload:0'
CHUNK = bytes(range(256)) * 4096  # one deterministic 1 MiB buffer


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def proc_status_for_child(pid):
    # /proc can expose host PIDs while Popen.pid is in a nested PID namespace.
    parent = str(Path('/proc/self').resolve().name)
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = dict(line.split(':', 1) for line in (entry/'status').read_text().splitlines() if ':' in line)
            namespace_pids = fields.get('NSpid', fields.get('Pid', '')).split()
            if fields.get('PPid', '').strip() == parent and namespace_pids[-1:] == [str(pid)]:
                return entry/'status'
        except OSError:
            pass
    return None


def rss(status_path):
    if status_path is None:
        return 0
    try:
        for line in status_path.read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return 0


def progress(phase, count, size, start, last):
    now = time.monotonic()
    if now - last >= 5 or count == size:
        print(f'{phase}: {count}/{size} bytes ({count / max(now-start, .001) / 2**20:.1f} MiB/s)', flush=True)
        return now
    return last


def run(args, report):
    with tempfile.TemporaryDirectory(prefix='xmpp-large-', dir=args.temp_dir) as tmp:
        root = Path(tmp)
        report['free_disk_before_bytes'] = shutil.disk_usage(root).free
        assert report['free_disk_before_bytes'] >= args.size + 256 * 2**20, 'Insufficient free disk for real upload'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        port, https = free_port(), free_port()
        while https == port:
            https = free_port()
        cert = {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}
        config = {'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'],
                            'c2s_ports': [port], 'http_ports': [], 'https_ports': [https], 's2s_ports': [],
                            'modules_enabled': ['tls', 'saslauth', 'disco', 'ping'], 'ssl': cert},
                  'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'ssl': cert}},
                            'upload.localhost': {'component': 'http_file_share', 'options': {
                                'http_host': 'localhost', 'http_file_share_backend': 'local', 'http_file_share_base_url': f'https://localhost:{https}/file_share',
                                'http_file_share_size_limit': args.size,
                                'http_file_share_daily_quota': args.size,
                                'http_file_share_global_quota': args.size,
                                'http_file_share_expires_after': 'never'}}}}
        config_path = root/'config.json'
        config_path.write_text(json.dumps(config))
        subprocess.run([str(args.binary), 'create-user', str(config_path), 'alice', '--password-stdin'],
                       input='large-file-secret\n', text=True, check=True, capture_output=True)
        with (root/'server.log').open('w+') as log:
            server = subprocess.Popen([str(args.binary), 'serve', str(config_path), '--experimental'], stdout=log, stderr=log)
            stop = threading.Event()
            report['max_rss_bytes'] = {'server': 0, 'client': 0}
            server_status = proc_status_for_child(server.pid)
            report['rss_proc_status_paths'] = {'server': str(server_status), 'client': '/proc/self/status'}
            def sample():
                while not stop.is_set():
                    for role, status_path in [('server', server_status), ('client', Path('/proc/self/status'))]:
                        report['max_rss_bytes'][role] = max(report['max_rss_bytes'][role], rss(status_path))
                    stop.wait(.05)
            monitor = threading.Thread(target=sample, daemon=True)
            monitor.start()
            client = None
            try:
                assert server_status is not None, 'cannot resolve actual server /proc status for RSS sampling'
                for _ in range(200):
                    assert server.poll() is None, 'server exited during startup'
                    try:
                        with socket.create_connection(('127.0.0.1', port), .1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError('server startup timed out')
                client = Client(port, root/'cert.pem', 'alice', 'large-file-secret')
                client.send(f"<iq type='get' to='upload.localhost' id='large-slot'><request xmlns='{NS}' filename='large.bin' size='{args.size}' content-type='application/octet-stream'/></iq>")
                slot = client.iq('large-slot').find(f'{{{NS}}}slot')
                assert slot is not None
                put = slot.find(f'{{{NS}}}put')
                get = slot.find(f'{{{NS}}}get')
                put_url, get_url = urlsplit(put.get('url')), urlsplit(get.get('url'))
                assert put_url.scheme == get_url.scheme == 'https'
                assert put_url.hostname == get_url.hostname == 'localhost'
                headers = {h.get('name'): h.text for h in put.findall(f'{{{NS}}}header')}
                context = ssl.create_default_context(cafile=str(root/'cert.pem'))
                def connect(url):
                    return http.client.HTTPSConnection(url.hostname, url.port, context=context, timeout=120)
                def path(url):
                    return url.path + ('?' + url.query if url.query else '')
                start = last = time.monotonic()
                digest = hashlib.sha256()
                sent = 0
                conn = connect(put_url)
                try:
                    conn.putrequest('PUT', path(put_url))
                    for name, value in {**headers, 'Content-Length': str(args.size), 'Content-Type': 'application/octet-stream'}.items():
                        conn.putheader(name, value)
                    conn.endheaders()
                    while sent < args.size:
                        piece = memoryview(CHUNK)[:min(len(CHUNK), args.size - sent)]
                        conn.send(piece)
                        digest.update(piece)
                        sent += len(piece)
                        last = progress('PUT', sent, args.size, start, last)
                    response = conn.getresponse()
                    assert response.status == 201, (response.status, response.read(4096))
                    response.read()
                finally:
                    conn.close()
                report.update(put_bytes=sent, put_seconds=time.monotonic()-start, sha256=digest.hexdigest())
                # A real complete on-disk file, including allocated blocks, is required.
                stored = list((root/'data').glob('*/http_file_share/*.bin'))
                assert len(stored) == 1, stored
                stat = stored[0].stat()
                assert stat.st_size == args.size
                assert stat.st_blocks * 512 >= args.size, 'file unexpectedly sparse'
                report['stored_bytes'] = stat.st_size
                report['allocated_bytes'] = stat.st_blocks * 512
                report['free_disk_after_put_bytes'] = shutil.disk_usage(root).free
                conn = connect(get_url)
                try:
                    conn.request('HEAD', path(get_url))
                    response = conn.getresponse()
                    assert response.status == 200 and int(response.getheader('Content-Length')) == args.size
                    assert response.read() == b''
                finally:
                    conn.close()
                report['head_status'] = 200
                start = last = time.monotonic()
                received, reads = 0, 0
                downloaded = hashlib.sha256()
                conn = connect(get_url)
                try:
                    conn.request('GET', path(get_url))
                    response = conn.getresponse()
                    assert response.status == 200 and int(response.getheader('Content-Length')) == args.size
                    while True:
                        piece = response.read(len(CHUNK))
                        reads += 1
                        if not piece:
                            break
                        downloaded.update(piece)
                        received += len(piece)
                        last = progress('GET', received, args.size, start, last)
                    assert received == args.size and downloaded.digest() == digest.digest()
                finally:
                    conn.close()
                report.update(get_bytes=received, get_read_calls=reads, get_seconds=time.monotonic()-start,
                              get_sha256=downloaded.hexdigest())
                # Exercise a range crossing 4 GiB when the selected size permits it.
                offset = min(2**32 - 7, args.size - 32)
                conn = connect(get_url)
                try:
                    conn.request('GET', path(get_url), headers={'Range': f'bytes={offset}-{offset+31}'})
                    response = conn.getresponse()
                    assert response.status == 206
                    assert response.getheader('Content-Range') == f'bytes {offset}-{offset+31}/{args.size}'
                    assert response.read(33) == bytes((offset+i) % 256 for i in range(32))
                finally:
                    conn.close()
                report.update(range_status=206, range_offset=offset)
                conn = connect(put_url)
                try:
                    # No second large body: single-use check must reject at headers.
                    conn.putrequest('PUT', path(put_url))
                    for name, value in {**headers, 'Content-Length': str(args.size)}.items():
                        conn.putheader(name, value)
                    conn.endheaders()
                    response = conn.getresponse()
                    assert response.status == 409, response.status
                    response.read()
                finally:
                    conn.close()
                report['reuse_status'] = 409
                client.send(f"<iq type='get' to='upload.localhost' id='over-quota'><request xmlns='{NS}' filename='extra.bin' size='1'/></iq>")
                rejected = client.iq('over-quota', error=True)
                assert rejected.find('.//{urn:ietf:params:xml:ns:xmpp-stanzas}not-acceptable') is not None, ET.tostring(rejected)
                report['over_quota_condition'] = 'not-acceptable'
                assert 0 < report['max_rss_bytes']['client'] < 256 * 2**20, report['max_rss_bytes']
                assert 0 < report['max_rss_bytes']['server'] < 512 * 2**20, report['max_rss_bytes']
                report['status'] = 'passed'
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read()[-20000:], flush=True)
                raise
            finally:
                if client:
                    client.close()
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
                stop.set()
                monitor.join(timeout=2)
    report['temporary_files_cleaned'] = not root.exists()
    report['free_disk_after_cleanup_bytes'] = shutil.disk_usage(args.temp_dir or tempfile.gettempdir()).free


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=BIN)
    parser.add_argument('--size', type=int, default=10 * 2**30, help='actual network bytes; default 10 GiB')
    parser.add_argument('--report', type=Path, default=Path('/tmp/xmpp078-large.json'))
    parser.add_argument('--temp-dir', type=Path)
    args = parser.parse_args()
    assert args.size >= 32
    args.binary = args.binary.resolve()
    report = {'status': 'failed', 'requested_bytes': args.size, 'python_chunk_bytes': len(CHUNK),
              'transport': 'verified TLS HTTPS', 'storage': 'local streaming file', 'rss_sample_interval_seconds': .05}
    started = time.monotonic()
    try:
        run(args, report)
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['total_seconds'] = time.monotonic() - started
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
