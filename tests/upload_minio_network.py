#!/usr/bin/env python3
"""Opt-in genuine MinIO integration; no S3 fixture is used.

MINIO_BINARY=/path/to/minio python3 tests/upload_minio_network.py --binary target/release/rust-xmpp
Default sends an actual 10 GiB HTTPS upload through Rust into isolated MinIO,
then verifies every byte through HTTPS, multipart ETag, ranges, restart and crash
cleanup. Requires openssl, a genuine MinIO executable, and size + 512 MiB free.
--size permits a small smoke check; only sizes >5 GiB qualify the large-object test.
"""
import argparse
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote, urlsplit
import xml.etree.ElementTree as ET

from _wire_client import Client
from upload_large_network import CHUNK, free_port, proc_status_for_child, rss, progress
from upload_s3_network import slot, start, stop, wait_for

ACCESS = 'isolated-minio-test-access'
SECRET = 'isolated-minio-test-secret-not-production'
BUCKET = 'xmpp-integration'
PART = 8 * 2**20


def signed(port, method, path, query='', body=b''):
    """Small independent SigV4 administrative client, never stores object bodies."""
    date = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    scope = date[:8] + '/us-east-1/s3/aws4_request'
    payload = hashlib.sha256(body).hexdigest()
    headers = {'host': f'127.0.0.1:{port}', 'x-amz-content-sha256': payload, 'x-amz-date': date}
    names = ';'.join(sorted(headers))
    canonical = '\n'.join((method, path, query, ''.join(f'{k}:{headers[k]}\n' for k in sorted(headers)), names, payload))
    key = ('AWS4' + SECRET).encode()
    for value in (date[:8], 'us-east-1', 's3', 'aws4_request'):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    value = '\n'.join(('AWS4-HMAC-SHA256', date, scope, hashlib.sha256(canonical.encode()).hexdigest()))
    signature = hmac.new(key, value.encode(), hashlib.sha256).hexdigest()
    headers['Authorization'] = f'AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, SignedHeaders={names}, Signature={signature}'
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
    try:
        conn.request(method, path + ('?' + query if query else ''), body, headers)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def uploads(port):
    status, _, body = signed(port, 'GET', '/' + BUCKET, 'uploads=')
    assert status == 200, (status, body[:1024])
    return [n for n in ET.fromstring(body).iter() if n.tag.endswith('}Upload')]


def has_uploaded_part(port):
    for upload in uploads(port):
        values = {node.tag.rsplit('}', 1)[-1]: node.text for node in upload}
        path = '/' + BUCKET + '/' + quote(values['Key'], safe='/')
        status, _, body = signed(port, 'GET', path, 'uploadId=' + quote(values['UploadId'], safe='-_.~'))
        if status == 200 and any(node.tag.endswith('}Part') for node in ET.fromstring(body).iter()):
            return True
    return False


def run(args, report):
    try:
        version = subprocess.check_output([str(args.minio), '--version'], text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        raise RuntimeError('MinIO preflight failed before any upload: ' + error.output[-4000:]) from error
    assert 'version ' in version.lower() and 'MinIO, Inc.' in version, 'supplied executable does not identify as MinIO'
    binary_hash = hashlib.sha256()
    with args.minio.open('rb') as stream:
        for piece in iter(lambda: stream.read(2**20), b''): binary_hash.update(piece)
    rust_hash = hashlib.sha256()
    with args.binary.open('rb') as stream:
        for piece in iter(lambda: stream.read(2**20), b''): rust_hash.update(piece)
    rust_version = subprocess.check_output([str(args.binary), '--version'], text=True).strip()
    report.update(minio_version=version.strip(), minio_binary_sha256=binary_hash.hexdigest(), binary=str(args.binary), binary_version=rust_version, binary_sha256=rust_hash.hexdigest(), size=args.size, qualifies_over_5gib=args.size > 5 * 2**30)
    if args.minio_compat_patch:
        patch = args.minio_compat_patch.read_bytes()
        report['minio_test_only_compatibility_patch'] = {'sha256': hashlib.sha256(patch).hexdigest(), 'diff': patch.decode(), 'limitation': 'Modified upstream MinIO: EPERM interface enumeration uses loopback; all S3/auth/storage code remains upstream.'}
    with tempfile.TemporaryDirectory(prefix='xmpp-minio-', dir=args.temp_dir) as directory:
        root = Path(directory)
        assert shutil.disk_usage(root).free > args.size + 512 * 2**20, 'insufficient free disk'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        c2s, https, minio_port, console = [free_port() for _ in range(4)]
        cert = {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}
        options = {'http_host': 'localhost', 'http_file_share_backend': 's3', 'http_file_share_s3': {'endpoint': f'http://127.0.0.1:{minio_port}', 'bucket': BUCKET, 'region': 'us-east-1', 'access_key': ACCESS, 'secret_key': SECRET, 'key_prefix': 'integration'}, 'http_file_share_base_url': f'https://localhost:{https}/file_share', 'http_file_share_size_limit': args.size, 'http_file_share_daily_quota': args.size * 3, 'http_file_share_global_quota': args.size * 3, 'http_file_share_expires_after': False}
        config = {'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [c2s], 's2s_ports': [], 'http_ports': [], 'https_ports': [https], 'ssl': cert, 'modules_enabled': ['tls', 'saslauth', 'ping', 'disco']}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'ssl': cert}}, 'upload.localhost': {'component': 'http_file_share', 'options': options}}}
        config_path = root/'config.json'
        config_path.write_text(json.dumps(config))
        subprocess.run([str(args.binary), 'create-user', str(config_path), 'alice', '--password-stdin'], input='integration-secret\n', text=True, check=True, capture_output=True)
        minio = server = client = None
        done = threading.Event()
        report['max_rss_bytes'] = {'server': 0, 'client': 0, 'minio': 0}
        paths = {'client': Path('/proc/self/status')}
        def sample():
            while not done.wait(.05):
                for role, path in list(paths.items()):
                    report['max_rss_bytes'][role] = max(report['max_rss_bytes'][role], rss(path))
        monitor = threading.Thread(target=sample, daemon=True)
        context = ssl.create_default_context(cafile=str(root/'cert.pem'))
        def request(url, method='GET', headers=None):
            parsed = urlsplit(url)
            connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=120)
            connection.request(method, parsed.path, headers=headers or {})
            return connection, connection.getresponse()
        def check_range(url, offset):
            conn, response = request(url, headers={'Range': f'bytes={offset}-{offset+31}'})
            try:
                assert response.status == 206
                assert response.getheader('Content-Range') == f'bytes {offset}-{offset+31}/{args.size}'
                assert response.read(33) == bytes((offset+i) % 256 for i in range(32))
            finally:
                conn.close()
        with (root/'minio.log').open('w+') as minio_log, (root/'server.log').open('w+') as log:
            try:
                env = dict(os.environ, MINIO_ROOT_USER=ACCESS, MINIO_ROOT_PASSWORD=SECRET, MINIO_BROWSER='off', GOMAXPROCS='4', GOMEMLIMIT='1GiB')
                minio = subprocess.Popen([str(args.minio), 'server', str(root/'minio-data'), '--address', f'127.0.0.1:{minio_port}', '--console-address', f'127.0.0.1:{console}'], env=env, stdout=minio_log, stderr=minio_log)
                paths['minio'] = proc_status_for_child(minio.pid)
                for _ in range(200):
                    assert minio.poll() is None, 'MinIO exited at startup'
                    try:
                        status, _, _ = signed(minio_port, 'PUT', '/' + BUCKET)
                        if status in (200, 409): break
                    except OSError: pass
                    time.sleep(.05)
                else: raise AssertionError('MinIO startup timeout')
                server = start(str(args.binary), config_path, c2s, log)
                paths['server'] = proc_status_for_child(server.pid)
                assert all(paths.values()), 'cannot resolve actual child process RSS paths'
                monitor.start()
                client = Client(c2s, root/'cert.pem', 'alice', 'integration-secret')
                url, headers = slot(client, 'upload.localhost', args.size, 'real-minio')
                parsed = urlsplit(url)
                assert parsed.scheme == 'https' and parsed.hostname == 'localhost'
                conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=120)
                digest = hashlib.sha256(); sent = 0; began = last = time.monotonic()
                try:
                    conn.putrequest('PUT', parsed.path)
                    for name, value in {**headers, 'Content-Length': str(args.size)}.items(): conn.putheader(name, value)
                    conn.endheaders()
                    while sent < args.size:
                        piece = memoryview(CHUNK)[:min(len(CHUNK), args.size-sent)]
                        conn.send(piece); digest.update(piece); sent += len(piece)
                        last = progress('MINIO PUT', sent, args.size, began, last)
                    response = conn.getresponse()
                    assert response.status == 201, (response.status, response.read(4096))
                    response.read()
                finally: conn.close()
                report.update(put_bytes=sent, put_seconds=time.monotonic()-began, sha256=digest.hexdigest())
                # MinIO's own HEAD proves the object is multipart, independent of Rust metadata.
                object_id = parsed.path.split('/')[-2]
                status, remote, body = signed(minio_port, 'HEAD', '/' + BUCKET + '/integration/' + object_id)
                assert status == 200, (status, body)
                remote = {k.lower(): v for k, v in remote.items()}
                assert int(remote['content-length']) == args.size
                etag = remote['etag'].strip('"')
                assert '-' in etag and int(etag.rsplit('-', 1)[1]) == (args.size + PART - 1)//PART, etag
                allocated = sum(path.stat().st_blocks * 512 for path in (root/'minio-data').rglob('*') if path.is_file())
                assert allocated >= args.size, 'MinIO payload storage unexpectedly sparse'
                report.update(minio_etag=etag, multipart_parts=int(etag.rsplit('-', 1)[1]), minio_allocated_bytes=allocated, free_disk_after_put_bytes=shutil.disk_usage(root).free)
                conn, response = request(url, 'HEAD')
                assert response.status == 200 and int(response.getheader('Content-Length')) == args.size
                response.read(); conn.close()
                received = 0; downloaded = hashlib.sha256(); began = last = time.monotonic()
                conn, response = request(url)
                try:
                    assert response.status == 200
                    while True:
                        piece = response.read(len(CHUNK))
                        if not piece: break
                        downloaded.update(piece); received += len(piece)
                        last = progress('MINIO GET', received, args.size, began, last)
                finally: conn.close()
                assert received == args.size and downloaded.digest() == digest.digest()
                report.update(get_bytes=received, get_sha256=downloaded.hexdigest(), get_seconds=time.monotonic()-began)
                offsets = sorted(set([0, min(2**32-7, args.size-32), min(5*2**30-7, args.size-32), args.size-32]))
                for offset in offsets: check_range(url, offset)
                report['range_offsets'] = offsets
                client.close(); client = None
                stop(server); server = None
                server = start(str(args.binary), config_path, c2s, log); paths['server'] = proc_status_for_child(server.pid)
                check_range(url, args.size-32)
                report['restart_range_ok'] = True
                replay = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=30)
                try:
                    replay.putrequest('PUT', parsed.path)
                    for name, value in {**headers, 'Content-Length': str(args.size)}.items(): replay.putheader(name, value)
                    replay.endheaders()
                    response = replay.getresponse()
                    assert response.status == 409, 'single-use upload state did not survive restart'
                    response.read()
                finally: replay.close()
                report['restart_reuse_status'] = 409
                client = Client(c2s, root/'cert.pem', 'alice', 'integration-secret')
                crash_size = max(PART*2, min(args.size, PART*3))
                # The configured maximum must also permit the crash probe in small smoke mode.
                crash_size = min(crash_size, args.size)
                assert crash_size > PART, 'size must exceed 8 MiB for crash multipart test'
                crash_url, crash_headers = slot(client, 'upload.localhost', crash_size, 'crash-minio')
                crash = urlsplit(crash_url)
                conn = http.client.HTTPSConnection(crash.hostname, crash.port, context=context, timeout=30)
                conn.putrequest('PUT', crash.path)
                for name, value in {**crash_headers, 'Content-Length': str(crash_size)}.items(): conn.putheader(name, value)
                conn.endheaders()
                for _ in range(PART//len(CHUNK)): conn.send(CHUNK)
                wait_for(lambda: has_uploaded_part(minio_port), 'MinIO never stored crash multipart part')
                crash_id = crash.path.split('/')[-2]
                metadata = root/'data'/'upload%2elocalhost'/'rust_uploads.json'
                wait_for(lambda: json.loads(metadata.read_text())[crash_id].get('upload_id'), 'multipart id not durable')
                server.kill(); server.wait(timeout=10); server = None
                conn.close(); client.close(); client = None
                assert uploads(minio_port), 'no real abandoned multipart at crash'
                server = start(str(args.binary), config_path, c2s, log); paths['server'] = proc_status_for_child(server.pid)
                wait_for(lambda: not uploads(minio_port), 'startup did not abort genuine MinIO multipart')
                check_range(url, args.size-32)
                report['crash_multipart_cleanup_ok'] = True
                assert 0 < report['max_rss_bytes']['server'] < args.server_rss_mib * 2**20, report['max_rss_bytes']
                assert 0 < report['max_rss_bytes']['client'] < 256 * 2**20, report['max_rss_bytes']
                assert 0 < report['max_rss_bytes']['minio'] < args.minio_rss_mib * 2**20, report['max_rss_bytes']
                report['ok'] = True
            except BaseException:
                for name, stream in [('RUST', log), ('MINIO', minio_log)]:
                    stream.flush(); stream.seek(0)
                    output = stream.read().replace(SECRET, '[REDACTED]').replace(ACCESS, '[REDACTED]')
                    print(name + ' LOG:\n' + output[-12000:])
                raise
            finally:
                done.set()
                if monitor.is_alive(): monitor.join(timeout=2)
                if client is not None: client.close()
                if server is not None: stop(server)
                if minio is not None:
                    minio.terminate()
                    try: minio.wait(timeout=10)
                    except subprocess.TimeoutExpired: minio.kill(); minio.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/rust-xmpp'))
    parser.add_argument('--minio', type=Path, default=os.environ.get('MINIO_BINARY'))
    parser.add_argument('--minio-compat-patch', type=Path, help='record any test-only MinIO environment adapter diff in the report')
    parser.add_argument('--size', type=int, default=10 * 2**30)
    parser.add_argument('--temp-dir', type=Path)
    parser.add_argument('--server-rss-mib', type=int, default=512)
    parser.add_argument('--minio-rss-mib', type=int, default=2048)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    parser.error('--minio or MINIO_BINARY must name a genuine MinIO executable') if args.minio is None else None
    args.binary, args.minio = args.binary.resolve(), args.minio.resolve()
    assert args.size > PART and args.size >= 32
    report = {'ok': False}
    try: run(args, report)
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        result = json.dumps(report, indent=2)
        print(result, flush=True)
        if args.report: args.report.write_text(result + '\n')
