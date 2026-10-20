#!/usr/bin/env python3
"""Real XMPP/HTTP upload integration against an independent S3 protocol fixture.

Usage: python3 tests/upload_s3_network.py target/release/rust-xmpp
No external service or credentials are used. This validates the S3 HTTP contract
and independently recomputes SigV4; it is not an AWS or MinIO qualification test.
"""
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, quote, unquote, urlsplit
import xml.etree.ElementTree as ET

from _wire_client import Client

NS = 'urn:xmpp:http:upload:0'
ACCESS = 'fixture-access-not-production'
SECRET = 'fixture-secret-not-production'
TOKEN = 'fixture-session-not-production'
REGION = 'fixture-region-1'
PART = 8 * 1024 * 1024


def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Store(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.objects = {}
        self.uploads = {}
        self.events = []
        self.errors = []
        self.fail = None
        self.lock = threading.Lock()

    def verify(self, handler, payload):
        authorization = handler.headers['Authorization']
        algorithm, fields = authorization.split(' ', 1)
        assert algorithm == 'AWS4-HMAC-SHA256', 'wrong signature algorithm'
        fields = dict(field.strip().split('=', 1) for field in fields.split(','))
        credential = fields['Credential'].split('/')
        assert credential[0] == ACCESS and credential[2:] == [REGION, 's3', 'aws4_request'], 'wrong credential scope'
        date = handler.headers['x-amz-date']
        assert credential[1] == date[:8], 'date mismatch'
        assert handler.headers['x-amz-security-token'] == TOKEN, 'session token missing'
        payload_hash = digest(payload)
        assert handler.headers['x-amz-content-sha256'] == payload_hash, 'payload checksum mismatch'
        names = fields['SignedHeaders'].split(';')
        assert names == sorted(names), 'signed headers not sorted'
        assert {'host', 'x-amz-date', 'x-amz-content-sha256', 'x-amz-security-token'} <= set(names), 'unsigned required header'
        headers = ''.join(f'{name}:{" ".join(handler.headers[name].split())}\n' for name in names)
        parsed = urlsplit(handler.path)
        # AWS URI encoding preserves slash separators, but escapes all other
        # non-unreserved bytes. Keys here include spaces and plus signs.
        pairs = []
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            pairs.extend((quote(key, safe='-_.~'), quote(value, safe='-_.~')) for value in values)
        query = '&'.join(f'{key}={value}' for key, value in sorted(pairs))
        canonical = '\n'.join((handler.command, parsed.path, query, headers, ';'.join(names), payload_hash))
        scope = '/'.join(credential[1:])
        string_to_sign = '\n'.join((algorithm, date, scope, digest(canonical.encode())))
        signing_key = ('AWS4' + SECRET).encode()
        for value in (credential[1], REGION, 's3', 'aws4_request'):
            signing_key = hmac.new(signing_key, value.encode(), hashlib.sha256).digest()
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(signature, fields['Signature']), 'invalid SigV4 signature'


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def reply(self, status, payload=b'', **headers):
        self.send_response(status)
        self.send_header('Content-Length', str(len(payload)))
        for name, value in headers.items():
            self.send_header(name.replace('_', '-'), value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(payload)

    def do_GET(self): self.dispatch()
    def do_HEAD(self): self.dispatch()
    def do_POST(self): self.dispatch()
    def do_PUT(self): self.dispatch()
    def do_DELETE(self): self.dispatch()

    def dispatch(self):
        try:
            payload = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            self.server.verify(self, payload)
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query, keep_blank_values=True)
            if self.command == 'GET' and 'uploads' in query:
                assert parsed.path == '/api/fixture-bucket', 'list must address bucket root'
                assert query.get('encoding-type') == ['url'], 'list must encode arbitrary XML keys'
                prefix = query.get('prefix', [''])[0]
                with self.server.lock:
                    self.server.events.append(('list', prefix, len(payload)))
                    entries = sorted((unquote(upload['key'].removeprefix('/api/fixture-bucket/')), uid)
                                     for uid, upload in self.server.uploads.items()
                                     if unquote(upload['key'].removeprefix('/api/fixture-bucket/')).startswith(prefix))
                    marker = (query.get('key-marker', [''])[0], query.get('upload-id-marker', [''])[0])
                    entries = [entry for entry in entries if entry > marker]
                    # Small pages force both marker fields to be exercised.
                    page, remaining = entries[:2], entries[2:]
                    root = ET.Element('ListMultipartUploadsResult')
                    for key, uid in page:
                        upload = ET.SubElement(root, 'Upload')
                        ET.SubElement(upload, 'Key').text = quote(key, safe='-_.~')
                        ET.SubElement(upload, 'UploadId').text = uid
                    ET.SubElement(root, 'IsTruncated').text = 'true' if remaining else 'false'
                    if remaining:
                        ET.SubElement(root, 'NextKeyMarker').text = quote(page[-1][0], safe='-_.~')
                        ET.SubElement(root, 'NextUploadIdMarker').text = page[-1][1]
                    return self.reply(200, ET.tostring(root))
            assert parsed.path.startswith('/api/fixture-bucket/space%20%2B/'), 'bucket/prefix escaping mismatch'

            key = parsed.path
            with self.server.lock:
                stage = ('init' if 'uploads' in query else 'part' if self.command == 'PUT'
                         else 'complete' if self.command == 'POST' else 'abort' if 'uploadId' in query
                         else self.command.lower())
                self.server.events.append((stage, key, len(payload)))
                if stage == 'complete':
                    assert self.headers.get('If-None-Match') == '*', 'completion must prevent overwrite'
                    if self.server.fail == 'complete-malformed':
                        self.server.fail = None
                        return self.reply(200, b'<unterminated')
                if stage == 'complete' and self.server.fail == 'complete-error':
                    self.server.fail = None
                    return self.reply(200, b'<Error><Code>InternalError</Code></Error>')
                if self.server.fail == stage:
                    self.server.fail = None
                    return self.reply(503, b'<Error><Code>FixtureUnavailable</Code></Error>')
                if stage == 'init':
                    uid = f'upload+{len(self.server.events)}/='
                    self.server.uploads[uid] = {'key': key, 'parts': {}}
                    return self.reply(200, f'<InitiateMultipartUploadResult><UploadId>{uid}</UploadId></InitiateMultipartUploadResult>'.encode())
                if stage == 'part':
                    upload = self.server.uploads[query['uploadId'][0]]
                    number = int(query['partNumber'][0])
                    etag = '"' + hashlib.md5(payload).hexdigest() + '"'
                    upload['parts'][number] = (payload, etag)
                    return self.reply(200, ETag=etag)
                if stage == 'complete':
                    upload = self.server.uploads[query['uploadId'][0]]
                    root = ET.fromstring(payload)
                    parts = list(root)
                    result = []
                    for index, node in enumerate(parts, 1):
                        number = int(node.findtext('PartNumber'))
                        assert number == index, 'noncontiguous multipart completion'
                        data, etag = upload['parts'][number]
                        assert node.findtext('ETag') == etag, 'ETag mismatch'
                        if index < len(parts):
                            assert len(data) >= 5 * 1024 * 1024, 'nonfinal S3 part below 5 MiB'
                        result.append(data)
                    self.server.objects[key] = b''.join(result)
                    del self.server.uploads[query['uploadId'][0]]
                    if self.server.fail == 'complete-ambiguous':
                        self.server.fail = None
                        # The remote object exists, but the completion response
                        # gives the proxy no trustworthy success confirmation.
                        return self.reply(200, b'<Error><Code>InternalError</Code></Error>')
                    return self.reply(200, b'<CompleteMultipartUploadResult><ETag>"complete"</ETag></CompleteMultipartUploadResult>')
                if stage == 'abort':
                    removed = self.server.uploads.pop(query['uploadId'][0], None)
                    return self.reply(204 if removed is not None else 404)
                if self.command == 'DELETE':
                    self.server.objects.pop(key, None)
                    return self.reply(204)
                data = self.server.objects.get(key)
                if data is None:
                    return self.reply(404)
                if self.headers.get('Range'):
                    start, end = self.headers['Range'].removeprefix('bytes=').split('-')
                    start, end = int(start), int(end)
                    return self.reply(206, data[start:end + 1], Content_Range=f'bytes {start}-{end}/{len(data)}')
                return self.reply(200, data, Content_Type='application/octet-stream')
        except (BrokenPipeError, ConnectionResetError):
            # The crash recovery case deliberately kills the HTTP peer.
            return
        except BaseException as error:
            self.server.errors.append(f'{type(error).__name__}: {error}')
            self.reply(500, b'fixture validation failed')


def request(url, method='GET', body=None, headers=None):
    parsed = urlsplit(url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=20)
    try:
        try:
            connection.request(method, parsed.path, body=body, headers=headers or {})
        except (BrokenPipeError, ConnectionResetError):
            # Authorization, replay, and backend preflight errors may produce
            # a response before the large request body finishes transmitting.
            pass
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def slot(client, host, size, ident, error=False):
    client.send(f"<iq type='get' id='{ident}' to='{host}'><request xmlns='{NS}' filename='test +.bin' size='{size}' content-type='application/octet-stream'/></iq>")
    response = client.iq(ident, error=error)
    if error:
        return response
    node = response.find(f'{{{NS}}}slot')
    assert node is not None, ET.tostring(response)
    put = node.find(f'{{{NS}}}put')
    headers = {header.get('name'): header.text for header in put}
    return put.get('url'), headers


def start(binary, config, port, log):
    process = subprocess.Popen([binary, 'serve', str(config), '--experimental'], stdout=log, stderr=log)
    for _ in range(100):
        assert process.poll() is None, 'server exited during startup'
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return process
        except OSError:
            time.sleep(.05)
    raise AssertionError('server startup timeout')


def stop(process):
    process.terminate()
    try:
        assert process.wait(timeout=10) == 0, 'server shutdown failed'
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise


def wait_for(predicate, message):
    for _ in range(100):
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError(message)


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-s3-network-') as directory, Store() as store:
        root = Path(directory)
        worker = threading.Thread(target=store.serve_forever, daemon=True)
        worker.start()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'), '-subj',
                        '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        c2s, http_port = free_port(), free_port()
        size = PART + 123
        options = {'http_host': '127.0.0.1', 'http_file_share_backend': 's3', 'http_file_share_s3': {
            'endpoint': f'http://127.0.0.1:{store.server_address[1]}/api',
            'bucket': 'fixture-bucket', 'region': REGION, 'access_key': ACCESS,
            'secret_key': SECRET, 'session_token': TOKEN, 'key_prefix': 'space +'},
            'http_file_share_base_url': f'http://127.0.0.1:{http_port}/s3',
            'http_paths': {'file_share': '/s3'}, 'http_file_share_size_limit': size,
            'http_file_share_daily_quota': size * 7, 'http_file_share_global_quota': size * 7,
            'http_file_share_expires_after': False}
        config_data = {'global': {'data_path': str(root / 'data'), 'interfaces': ['127.0.0.1'],
            'c2s_ports': [c2s], 's2s_ports': [], 'http_ports': [http_port], 'https_ports': [],
            'modules_enabled': ['tls', 'saslauth', 'ping', 'disco']}, 'hosts': {
            'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256',
                'ssl': {'key': str(root / 'key.pem'), 'certificate': str(root / 'cert.pem')}}},
            's3.localhost': {'component': 'http_file_share', 'options': options},
            'local.localhost': {'component': 'http_file_share', 'options': {'http_host': '127.0.0.1',
                'http_file_share_base_url': f'http://127.0.0.1:{http_port}/local',
                'http_paths': {'file_share': '/local'}}}}}
        config = root / 'config.json'
        config.write_text(json.dumps(config_data))
        subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'],
                       input='secret\n', text=True, check=True, capture_output=True)
        process = None
        client = None
        with (root / 'server.log').open('w+') as log:
            try:
                process = start(binary, config, c2s, log)
                client = Client(c2s, root / 'cert.pem', 'alice', 'secret')
                data = b'A' * PART + b'B' * 123
                url, headers = slot(client, 's3.localhost', size, 'good')
                # Send one part and fence on the fixture before sending the
                # tail: the proxy must make progress without buffering the file.
                parsed = urlsplit(url)
                connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=20)
                connection.putrequest('PUT', parsed.path)
                for name, value in {**headers, 'Content-Length': str(size)}.items():
                    connection.putheader(name, value)
                connection.endheaders()
                connection.send(data[:PART])
                wait_for(lambda: any(stage == 'part' for stage, _, _ in store.events), 'upload buffered the entire client body')
                connection.send(data[PART:])
                response = connection.getresponse()
                assert response.status == 201, (response.status, response.read())
                response.read()
                connection.close()
                assert [length for stage, _, length in store.events if stage == 'part'] == [PART, 123]
                assert request(url)[2] == data
                status, head, body = request(url, 'HEAD')
                assert status == 200 and int(head.get('content-length', head.get('Content-Length', -1))) == size and body == b''
                etag = head.get('etag', head.get('ETag'))
                assert etag, 'missing ETag'
                count = len(store.events)
                assert request(url, headers={'If-None-Match': etag})[0] == 304
                assert request(url, headers={'If-None-Match': 'W/' + etag})[0] == 304
                assert len(store.events) == count, 'conditional hit reached S3'
                assert request(url, headers={'Range': 'bytes=1-2', 'If-Range': etag})[2] == b'AA'
                status, _, body = request(url, headers={'Range': 'bytes=1-2', 'If-Range': '"stale"'})
                assert status == 200 and body == data
                status, range_headers, body = request(url, headers={'Range': f'bytes={PART - 2}-{PART + 2}'})
                assert status == 206 and body == b'AABBB'
                assert range_headers.get('content-range', range_headers.get('Content-Range')) == f'bytes {PART - 2}-{PART + 2}/{size}'
                assert request(url, headers={'Range': 'bytes=-5'})[2] == b'BBBBB'
                assert request(url, headers={'Range': f'bytes={PART}-'})[2] == b'B' * 123
                count = len(store.events)
                assert request(url, headers={'Range': f'bytes={size}-'})[0] == 416
                assert len(store.events) == count, 'invalid range reached S3'
                for stage, method in (('get', 'GET'), ('head', 'HEAD')):
                    store.fail = stage
                    assert request(url, method)[0] >= 500
                    assert request(url)[2] == data
                assert request(url, 'PUT', data, headers)[0] == 409, 'slot reused'
                local_url, local_headers = slot(client, 'local.localhost', 4, 'local')
                assert request(local_url, 'PUT', b'here', local_headers)[0] == 201
                assert request(local_url)[2] == b'here'
                empty_url, empty_headers = slot(client, 's3.localhost', 0, 'empty')
                assert request(empty_url, 'PUT', b'', empty_headers)[0] == 201
                assert request(empty_url)[2] == b''
                for stage in ('init', 'part', 'complete', 'complete-error'):
                    bad_url, bad_headers = slot(client, 's3.localhost', size, 'fail-' + stage)
                    store.fail = stage
                    status, _, response = request(bad_url, 'PUT', data, bad_headers)
                    assert status >= 500, (stage, status)
                    assert SECRET.encode() not in response and TOKEN.encode() not in response
                    assert request(bad_url)[0] in (404, 410), 'failed upload became readable'
                    wait_for(lambda: not store.uploads, 'failed multipart was not aborted')
                    assert request(local_url)[2] == b'here', 'S3 failure broke local backend'
                    # Failed slots remain retryable and only commit on success.
                    def retry_failed_slot():
                        # Abort reconciliation briefly holds the same slot claim.
                        retry_status = request(bad_url, 'PUT', data, bad_headers)[0]
                        assert retry_status in (201, 409), (stage, retry_status)
                        return retry_status == 201
                    wait_for(retry_failed_slot, 'failed slot remained unavailable: ' + stage)
                ambiguous_url, ambiguous_headers = slot(client, 's3.localhost', size, 'ambiguous-complete')
                store.fail = 'complete-ambiguous'
                status, _, _ = request(ambiguous_url, 'PUT', data, ambiguous_headers)
                assert status >= 500, 'ambiguous completion reported success'
                wait_for(lambda: request(ambiguous_url)[0] == 200, 'committed object was not reconciled after ambiguous completion')
                assert request(ambiguous_url)[2] == data
                assert request(ambiguous_url, 'PUT', data, ambiguous_headers)[0] == 409, 'ambiguous completion allowed object overwrite'
                assert not store.uploads
                abort_url, abort_headers = slot(client, 's3.localhost', size, 'disconnect')
                parsed = urlsplit(abort_url)
                with socket.create_connection((parsed.hostname, parsed.port), timeout=10) as stream:
                    head = f'PUT {parsed.path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nContent-Length: {size}\r\n'
                    head += ''.join(f'{key}: {value}\r\n' for key, value in abort_headers.items()) + '\r\n'
                    stream.sendall(head.encode() + data[:PART])
                    wait_for(lambda: any(stage == 'part' and key.endswith('/' + parsed.path.split('/')[-2]) for stage, key, _ in store.events), 'disconnect fixture did not receive first part')
                wait_for(lambda: any(stage == 'abort' and key.endswith('/' + parsed.path.split('/')[-2]) for stage, key, _ in store.events), 'disconnected multipart was not aborted')
                wait_for(lambda: not store.uploads, 'disconnected multipart leaked')
                slot(client, 's3.localhost', size, 'quota', error=True)
                client.close(); client = None
                stop(process); process = None
                options['http_file_share_daily_quota'] = size * 12
                options['http_file_share_global_quota'] = size * 12
                config.write_text(json.dumps(config_data))
                process = start(binary, config, c2s, log)
                assert request(url)[2] == data, 'S3 metadata did not survive restart'
                assert request(url, 'PUT', data, headers)[0] == 409, 'single-use state lost on restart'
                client = Client(c2s, root / 'cert.pem', 'alice', 'secret')
                crash_url, crash_headers = slot(client, 's3.localhost', size, 'crash')
                parsed = urlsplit(crash_url)
                crash_id = parsed.path.split('/')[-2]
                stream = socket.create_connection((parsed.hostname, parsed.port), timeout=10)
                head = f'PUT {parsed.path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nContent-Length: {size}\r\n'
                head += ''.join(f'{key}: {value}\r\n' for key, value in crash_headers.items()) + '\r\n'
                stream.sendall(head.encode() + data[:PART])
                wait_for(lambda: any(stage == 'part' and key.endswith('/' + crash_id) for stage, key, _ in store.events), 'crash fixture did not receive first part')
                metadata = root / 'data' / 's3%2elocalhost' / 'rust_uploads.json'
                cached = json.loads(metadata.read_text())
                assert cached[crash_id].get('upload_id'), 'multipart identifier was not durable before part upload'
                process.kill(); process.wait(timeout=10); process = None
                stream.close()
                client.close(); client = None
                assert store.uploads, 'crash did not leave a remote multipart to recover'
                # Model the earlier crash window: initiation reached S3, but its
                # UploadId never reached the local journal. Include multiple
                # owned uploads plus a foreign prefix match across list pages.
                cached = json.loads(metadata.read_text())
                assert cached[crash_id].get('multipart_intent'), 'intent not durable before initiation'
                cached[crash_id]['upload_id'] = None
                metadata.write_text(json.dumps(cached))
                owned_key = '/api/fixture-bucket/space%20%2B/' + crash_id
                foreign_uid = 'foreign-prefix-match'
                with store.lock:
                    for uid in ('orphan-a', 'orphan-b', 'orphan-c'):
                        store.uploads[uid] = {'key': owned_key, 'parts': {}}
                    store.uploads[foreign_uid] = {'key': owned_key + '-foreign', 'parts': {}}
                process = start(binary, config, c2s, log)
                wait_for(lambda: set(store.uploads) == {foreign_uid}, 'startup did not abort only exact owned-key multiparts')
                assert not any(stage == 'abort' and key == owned_key + '-foreign' for stage, key, _ in store.events), 'recovery aborted foreign prefix match'
                with store.lock:
                    del store.uploads[foreign_uid]
                wait_for(lambda: not json.loads(metadata.read_text())[crash_id].get('upload_id'), 'startup retained abandoned multipart identifier')
                assert request(url)[2] == data
                stop(process); process = None
                # Model a remote completion followed by a crash before the
                # local completion marker was persisted. Age exceeds the stale
                # reservation timeout but remains within retention.
                good_id = urlsplit(url).path.split('/')[-2]
                cached = json.loads(metadata.read_text())
                old = int(time.time()) - 700
                cached[good_id].update(complete=False, upload_id='completed-before-crash', created=old)
                metadata.write_text(json.dumps(cached))
                archive = metadata.parent / 'uploads.list'
                lines = archive.read_text().splitlines(keepends=True)
                changed = False
                for index, line in enumerate(lines):
                    if good_id in line:
                        line, count = re.subn(r'(\["when"\]=)[0-9.]+', lambda match: match[1] + str(old) + '.0', line)
                        assert count == 1, 'failed to age authoritative upload timestamp'
                        lines[index] = line
                        changed = True
                assert changed
                archive.write_text(''.join(lines))
                archive.with_suffix('.lidx').unlink(missing_ok=True)
                options['http_file_share_expires_after'] = 3600
                config.write_text(json.dumps(config_data))
                process = start(binary, config, c2s, log)
                wait_for(lambda: json.loads(metadata.read_text()).get(good_id, {}).get('complete'), 'startup did not reconcile committed object before stale pruning')
                assert request(url)[2] == data, 'committed object was deleted as an old reservation'
                assert not json.loads(metadata.read_text())[good_id].get('upload_id')
                # Unknown completion + HEAD404 quarantines only its own slot.
                client = Client(c2s, root / 'cert.pem', 'alice', 'secret')
                uncertain_url, uncertain_headers = slot(client, 's3.localhost', 1, 'uncertain')
                uncertain_id = urlsplit(uncertain_url).path.split('/')[-2]
                store.fail = 'complete-malformed'
                assert request(uncertain_url, 'PUT', b'Q', uncertain_headers)[0] >= 500
                assert json.loads(metadata.read_text())[uncertain_id]['completion_attempted']
                client.close(); client = None
                stop(process); process = None
                process = start(binary, config, c2s, log)
                assert request(uncertain_url, 'PUT', b'Q', uncertain_headers)[0] == 409
                retained = json.loads(metadata.read_text())[uncertain_id]
                assert retained['completion_attempted'] and not retained['complete']
                client = Client(c2s, root / 'cert.pem', 'alice', 'secret')
                independent_url, independent_headers = slot(client, 's3.localhost', 1, 'independent')
                assert request(independent_url, 'PUT', b'I', independent_headers)[0] == 201
                # A late commit resolves through the next maintenance pass;
                # requesting another slot also triggers that same pruning pass.
                with store.lock:
                    store.objects['/api/fixture-bucket/space%20%2B/' + uncertain_id] = b'Q'
                slot(client, 's3.localhost', 1, 'trigger-reconciliation')
                wait_for(lambda: json.loads(metadata.read_text())[uncertain_id]['complete'], 'late completion was not reconciled')
                assert request(uncertain_url)[2] == b'Q'
                client.close(); client = None
                stop(process); process = None
                # Force expiry without slowing this test with a wall-clock wait.
                options['http_file_share_expires_after'] = 0
                config.write_text(json.dumps(config_data))
                process = start(binary, config, c2s, log)
                assert request(url)[0] in (404, 410)
                wait_for(lambda: not store.objects, 'expired S3 objects were not deleted')
                assert not store.errors, store.errors
                log.flush(); log.seek(0)
                output = log.read()
                assert SECRET not in output and TOKEN not in output and ACCESS not in output, 'credentials leaked to logs'
                print('PASS upload S3 protocol fixture: SigV4, multipart, abort, range, restart, expiry and backend isolation')
            except BaseException:
                log.flush(); log.seek(0)
                output = log.read()
                for credential in (SECRET, TOKEN, ACCESS):
                    output = output.replace(credential, '[REDACTED]')
                print('SERVER LOG:\n' + output)
                print('FIXTURE ERRORS:', store.errors)
                raise
            finally:
                if client is not None:
                    client.close()
                if process is not None:
                    stop(process)
                store.shutdown()
                worker.join(timeout=5)


if __name__ == '__main__':
    run(str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release/rust-xmpp').resolve()))
