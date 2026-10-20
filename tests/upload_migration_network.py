#!/usr/bin/env python3
"""Offline upload-migrate regression using the independent signed S3 fixture.

Usage: python3 tests/upload_migration_network.py target/release/rust-xmpp
Exercises real XMPP slots and HTTP bodies; no cloud service or large disk is needed.
The fixture validates SigV4 independently (see upload_s3_network.py).
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit

from _wire_client import Client
from upload_s3_network import (ACCESS, PART, REGION, SECRET, TOKEN, Store,
                               free_port, request, slot, start, stop)

HOST = 'upload.localhost'


class MigrationStore(Store):
    """Fail a chosen completion after earlier objects have really been copied."""
    def __init__(self):
        super().__init__()
        self.completions = 0
        self.fail_completion = None

    def verify(self, handler, payload):
        super().verify(handler, payload)
        query = parse_qs(urlsplit(handler.path).query, keep_blank_values=True)
        if handler.command == 'POST' and 'uploadId' in query:
            self.completions += 1
            if self.completions == self.fail_completion:
                self.fail = 'complete-error'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked(command, success=True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    assert (result.returncode == 0) == success, (command, result.returncode, output)
    assert all(value not in output for value in (ACCESS, SECRET, TOKEN)), 'credentials leaked by CLI'
    return output


def migrate(binary, old, new, execute=False, success=True):
    command = [binary, 'upload-migrate', str(old), str(new), '--component', HOST]
    if execute:
        command.append('--execute')
    return checked(command, success)


def source_files(directory):
    return {str(path.relative_to(directory)): sha(path.read_bytes())
            for path in directory.rglob('*.bin')}


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-upload-migration-') as directory, \
            MigrationStore() as first, MigrationStore() as second:
        root = Path(directory)
        stores = (first, second)
        workers = [threading.Thread(target=store.serve_forever, daemon=True) for store in stores]
        for worker in workers:
            worker.start()
        checked(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                 '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'])
        c2s, http_port = free_port(), free_port()
        while c2s == http_port:
            http_port = free_port()
        cert = {'key': str(root / 'key.pem'), 'certificate': str(root / 'cert.pem')}
        options = {'http_host': '127.0.0.1', 'http_file_share_backend': 'local',
                   'http_file_share_base_url': f'http://127.0.0.1:{http_port}/files',
                   'http_paths': {'file_share': '/files'},
                   'http_file_share_size_limit': PART + 123,
                   'http_file_share_daily_quota': PART * 8,
                   'http_file_share_global_quota': PART * 8,
                   'http_file_share_expires_after': False}
        base = {'global': {'data_path': str(root / 'data'), 'interfaces': ['127.0.0.1'],
                           'c2s_ports': [c2s], 's2s_ports': [], 'http_ports': [http_port],
                           'https_ports': [], 'modules_enabled': ['tls', 'saslauth', 'ping', 'disco']},
                'hosts': {'localhost': {'options': {'authentication': 'internal_hashed',
                                                   'password_hash': 'SHA-256', 'ssl': cert}},
                          HOST: {'component': 'http_file_share', 'options': options}}}
        configs = []
        for name, store in [('local', None), ('s3-first', first), ('s3-second', second)]:
            config = copy.deepcopy(base)
            if store:
                component = config['hosts'][HOST]['options']
                component['http_file_share_backend'] = 's3'
                component['http_file_share_s3'] = {
                    'endpoint': f'http://127.0.0.1:{store.server_address[1]}/api',
                    'bucket': 'fixture-bucket', 'region': REGION, 'access_key': ACCESS,
                    'secret_key': SECRET, 'session_token': TOKEN, 'key_prefix': 'space +'}
            path = root / f'{name}.json'
            path.write_text(json.dumps(config))
            configs.append(path)
        local, remote_a, remote_b = configs
        result = subprocess.run([binary, 'create-user', str(local), 'alice', '--password-stdin'],
                                input='secret\n', text=True, capture_output=True, timeout=30)
        assert result.returncode == 0, result.stderr
        component_path = root / 'data' / 'upload%2elocalhost'
        identity_path = component_path / 'rust_upload_backend.json'
        metadata_path = component_path / 'rust_uploads.json'
        archive_path = component_path / 'uploads.list'
        process = client = None
        uploads = []
        with (root / 'server.log').open('w+') as log:
            try:
                process = start(binary, local, c2s, log)
                client = Client(c2s, root / 'cert.pem', 'alice', 'secret')
                for index, payload in enumerate((b'A' * PART + b'B' * 123, b'migration\x00hash\xff', b'')):
                    url, headers = slot(client, HOST, len(payload), f'migrate-{index}')
                    assert request(url, 'PUT', payload, headers)[0] == 201
                    status, head, body = request(url, 'HEAD')
                    assert status == 200 and not body
                    head = {key.lower(): value for key, value in head.items()}
                    uploads.append((url, headers, payload, head['etag']))
                # Both dry-run and execute need the same exclusive data lock.
                migrate(binary, local, remote_a, success=False)
                migrate(binary, local, remote_a, execute=True, success=False)
                assert not first.events, 'live-server lock denial reached S3'
                client.close(); client = None
                stop(process); process = None
                original_files = source_files(component_path / 'http_file_share')
                assert len(original_files) == len(uploads)
                original_records = json.loads(metadata_path.read_text())
                original_archive = archive_path.read_bytes()

                def verify_serving(config, preserve_metadata=True):
                    nonlocal process
                    process = start(binary, config, c2s, log)
                    for url, headers, payload, etag in uploads:
                        status, _, data = request(url)
                        assert status == 200 and sha(data) == sha(payload), 'original URL body/hash changed'
                        status, head, body = request(url, 'HEAD')
                        head = {key.lower(): value for key, value in head.items()}
                        assert status == 200 and body == b''
                        assert int(head['content-length']) == len(payload) and head['etag'] == etag
                        assert request(url, headers={'If-None-Match': etag})[0] == 304
                        assert request(url, 'PUT', payload, headers)[0] == 409, 'original JWT became reusable'
                    stop(process); process = None
                    if preserve_metadata:
                        records = json.loads(metadata_path.read_text())
                        stable = lambda rows: {key: {field: value for field, value in record.items() if field != 'xml'}
                                               for key, record in rows.items()}
                        assert stable(records) == stable(original_records), 'slot/JWT metadata changed'

                # Invalid destination configuration must not mutate source state.
                invalid = json.loads(remote_a.read_text())
                del invalid['hosts'][HOST]['options']['http_file_share_s3']['bucket']
                bad = root / 'invalid.json'
                bad.write_text(json.dumps(invalid))
                identity = identity_path.read_bytes()
                migrate(binary, local, bad, execute=True, success=False)
                assert identity_path.read_bytes() == identity and not first.objects
                assert source_files(component_path / 'http_file_share') == original_files

                # Default is a plan only: no writes, no identity/metadata cutover.
                migrate(binary, local, remote_a)
                assert not first.objects and not first.uploads
                assert not any(stage in ('init', 'part', 'complete', 'abort', 'delete')
                               for stage, _, _ in first.events), 'dry-run wrote to destination'
                assert identity_path.read_bytes() == identity
                assert json.loads(metadata_path.read_text()) == original_records

                # One object is durable before a later copy fails. Neither the
                # failed command nor a server restart may cut over early.
                first.fail_completion = first.completions + 2
                migrate(binary, local, remote_a, execute=True, success=False)
                assert first.objects, 'failure injection did not leave a resumable copied object'
                assert identity_path.read_bytes() == identity, 'incomplete migration changed active backend'
                assert json.loads(metadata_path.read_text()) == original_records
                assert source_files(component_path / 'http_file_share') == original_files
                # A pending journal fences both configurations until resume.
                for blocked in (local, remote_a):
                    rejected = subprocess.Popen([binary, 'serve', str(blocked), '--experimental'],
                                                stdout=log, stderr=log)
                    try:
                        assert rejected.wait(timeout=15) != 0, 'pending migration started serving'
                    finally:
                        if rejected.poll() is None:
                            rejected.kill(); rejected.wait(timeout=10)
                first.fail_completion = None
                completed_before_resume = first.completions
                migration_cache, migration_archive = metadata_path.read_bytes(), archive_path.read_bytes()
                migrate(binary, local, remote_a, execute=True)
                assert metadata_path.read_bytes() == migration_cache and archive_path.read_bytes() == migration_archive
                assert first.completions - completed_before_resume < len(uploads), 'resume recopied verified objects'
                assert source_files(component_path / 'http_file_share') == original_files
                verify_serving(remote_a)
                assert sorted(sha(data) for data in first.objects.values()) == sorted(sha(row[2]) for row in uploads)

                # S3 -> S3 and S3 -> local preserve remote source objects, even
                # though final local files already exist from the first backend.
                first_objects = dict(first.objects)
                for old, new, destination in ((remote_a, remote_b, second), (remote_b, local, None)):
                    second_objects = dict(second.objects)
                    before = identity_path.read_bytes()
                    destination_objects = dict(destination.objects) if destination else None
                    migrate(binary, old, new)
                    assert identity_path.read_bytes() == before
                    if destination:
                        assert destination.objects == destination_objects
                    migration_cache, migration_archive = metadata_path.read_bytes(), archive_path.read_bytes()
                    migrate(binary, old, new, execute=True)
                    assert metadata_path.read_bytes() == migration_cache and archive_path.read_bytes() == migration_archive
                    verify_serving(new)
                    assert first.objects == first_objects, 'S3 source objects were deleted/changed'
                    if destination is None:
                        assert second.objects == second_objects, 'second S3 source objects were deleted/changed'
                assert sorted(sha(data) for data in second.objects.values()) == sorted(sha(row[2]) for row in uploads)
                assert source_files(component_path / 'http_file_share') == original_files
                # A native final local file is authoritative even when its Rust
                # cache completion flag is false. Unfinished multipart intent
                # still rejects the operation without modifying the backend.
                native = copy.deepcopy(original_records)
                native_id = next(iter(native))
                native[native_id]['multipart_intent'] = True
                metadata_path.write_text(json.dumps(native))
                before = identity_path.read_bytes()
                migrate(binary, local, remote_a, execute=True, success=False)
                assert identity_path.read_bytes() == before
                native[native_id] = copy.deepcopy(original_records[native_id])
                native[native_id]['complete'] = False
                metadata_path.write_text(json.dumps(native))
                native_bytes = metadata_path.read_bytes()
                native_archive = archive_path.read_bytes()
                migrate(binary, local, remote_a, execute=True)
                assert metadata_path.read_bytes() == native_bytes, 'migration rewrote native completion cache'
                assert archive_path.read_bytes() == native_archive
                verify_serving(remote_a, preserve_metadata=False)
                assert all(not store.errors for store in stores), [store.errors for store in stores]
                print('PASS upload migration: local -> S3 -> S3 -> local, hashes, original URLs/JWT/HEAD, lock, dry-run, fail-closed resume')
            except BaseException:
                log.flush(); log.seek(0)
                output = log.read()
                for credential in (ACCESS, SECRET, TOKEN):
                    output = output.replace(credential, '[REDACTED]')
                print('SERVER LOG:\n' + output)
                print('FIXTURE ERRORS:', [store.errors for store in stores])
                raise
            finally:
                if client is not None:
                    client.close()
                if process is not None:
                    stop(process)
                for store in stores:
                    store.shutdown()
                for worker in workers:
                    worker.join(timeout=5)


if __name__ == '__main__':
    run(str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release/rust-xmpp').resolve()))
