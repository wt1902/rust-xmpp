#!/usr/bin/env python3
"""Structured logging regression using isolated accounts and real STARTTLS.

Usage: python3 tests/logging_network.py [BINARY]
Only a short PASS is printed: server output and credential-bearing wire data
remain in the temporary fixture and are never included in assertion messages.
"""
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import socket
import signal
import ssl
import subprocess
import sys
import tempfile
import time

from _wire_client import BIN, Client
from android_sasl_network import Connection, SASL, b64

PASSWORD = 'logging-fixture-password-7d092c'
WRONG_PASSWORD = 'logging-wrong-password-8f14ad'
BODY = 'logging-private-message-body-326abc'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def records(path):
    if not path.exists():
        return []
    result = []
    for line in path.read_text().splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            raise AssertionError('log file contains a non-JSON record') from None
    return result


def wait_for(path, predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        found = records(path)
        if predicate(found):
            return found
        time.sleep(.02)
    raise AssertionError('required structured log event was not written')


def fields(record):
    values = record['fields']
    require(isinstance(values, list), 'fields must be a list')
    require(all(isinstance(f, dict) and set(f) == {'key', 'value'} for f in values),
            'invalid structured field shape')
    return {f['key']: f['value'] for f in values}


def plain(port, cert, user, password, forbidden):
    connection = Connection(port, cert, ssl.TLSVersion.TLSv1_2)
    try:
        payload = b64(f'\0{user}\0{password}'.encode())
        forbidden.add(payload)
        connection.send(f"<auth xmlns='{SASL}' mechanism='PLAIN'>{payload}</auth>")
        require(connection.stanza().tag == '{' + SASL + '}failure',
                'invalid PLAIN login was accepted')
    finally:
        connection.sock.close()


def corrupt_account(port, cert, forbidden):
    connection = Connection(port, cert, ssl.TLSVersion.TLSv1_2)
    try:
        payload = b64(b'n,,n=broken,r=corrupt-account-log-check')
        forbidden.add(payload)
        connection.send(f"<auth xmlns='{SASL}' mechanism='SCRAM-SHA-256'>{payload}</auth>")
        require(connection.stanza().tag == '{' + SASL + '}failure',
                'corrupt account record did not reject authentication')
    finally:
        connection.sock.close()


def scram(port, cert, forbidden, wrong_binding=False, disconnect=False):
    connection = Connection(port, cert, ssl.TLSVersion.TLSv1_2)
    try:
        gs2 = 'p=tls-server-end-point,,'
        bare = 'n=alice,r=log-fixture-client-nonce'
        initial = b64((gs2 + bare).encode())
        forbidden.add(initial)
        connection.send(f"<auth xmlns='{SASL}' mechanism='SCRAM-SHA-256-PLUS'>{initial}</auth>")
        challenge = connection.stanza()
        require(challenge.tag == '{' + SASL + '}challenge', 'SCRAM challenge missing')
        if disconnect:
            return
        first = base64.b64decode(challenge.text).decode()
        attrs = dict(item.split('=', 1) for item in first.split(','))
        binding = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).digest()
        if wrong_binding:
            binding = bytes([binding[0] ^ 1]) + binding[1:]
        final = 'c=' + b64(gs2.encode() + binding) + ',r=' + attrs['r']
        salted = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode(),
                                     base64.b64decode(attrs['s']), int(attrs['i']))
        mac = lambda key, message: hmac.new(key, message, 'sha256').digest()
        client_key = mac(salted, b'Client Key')
        signature = mac(hashlib.sha256(client_key).digest(),
                        (bare + ',' + first + ',' + final).encode())
        proof = bytes(a ^ b for a, b in zip(client_key, signature))
        if not wrong_binding:
            proof = bytes([proof[0] ^ 1]) + proof[1:]
        encoded_proof = b64(proof)
        response = final + ',p=' + encoded_proof
        payload = b64(response.encode())
        forbidden.update((encoded_proof, response, payload))
        connection.send(f"<response xmlns='{SASL}'>{payload}</response>")
        require(connection.stanza().tag == '{' + SASL + '}failure',
                'invalid SCRAM response was accepted')
    finally:
        connection.sock.close()


def run(binary):
    with tempfile.TemporaryDirectory(prefix='xmpp-logging-') as tmp:
        root = Path(tmp)
        cert = root / 'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                        '-sha256', '-nodes', '-days', '1', '-keyout', str(root / 'key.pem'),
                        '-out', str(cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        log_path = root / 'structured.jsonl'
        config = root / 'config.json'
        config.write_text(json.dumps({'global': {
            'data_path': str(root / 'data'), 'interfaces': ['127.0.0.1'],
            'c2s_ports': [port], 'http_ports': [], 'https_ports': [], 's2s_ports': [],
            'modules_enabled': ['tls', 'saslauth', 'ping'],
            'log_format': 'json', 'log': {'debug': str(log_path)}},
            'hosts': {'localhost': {'options': {
                'authentication': 'internal_hashed', 'password_hash': 'SHA-256',
                'ssl': {'key': str(root / 'key.pem'), 'certificate': str(cert)}}}}}))
        subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'],
                       input=PASSWORD + '\n', text=True, check=True, capture_output=True)
        account_dir = root / 'data' / 'localhost' / 'accounts'
        require((account_dir / 'alice.dat').exists(), 'fixture account path missing')
        (account_dir / 'broken.dat').write_text('return { malformed =\n')
        forbidden = {PASSWORD, WRONG_PASSWORD, BODY,
                     b64(f'\0alice\0{PASSWORD}'.encode())}
        start = datetime.now(timezone.utc)
        with (root / 'process.log').open('w') as output:
            process = subprocess.Popen([binary, 'serve', str(config), '--experimental'],
                                       stdout=output, stderr=output)
            try:
                for _ in range(100):
                    require(process.poll() is None, 'fixture server stopped')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError('fixture server did not listen')
                # Wait for readiness-probe close before measuring individual sessions.
                wait_for(log_path, lambda rows: any(r.get('event') == 'connection-closed' for r in rows))
                cases = []

                def case(name, action, expected, rejected=False, reason=None):
                    before = {r.get('connection') for r in records(log_path)
                              if r.get('event') == 'connection-open'}
                    action()
                    rows = wait_for(log_path, lambda rs: any(
                        r.get('event') == 'connection-closed' and r.get('connection') not in before
                        for r in rs))
                    opens = [r for r in rows if r.get('event') == 'connection-open'
                             and r.get('connection') not in before]
                    require(len(opens) == 1, name + ': expected one connection ID')
                    cid = opens[0]['connection']
                    require(isinstance(cid, str) and bool(cid), name + ': missing connection ID')
                    session = [r for r in rows if r.get('connection') == cid]
                    events = [r['event'] for r in session]
                    cursor = 0
                    for event in expected:
                        require(event in events[cursor:], name + ': missing or out-of-order ' + event)
                        cursor = events.index(event, cursor) + 1
                    if rejected:
                        rejections = [r for r in session if r['event'] == 'sasl-rejected']
                        require(bool(rejections), name + ': missing rejection')
                        reasons = [fields(r).get('reason') for r in rejections]
                        require(all(isinstance(r, str) and r for r in reasons), name + ': reason missing')
                        if reason:
                            lookup = [r for r in session if r['event'] == 'account-lookup']
                            require(bool(lookup), name + ': missing account lookup diagnostic')
                            require(any(fields(r).get('reason') in reason for r in lookup),
                                    name + ': expected account lookup reason missing')
                        require('auth-success' not in events and 'resource-bound' not in events,
                                name + ': rejected session authenticated')
                    cases.append(cid)

                def success():
                    client = Client(port, cert, 'alice', PASSWORD, resource='logging-check')
                    try:
                        client.sync()
                        client.send(f"<message to='alice@localhost/logging-check'><body>{BODY}</body></message>")
                        client.sync()
                    finally:
                        client.close()

                common = ['connection-open', 'tls-established', 'sasl-features', 'sasl-attempt']
                case('PLAIN success', success, common + ['auth-success', 'resource-bound', 'connection-closed'])
                case('PLAIN wrong password', lambda: plain(port, cert, 'alice', WRONG_PASSWORD, forbidden),
                     common + ['sasl-rejected', 'connection-closed'], rejected=True)
                for wrong_binding in (False, True):
                    case('SCRAM invalid binding' if wrong_binding else 'SCRAM wrong proof',
                         lambda wrong_binding=wrong_binding: scram(port, cert, forbidden, wrong_binding),
                         common + ['sasl-challenge', 'sasl-rejected', 'connection-closed'], rejected=True)
                case('disconnect during challenge', lambda: scram(port, cert, forbidden, disconnect=True),
                     common + ['sasl-challenge', 'connection-closed'])
                case('unknown user', lambda: plain(port, cert, 'missing-user', WRONG_PASSWORD, forbidden),
                     common + ['sasl-rejected', 'connection-closed'], rejected=True)
                case('corrupt account', lambda: corrupt_account(port, cert, forbidden),
                     common + ['sasl-rejected', 'connection-closed'], rejected=True, reason={'account-record-invalid', 'account-hash-or-record-invalid'})
                rotated = root / 'structured-rotated.jsonl'
                log_path.rename(rotated)
                process.send_signal(signal.SIGHUP)
                wait_for(log_path, lambda rs: any(r.get('event') == 'logs-reopened' for r in rs))
                case('PLAIN success after SIGHUP rotation', success,
                     common + ['auth-success', 'resource-bound', 'connection-closed'])
                require(len(set(cases)) == len(cases), 'connection IDs were reused')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        end = datetime.now(timezone.utc)
        rows = records(rotated) + records(log_path)
        require(bool(rows), 'configured JSON log file is empty')
        previous = start
        for row in rows:
            require(set(row) == {'timestamp', 'level', 'module', 'connection', 'event', 'fields'},
                    'invalid JSON log record shape')
            require(row['level'] in ('debug', 'info', 'warn', 'error'), 'invalid log level')
            require(isinstance(row['module'], str) and row['module'], 'missing module')
            require(isinstance(row['event'], str) and row['event'], 'missing event')
            fields(row)
            try:
                stamp = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
            except (TypeError, ValueError):
                raise AssertionError('invalid log timestamp') from None
            require(stamp.tzinfo is not None, 'log timestamp lacks timezone')
            # Logger timestamps use millisecond precision.
            require(start.timestamp() - .001 <= stamp.timestamp() <= end.timestamp(),
                    'log timestamp is outside fixture lifetime')
            require(stamp.timestamp() + .001 >= previous.timestamp(), 'log timestamps are out of order')
            previous = stamp
        raw = rotated.read_text() + log_path.read_text()
        require(all(value not in raw for value in forbidden), 'sensitive wire content leaked into log')
    print('PASS: JSON file logging, TLS/auth/bind correlation, rejection reasons, secret redaction and SIGHUP rotation')


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else str(BIN))
