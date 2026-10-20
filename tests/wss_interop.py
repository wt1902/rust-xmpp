#!/usr/bin/env python3
"""Verified-TLS browser-style RFC 7395 handshake regression.

Requires Python 3.11+, websockets and openssl. Starts an HTTPS-only server
bound to loopback; no credentials, external network or system trust changes.
Usage: python3 tests/wss_interop.py [--binary target/release/rust-xmpp]
"""
import argparse
import asyncio
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

import websockets

ORIGIN = 'https://conversejs.wthome.ru'
FRAMING = 'urn:ietf:params:xml:ns:xmpp-framing'


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def http_status(port, context, path='/xmpp-websocket', origin=ORIGIN, protocol='xmpp', address='127.0.0.1'):
    """Send browser handshake headers over certificate-verified TLS."""
    headers = [f'GET {path} HTTP/1.1', f'Host: localhost:{port}',
               'Connection: keep-alive, Upgrade', 'Upgrade: websocket',
               'Sec-WebSocket-Version: 13',
               'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==']
    if origin is not None:
        headers.append(f'Origin: {origin}')
    if protocol is not None:
        headers.append(f'Sec-WebSocket-Protocol: {protocol}')
    with socket.create_connection((address, port), timeout=5) as tcp:
        with context.wrap_socket(tcp, server_hostname='localhost') as stream:
            stream.sendall(('\r\n'.join(headers) + '\r\n\r\n').encode())
            response = b''
            while b'\r\n\r\n' not in response:
                chunk = stream.recv(4096)
                assert chunk, response
                response += chunk
            return int(response.split(b' ', 2)[1]), response


async def exercise(port, context):
    for path in ('/xmpp-websocket', '/xmpp-websocket/'):
        async with websockets.connect(f'wss://localhost:{port}{path}', ssl=context,
                                      origin=ORIGIN, subprotocols=['xmpp'], open_timeout=5) as ws:
            assert ws.subprotocol == 'xmpp', ws.subprotocol
            await ws.send(f'<open xmlns="{FRAMING}" to="localhost" version="1.0"/>')
            opened = ET.fromstring(await asyncio.wait_for(ws.recv(), timeout=5))
            assert opened.tag == f'{{{FRAMING}}}open', ET.tostring(opened)
            features = ET.fromstring(await asyncio.wait_for(ws.recv(), timeout=5))
            assert features.tag == '{http://etherx.jabber.org/streams}features', ET.tostring(features)
            await ws.send(f'<close xmlns="{FRAMING}"/>')
            closed = ET.fromstring(await asyncio.wait_for(ws.recv(), timeout=5))
            assert closed.tag == f'{{{FRAMING}}}close', ET.tostring(closed)



def verify_original_origin_policy(binary, config, root, port, context):
    """Reproduce the deployment mismatch before allowing the Converse page."""
    original = json.loads(json.dumps(config))
    original['global']['http_cors_override']['websocket']['origins'] = ['https://wthome.ru']
    path = root / 'original-origin-config.json'
    path.write_text(json.dumps(original))
    with (root / 'original-origin.log').open('w+') as log:
        server = subprocess.Popen([binary, 'serve', str(path), '--experimental'], stdout=log, stderr=log)
        try:
            for _ in range(100):
                assert server.poll() is None, 'original-origin server stopped during startup'
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError('original-origin HTTPS server startup timed out')
            status, headers = http_status(port, context, origin='https://wthome.ru')
            assert status == 101, headers
            status, headers = http_status(port, context, origin=ORIGIN)
            assert status == 403, headers
        except BaseException:
            log.flush()
            log.seek(0)
            print('ORIGINAL ORIGIN SERVER LOG:\n' + log.read())
            raise
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default=str(Path(__file__).resolve().parents[1] / 'target/release/rust-xmpp'))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='xmpp-wss-interop-') as temporary:
        root = Path(temporary)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True)
        port = free_port()
        interfaces = ['127.0.0.1']
        try:
            with socket.socket(socket.AF_INET6) as probe:
                probe.bind(('::1', 0))
            interfaces.append('::1')
        except OSError:
            pass
        config = {'global': {'data_path': str(root / 'data'), 'interfaces': ['127.0.0.1'],
                            'https_interfaces': interfaces, 'c2s_ports': [], 's2s_ports': [],
                            'http_ports': [], 'https_ports': [port],
                            'log_format': 'json',
                            'modules_enabled': ['tls', 'websocket', 'saslauth'],
                            'http_cors_override': {'websocket': {'origins': [ORIGIN]}},
                            'ssl': {'certificate': str(cert), 'key': str(key)}},
                  'hosts': {'localhost': {'options': {'authentication': 'internal_hashed'}}}}
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        context = ssl.create_default_context(cafile=str(cert))
        verify_original_origin_policy(args.binary, config, root, port, context)
        with (root / 'server.log').open('w+') as log:
            server = subprocess.Popen([args.binary, 'serve', str(path), '--experimental'], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    assert server.poll() is None, 'server stopped during startup'
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError('HTTPS-only server startup timed out')
                # Normal browser Origin, with token-list Connection header.
                status, headers = http_status(port, context)
                assert status == 101, headers
                assert b'sec-websocket-protocol: xmpp' in headers.lower(), headers
                if '::1' in interfaces:
                    status, headers = http_status(port, context, address='::1')
                    assert status == 101, headers
                for origin in ('https://PRIVATE-ORIGIN.example', ORIGIN + ':8443', 'null'):
                    status, headers = http_status(port, context, origin=origin)
                    assert status == 403, (origin, headers)
                for protocol in (None, 'chat', 'XMPP'):
                    status, headers = http_status(port, context, protocol=protocol)
                    assert status == 400, (protocol, headers)
                status, headers = http_status(port, context, path='/PRIVATE-PATH?token=PRIVATE-TOKEN')
                assert status == 404, headers
                # Native clients may omit Origin; they must still negotiate xmpp.
                status, headers = http_status(port, context, origin=None, protocol='chat, xmpp')
                assert status == 101, headers
                try:
                    http_status(port, ssl.create_default_context())
                except ssl.SSLCertVerificationError:
                    pass
                else:
                    raise AssertionError('untrusted TLS certificate was accepted')
                asyncio.run(exercise(port, context))
                log.flush()
                log.seek(0)
                logged = log.read()
                events = [json.loads(line) for line in logged.splitlines() if line.startswith('{')]
                http_events = [e for e in events if e.get('module') == 'http']
                assert any(e['event'] == 'connection-open' for e in http_events), logged
                listeners = [dict((f['key'], f['value']) for f in e['fields'])
                             for e in http_events if e['event'] == 'listener-ready']
                assert len(listeners) == len(interfaces), listeners
                assert all(e.get('transport') == 'https' for e in listeners), listeners
                assert any(e['event'] == 'tls-established' for e in http_events), logged
                requests = [dict((f['key'], f['value']) for f in e['fields'])
                            for e in http_events if e['event'] == 'request-complete']
                for status in ('101', '400', '403', '404'):
                    assert any(r.get('status') == status for r in requests), (status, requests)
                assert all(r.get('route') in ('websocket', 'bosh', 'other') for r in requests), requests
                assert all(secret not in logged for secret in
                           ('PRIVATE-PATH', 'PRIVATE-TOKEN', 'PRIVATE-ORIGIN', 'dGhlIHNhbXBsZSBub25jZQ==')), logged
            except BaseException:
                log.flush()
                log.seek(0)
                print('SERVER LOG:\n' + log.read())
                raise
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
    print('PASS: HTTPS-only configured interfaces (' + ','.join(interfaces) + '), verified TLS, reproduced original Origin 403 then allowed Converse Origin 101, xmpp subprotocol, both WS paths, RFC 7395 open/features/close and private HTTP diagnostics')


if __name__ == '__main__':
    main()
