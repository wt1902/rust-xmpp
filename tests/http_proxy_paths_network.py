#!/usr/bin/env python3
"""Loopback network regression for custom routes and TLS-terminating proxies.

Requires websockets and openssl. Uses an actual verified HTTPS proxy, HTTP
upstream, and isolated server data; never contacts an external service.
"""
import argparse
import asyncio
import base64
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

import websockets

ORIGIN = 'https://browser.example'
WS_PATH = '/private/xmpp/socket'
BOSH_PATH = '/private/xmpp/bind'
PUBLIC_WS = '/public/chat/socket'
PUBLIC_BOSH = '/public/chat/bind'
BOSH = 'http://jabber.org/protocol/httpbind'
FRAMING = 'urn:ietf:params:xml:ns:xmpp-framing'
SASL = 'urn:ietf:params:xml:ns:xmpp-sasl'
CLIENT = 'jabber:client'
BIND = 'urn:ietf:params:xml:ns:xmpp-bind'
PASSWORD = 'proxy-integration-password'
PLAIN = base64.b64encode(f'\0alice\0{PASSWORD}'.encode()).decode()


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def request(port, path, method='GET', body=b'', origin=ORIGIN,
            forwarded=None, context=None, address='127.0.0.1', upgrade=False, rfc=False):
    headers = {'Host': f'localhost:{port}', 'Connection': 'close'}
    if origin is not None:
        headers['Origin'] = origin
    if forwarded is not None:
        headers['Forwarded' if rfc else 'X-Forwarded-Proto'] = (
            f'for=198.51.100.77;proto={forwarded}' if rfc else forwarded)
    if method == 'POST':
        headers['Content-Type'] = 'text/xml'
    if upgrade:
        headers.update({'Connection': 'keep-alive, Upgrade', 'Upgrade': 'websocket',
                        'Sec-WebSocket-Version': '13',
                        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                        'Sec-WebSocket-Protocol': 'xmpp'})
    connection = (http.client.HTTPSConnection(address, port, context=context, timeout=8)
                  if context else http.client.HTTPConnection(address, port, timeout=8))
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


@contextmanager
def server(binary, config, root):
    path = root / 'config.json'
    path.write_text(json.dumps(config))
    with (root / 'server.log').open('w+') as log:
        process = subprocess.Popen([binary, 'serve', str(path), '--experimental'],
                                   stdout=log, stderr=log)
        try:
            for _ in range(100):
                assert process.poll() is None, 'server exited during startup'
                try:
                    with socket.create_connection(('127.0.0.1', config['global']['http_ports'][0]), .1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError('HTTP listener startup timed out')
            yield
        except BaseException:
            log.flush()
            log.seek(0)
            print('SERVER LOG:\n' + log.read())
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


class Proxy(socketserver.ThreadingTCPServer):
    """Small TLS-terminating, path-rewriting TCP proxy supporting WS upgrades."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, backend, tls, source='127.0.0.2', proto='https', rfc=False):
        self.backend, self.tls, self.source, self.proto = backend, tls, source, proto
        self.rfc = rfc
        self.errors = []
        super().__init__(('127.0.0.1', 0), ProxyHandler)

    def get_request(self):
        stream, peer = super().get_request()
        try:
            return self.tls.wrap_socket(stream, server_side=True), peer
        except BaseException:
            stream.close()
            raise

    def handle_error(self, request, client_address):
        import traceback
        self.errors.append(traceback.format_exc())


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(8)
        incoming = b''
        while b'\r\n\r\n' not in incoming:
            chunk = client.recv(4096)
            if not chunk:
                return
            incoming += chunk
            assert len(incoming) < 65536, 'oversized proxy request headers'
        head, payload = incoming.split(b'\r\n\r\n', 1)
        lines = head.decode('latin1').split('\r\n')
        method, path, version = lines[0].split(' ', 2)
        for public, internal in ((PUBLIC_WS, WS_PATH), (PUBLIC_BOSH, BOSH_PATH)):
            if path == public or path.startswith(public + '/') or path.startswith(public + '?'):
                path = internal + path[len(public):]
                break
        # The fixture models a proxy which replaces client-supplied metadata.
        headers = [line for line in lines[1:] if line.split(':', 1)[0].lower()
                   not in ('forwarded', 'x-forwarded-for', 'x-forwarded-proto')]
        if self.server.rfc:
            headers += [f'Forwarded: for=198.51.100.77;proto={self.server.proto}']
        else:
            headers += ['X-Forwarded-For: 198.51.100.7', f'X-Forwarded-Proto: {self.server.proto}']
        outgoing = ('\r\n'.join([f'{method} {path} {version}', *headers]) + '\r\n\r\n').encode('latin1')
        with socket.create_connection(('127.0.0.1', self.server.backend), timeout=8,
                                      source_address=(self.server.source, 0)) as upstream:
            upstream.sendall(outgoing + payload)
            while True:
                # SSLSocket may already have decrypted bytes buffered internally.
                readable = [client] if client.pending() else select.select([client, upstream], [], [], 8)[0]
                if not readable:
                    return
                for source in readable:
                    try:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is client else client).sendall(data)
                    except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError):
                        # Raw handshake probes intentionally close after HTTP101.
                        return


@contextmanager
def proxy(backend, tls, **kwargs):
    with Proxy(backend, tls, **kwargs) as fixture:
        worker = threading.Thread(target=fixture.serve_forever, daemon=True)
        worker.start()
        try:
            yield fixture.server_address[1]
            assert not fixture.errors, '\n'.join(fixture.errors)
        finally:
            fixture.shutdown()
            worker.join(timeout=5)


async def websocket_exchange(port, context, path, authenticate=False):
    async with websockets.connect(f'wss://localhost:{port}{path}', ssl=context,
                                  origin=ORIGIN, subprotocols=['xmpp'], open_timeout=8) as ws:
        assert ws.subprotocol == 'xmpp'
        await ws.send(f'<open xmlns="{FRAMING}" to="localhost" version="1.0"/>')
        opened = ET.fromstring(await asyncio.wait_for(ws.recv(), 5))
        assert opened.tag == f'{{{FRAMING}}}open', ET.tostring(opened)
        features = ET.fromstring(await asyncio.wait_for(ws.recv(), 5))
        assert features.find(f'.//{{{SASL}}}mechanism') is not None, ET.tostring(features)
        if authenticate:
            await ws.send(f'<auth xmlns="{SASL}" mechanism="PLAIN">{PLAIN}</auth>')
            success = ET.fromstring(await asyncio.wait_for(ws.recv(), 5))
            assert success.tag == f'{{{SASL}}}success', ET.tostring(success)
            await ws.send(f'<open xmlns="{FRAMING}" to="localhost" version="1.0"/>')
            assert ET.fromstring(await asyncio.wait_for(ws.recv(), 5)).tag == f'{{{FRAMING}}}open'
            assert ET.fromstring(await asyncio.wait_for(ws.recv(), 5)).tag.endswith('}features')
            await ws.send(f'<iq xmlns="{CLIENT}" type="set" id="bind"><bind xmlns="{BIND}"><resource>proxy-ws</resource></bind></iq>')
            bound = ET.fromstring(await asyncio.wait_for(ws.recv(), 5))
            assert bound.get('type') == 'result' and bound.get('id') == 'bind', ET.tostring(bound)
            assert bound.find(f'.//{{{BIND}}}jid').text == 'alice@localhost/proxy-ws', ET.tostring(bound)
            await ws.send(f'<iq xmlns="{CLIENT}" type="get" to="localhost" id="proxy-ping"><ping xmlns="urn:xmpp:ping"/></iq>')
            pong = ET.fromstring(await asyncio.wait_for(ws.recv(), 5))
            assert pong.get('type') == 'result' and pong.get('id') == 'proxy-ping', ET.tostring(pong)
        await ws.send(f'<close xmlns="{FRAMING}"/>')
        closed = ET.fromstring(await asyncio.wait_for(ws.recv(), 5))
        assert closed.tag == f'{{{FRAMING}}}close', ET.tostring(closed)


def bosh_exchange(port, context, path, authenticate=False):
    first = f'<body xmlns="{BOSH}" rid="100" to="localhost" wait="1" hold="1" ver="1.11"/>'.encode()
    status, _, payload = request(port, path, 'POST', first, context=context)
    assert status == 200, (status, payload)
    body = ET.fromstring(payload)
    sid = body.get('sid')
    assert sid and body.find(f'.//{{{SASL}}}mechanism') is not None, payload
    rid = 101

    def send(stanza='', extra=''):
        nonlocal rid
        document = f'<body xmlns="{BOSH}" sid="{sid}" rid="{rid}" {extra}>{stanza}</body>'.encode()
        rid += 1
        status, _, response = request(port, path, 'POST', document, context=context)
        assert status == 200, (status, response)
        return document, response, ET.fromstring(response)

    if authenticate:
        _, response, body = send(f'<auth xmlns="{SASL}" mechanism="PLAIN">{PLAIN}</auth>')
        assert body.find(f'{{{SASL}}}success') is not None, response
        _, response, body = send(extra='xmlns:xmpp="urn:xmpp:xbosh" xmpp:restart="true" to="localhost"')
        assert any(n.tag.endswith('}features') for n in body), response
        _, response, body = send(f'<iq xmlns="{CLIENT}" type="set" id="bind"><bind xmlns="{BIND}"><resource>proxy-bosh</resource></bind></iq>')
        assert body.find(f'.//{{{BIND}}}jid').text == 'alice@localhost/proxy-bosh', response
        poll, response, body = send(f'<iq xmlns="{CLIENT}" type="get" to="localhost" id="proxy-ping"><ping xmlns="urn:xmpp:ping"/></iq>')
        assert any(n.get('id') == 'proxy-ping' and n.get('type') == 'result' for n in body), response
    else:
        poll, response, body = send()
    assert body.get('type') != 'terminate', response
    # A retried RID after URI rewriting must return its exact cached response.
    retried_status, _, retried = request(port, path, 'POST', poll, context=context)
    assert retried_status == 200 and retried == response, (response, retried)
    _, response, body = send(extra='type="terminate"')
    assert body.get('type') == 'terminate', response


def policy_checks(port, context, ws_path, bosh_path):
    for path, method, upgrade in ((ws_path, 'GET', True), (bosh_path, 'OPTIONS', False)):
        status, headers, body = request(port, path, method, context=context, upgrade=upgrade)
        assert status == (101 if upgrade else 200), (path, status, body)
        assert headers.get('access-control-allow-origin') == ORIGIN, headers
        for origin in ('https://wrong.example', ORIGIN + ':8443', 'null'):
            status, _, body = request(port, path, method, context=context,
                                      upgrade=upgrade, origin=origin)
            assert status == 403, (path, origin, status, body)
        status, headers, _ = request(port, path, method, context=context,
                                     upgrade=upgrade, origin=None)
        assert status == (101 if upgrade else 200), (path, status)
        assert 'access-control-allow-origin' not in headers, headers
    status, _, body = request(port, bosh_path, 'POST', context=context,
                              origin='https://wrong.example')
    assert status == 403, (bosh_path, status, body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default=str(Path(__file__).resolve().parents[1] / 'target/release/rust-xmpp'))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='xmpp-http-proxy-paths-') as temporary:
        root = Path(temporary)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1',
                        '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True)
        client_tls = ssl.create_default_context(cafile=str(cert))
        proxy_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        proxy_tls.load_cert_chain(str(cert), str(key))
        backend, https = free_port(), free_port()
        interfaces = ['127.0.0.1']
        try:
            with socket.socket(socket.AF_INET6) as probe:
                probe.bind(('::1', 0))
            interfaces.append('::1')
        except OSError:
            pass
        config = {'global': {'data_path': str(root / 'data'), 'interfaces': ['127.0.0.1'],
                            'http_interfaces': interfaces, 'https_interfaces': interfaces,
                            'c2s_ports': [], 's2s_ports': [], 'http_ports': [backend], 'https_ports': [https],
                            'http_host': 'localhost', 'http_default_host': 'localhost', 'trusted_proxies': ['127.0.0.2/32'],
                            'http_legacy_x_forwarded': True,
                            'consider_websocket_secure': False, 'consider_bosh_secure': False,
                            'http_paths': {'websocket': WS_PATH, 'bosh': BOSH_PATH},
                            'http_cors_override': {name: {'origins': [ORIGIN]} for name in ('websocket', 'bosh')},
                            'modules_enabled': ['tls', 'websocket', 'bosh', 'saslauth', 'ping'],
                            'ssl': {'certificate': str(cert), 'key': str(key)}},
                  'hosts': {'localhost': {'options': {'authentication': 'internal_hashed'}}}}
        config_path = root / 'config.json'
        config_path.write_text(json.dumps(config))
        subprocess.run([args.binary, 'create-user', str(config_path), 'alice', '--password-stdin'],
                       input=PASSWORD + '\n', text=True, check=True, capture_output=True)
        with server(args.binary, config, root):
            policy_checks(https, client_tls, WS_PATH, BOSH_PATH)
            for suffix in ('', '/', '?cache=1'):
                asyncio.run(websocket_exchange(https, client_tls, WS_PATH + suffix))
                bosh_exchange(https, client_tls, BOSH_PATH + suffix)
            for path in ('/xmpp-websocket', '/xmpp-websocket/', '/http-bind', '/http-bind/'):
                status, _, body = request(https, path, context=client_tls, upgrade='websocket' in path)
                assert status == 404, (path, status, body)
            for address in interfaces:
                for path, method in ((WS_PATH, 'GET'), (BOSH_PATH, 'POST')):
                    for spoof in (None, 'https'):
                        status, _, body = request(backend, path, method, forwarded=spoof,
                                                  address=address, upgrade=method == 'GET')
                        assert status == 403, (address, path, spoof, status, body)
                if address == '::1':
                    status, _, body = request(https, WS_PATH, context=client_tls,
                                              address=address, upgrade=True)
                    assert status == 101, (address, status, body)
            with proxy(backend, proxy_tls) as public:
                policy_checks(public, client_tls, PUBLIC_WS, PUBLIC_BOSH)
                asyncio.run(websocket_exchange(public, client_tls, PUBLIC_WS, authenticate=True))
                bosh_exchange(public, client_tls, PUBLIC_BOSH, authenticate=True)
            # Both TLS on an untrusted peer and a trusted peer declaring plain
            # HTTP must fail the same gate, before any XMPP session is created.
            for options in ({'source': '127.0.0.1'}, {'proto': 'http'}):
                with proxy(backend, proxy_tls, **options) as public:
                    for path, method in ((PUBLIC_WS, 'GET'), (PUBLIC_BOSH, 'POST')):
                        status, _, body = request(public, path, method, context=client_tls,
                                                  upgrade=method == 'GET')
                        assert status == 403, (options, path, status, body)
        config['global']['http_legacy_x_forwarded'] = False
        with server(args.binary, config, root):
            with proxy(backend, proxy_tls, rfc=True) as public:
                asyncio.run(websocket_exchange(public, client_tls, PUBLIC_WS, authenticate=True))
                bosh_exchange(public, client_tls, PUBLIC_BOSH, authenticate=True)
            for path, method in ((WS_PATH, 'GET'), (BOSH_PATH, 'POST')):
                status, _, body = request(backend, path, method, forwarded='https',
                                          rfc=True, upgrade=method == 'GET')
                assert status == 403, (path, status, body)
            for options in ({'source': '127.0.0.1'}, {'proto': 'http'}):
                with proxy(backend, proxy_tls, rfc=True, **options) as public:
                    for path, method in ((PUBLIC_WS, 'GET'), (PUBLIC_BOSH, 'POST')):
                        status, _, body = request(public, path, method, context=client_tls,
                                                  upgrade=method == 'GET')
                        assert status == 403, (options, path, status, body)
    print('PASS: custom WS/BOSH routes, default-route 404, exact Origin policy, verified TLS proxy rewrite, trusted HTTPS metadata, untrusted/spoofed metadata denial, IPv6 when available, authenticated WS/BOSH bind/ping in legacy and RFC7239 modes and cached BOSH RID retry')


if __name__ == '__main__':
    main()
