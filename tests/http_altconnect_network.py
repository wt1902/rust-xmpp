#!/usr/bin/env python3
"""Real-binary XEP-0156 host-meta regression using isolated loopback listeners.

Requires Python 3.11+, openssl and websockets. No external services or trust
changes: the temporary certificate is trusted only by this test's TLS client.
"""
import argparse
import asyncio
from contextlib import contextmanager
import copy
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

import websockets

XRD = 'http://docs.oasis-open.org/ns/xri/xrd-1.0'
BOSH_REL = 'urn:xmpp:alt-connections:xbosh'
WS_REL = 'urn:xmpp:alt-connections:websocket'
FRAMING = 'urn:ietf:params:xml:ns:xmpp-framing'


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def request(port, path, method='GET', context=None, host=None):
    connection = (http.client.HTTPSConnection('localhost', port, context=context, timeout=5)
                  if context else http.client.HTTPConnection('127.0.0.1', port, timeout=5))
    try:
        connection.request(method, path, headers={
            'Host': host or f'localhost:{port}', 'Origin': 'https://unrelated.example',
            'Access-Control-Request-Method': 'GET', 'Connection': 'close'})
        response = connection.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        connection.close()


@contextmanager
def server(binary, config, root, label):
    directory = root / label
    directory.mkdir()
    config = copy.deepcopy(config)
    config['global']['data_path'] = str(directory / 'data')
    path = directory / 'config.json'
    path.write_text(json.dumps(config))
    ports = config['global']['http_ports'] + config['global']['https_ports']
    with (directory / 'server.log').open('w+') as log:
        process = subprocess.Popen([binary, 'serve', str(path), '--experimental'], stdout=log, stderr=log)
        try:
            for port in ports:
                for _ in range(100):
                    assert process.poll() is None, f'{label}: server exited during startup'
                    try:
                        with socket.create_connection(('127.0.0.1', port), .1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError(f'{label}: listener {port} startup timed out')
            yield
        except BaseException:
            log.flush()
            log.seek(0)
            print(f'{label} SERVER LOG:\n' + log.read())
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def documents(port, expected, context=None, base='/.well-known', host=None):
    """Both serializations describe exactly the same ordered transport links."""
    for suffix in ('', '?callback=PRIVATE_CALLBACK&cache=1'):
        for extension in ('', '.json'):
            path = base + '/host-meta' + extension + suffix
            status, headers, body = request(port, path, context=context, host=host)
            assert status == 200, (path, status, body)
            assert headers.get('access-control-allow-origin') == '*', headers
            content_type = headers.get('content-type', '').split(';')[0]
            if extension:
                assert content_type == 'application/json', headers
                parsed = json.loads(body)
                assert isinstance(parsed.get('links'), list), parsed
                links = [(link['rel'], link['href']) for link in parsed['links']]
            else:
                assert content_type == 'application/xrd+xml', headers
                parsed = ET.fromstring(body)
                assert parsed.tag == f'{{{XRD}}}XRD', body
                links = [(link.get('rel'), link.get('href')) for link in parsed.findall(f'{{{XRD}}}Link')]
            assert links == expected, (path, expected, links)
            assert b'PRIVATE_CALLBACK' not in body, body
            status, head_headers, body = request(port, path, 'HEAD', context, host)
            assert status == 200 and body == b'', (path, status, body)
            assert head_headers.get('access-control-allow-origin') == '*', head_headers
            status, options_headers, body = request(port, path, 'OPTIONS', context, host)
            assert 200 <= status < 300 and body == b'', (path, status, body)
            assert options_headers.get('access-control-allow-origin') == '*', options_headers
            allowed = {s.strip() for s in options_headers.get('access-control-allow-methods', '').split(',')}
            assert {'GET', 'HEAD', 'OPTIONS'} <= allowed, options_headers
    for extension in ('', '.json'):
        status, _, body = request(port, base + '/host-meta' + extension, 'POST', context, host)
        assert status == 405, (status, body)


async def websocket_exchange(port, context, path='/xmpp-websocket'):
    async with websockets.connect(f'wss://localhost:{port}{path}', ssl=context,
                                  origin='https://browser.example', subprotocols=['xmpp'], open_timeout=5) as ws:
        assert ws.subprotocol == 'xmpp'
        await ws.send(f'<open xmlns="{FRAMING}" to="localhost" version="1.0"/>')
        assert ET.fromstring(await asyncio.wait_for(ws.recv(), 5)).tag == f'{{{FRAMING}}}open'
        assert ET.fromstring(await asyncio.wait_for(ws.recv(), 5)).tag.endswith('}features')
        await ws.send(f'<close xmlns="{FRAMING}"/>')
        assert ET.fromstring(await asyncio.wait_for(ws.recv(), 5)).tag == f'{{{FRAMING}}}close'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default=str(Path(__file__).resolve().parents[1] / 'target/release/rust-xmpp'))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='xmpp-http-altconnect-') as temporary:
        root = Path(temporary)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True)
        context = ssl.create_default_context(cafile=str(cert))
        http, https = free_port(), free_port()
        while https == http:
            https = free_port()
        config = {'global': {'interfaces': ['127.0.0.1'], 'http_interfaces': ['127.0.0.1'],
                             'https_interfaces': ['127.0.0.1'], 'c2s_ports': [], 's2s_ports': [],
                             'http_ports': [http], 'https_ports': [https],
                             'modules_enabled': ['tls', 'bosh', 'websocket', 'http_altconnect', 'saslauth'],
                             'http_cors_override': {'websocket': {'origins': ['https://browser.example']}},
                             'ssl': {'certificate': str(cert), 'key': str(key)}},
                  'hosts': {'localhost': {'options': {'authentication': 'internal_hashed'}}}}
        secure = [(BOSH_REL, f'https://localhost:{https}/http-bind'),
                  (WS_REL, f'wss://localhost:{https}/xmpp-websocket')]
        with server(args.binary, config, root, 'defaults'):
            documents(http, secure)
            documents(https, secure, context)
            for port, tls in ((http, None), (https, context)):
                for host in ('unknown.example', 'localhost:999999', 'bad host'):
                    status, _, body = request(port, '/.well-known/host-meta.json', context=tls, host=host)
                    assert status in (400, 404), (host, status, body)
            asyncio.run(websocket_exchange(https, context))

        custom = copy.deepcopy(config)
        custom['global'].update({'http_paths': {'altconnect': 'discovery/$host/',
                                               'bosh': '/custom/bind', 'websocket': '/custom/socket'},
                                 'http_external_url': 'https://global.example/ignored'})
        custom['hosts']['localhost']['options'].update({
            'http_external_url': 'https://proxy.example:443/public/prefix/', 'http_host': 'chat.example'})
        public = [(BOSH_REL, 'https://proxy.example/public/prefix/custom/bind'),
                  (WS_REL, 'wss://proxy.example/public/prefix/custom/socket')]
        with server(args.binary, custom, root, 'custom'):
            for port, tls in ((http, None), (https, context)):
                documents(port, public, tls, '/discovery/localhost', 'chat.example')
                for path in ('/.well-known/host-meta', '/.well-known/host-meta.json',
                             '/public/prefix/discovery/localhost/host-meta'):
                    status, _, body = request(port, path, context=tls, host='chat.example')
                    assert status == 404, (path, status, body)
                status, _, body = request(port, '/discovery/localhost/host-meta.json', context=tls)
                assert status == 404, (status, body)

        disabled = copy.deepcopy(config)
        disabled['hosts']['localhost']['options']['modules_disabled'] = ['http_altconnect']
        with server(args.binary, disabled, root, 'disabled'):
            for port, tls in ((http, None), (https, context)):
                for extension in ('', '.json'):
                    status, _, body = request(port, '/.well-known/host-meta' + extension, context=tls)
                    assert status == 404, (status, body)
            asyncio.run(websocket_exchange(https, context))

        for label, disabled_modules, flags, expected in (
                ('bosh-disabled', ['bosh'], {}, [secure[1]]),
                ('websocket-disabled', ['websocket'], {}, [secure[0]]),
                ('no-transports', ['bosh', 'websocket'], {}, []),
                ('bosh-hidden', [], {'advertise_bosh': False}, [secure[1]]),
                ('websocket-hidden', [], {'advertise_websocket': False}, [secure[0]]),
                ('all-hidden', [], {'advertise_bosh': False, 'advertise_websocket': False}, [])):
            variant = copy.deepcopy(config)
            variant['hosts']['localhost']['options'].update(flags, modules_disabled=disabled_modules)
            with server(args.binary, variant, root, label):
                documents(http, expected)

        plain = copy.deepcopy(config)
        plain['global']['https_ports'] = []
        plain_links = [(BOSH_REL, f'http://localhost:{http}/http-bind'),
                       (WS_REL, f'ws://localhost:{http}/xmpp-websocket')]
        with server(args.binary, plain, root, 'http-only'):
            documents(http, plain_links)
    print('PASS: XEP-0156 XRD/JRD parity, CORS, safe methods, ignored JSONP, host checks, secure URL preference, custom mounts/public prefixes, module and advertisement gates, HTTP fallback and verified WSS framing')


if __name__ == '__main__':
    main()
