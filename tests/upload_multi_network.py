#!/usr/bin/env python3
"""Real TLS XMPP/HTTP multi-component upload isolation; no external services."""
import argparse
from contextlib import contextmanager
import copy
import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from _wire_client import Client, BIN

UPLOAD = 'urn:xmpp:http:upload:0'
DISCO = 'http://jabber.org/protocol/disco#info'


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def request(port, host, path, method='GET', body=None, authorization=None, extra_headers=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    headers = {'Host': host, 'Connection': 'close'}
    if authorization:
        headers['Authorization'] = authorization
    headers.update(extra_headers or {})
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


@contextmanager
def running(binary, config, root):
    path = root / 'config.json'
    path.write_text(json.dumps(config))
    with (root / 'server.log').open('w+') as log:
        process = subprocess.Popen([binary, 'serve', str(path), '--experimental'], stdout=log, stderr=log)
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
            print(log.read())
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def slot(client, component, identifier, size=5, error=False):
    client.send(f"<iq type='get' id='{identifier}' to='{component}'><request xmlns='{UPLOAD}' filename='hello.txt' size='{size}' content-type='text/plain'/></iq>")
    result = client.iq(identifier, error=error)
    if error:
        return result
    put = result.find(f'{{{UPLOAD}}}slot/{{{UPLOAD}}}put')
    return urlsplit(put.get('url')), put.find(f'{{{UPLOAD}}}header').text


def exercise(binary, root, shared):
    root.mkdir()
    cert, key = root / 'cert.pem', root / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    port, c2s = free_port(), free_port()
    hosts = ['files.example.test', 'files.example.test'] if shared else ['a.example.test', 'b.example.test']
    mounts = ['/files/a', '/files/b'] if shared else ['/files', '/files']
    components = ['upload-a.localhost', 'upload-b.localhost']
    config = {'global': {'data_path': str(root / 'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [c2s], 'http_ports': [port], 'https_ports': [], 's2s_ports': [], 'modules_enabled': ['tls', 'saslauth', 'disco', 'websocket', 'bosh', 'http_altconnect'], 'consider_bosh_secure': True, 'consider_websocket_secure': True, 'ssl': {'certificate': str(cert), 'key': str(key)}}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed'}}}}
    for index, component in enumerate(components):
        config['hosts'][component] = {'component': 'http_file_share', 'options': {'http_host': hosts[index], 'http_paths': {'file_share': mounts[index]}, 'http_file_share_size_limit': 8 * (index + 1), 'http_file_share_daily_quota': 5, 'http_file_share_global_quota': 5, 'http_file_share_secret': f'component-secret-{index}'}}
    path = root / 'config.json'
    path.write_text(json.dumps(config))
    subprocess.run([binary, 'create-user', str(path), 'alice', '--password-stdin'], input='secret\n', text=True, check=True, capture_output=True)
    slots = []
    with running(binary, config, root):
        client = Client(c2s, cert, 'alice', 'secret')
        try:
            client.send(f"<iq type='get' id='items' to='localhost'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")
            items = {node.get('jid') for node in client.iq('items').iter()}
            assert set(components) <= items, items
            for index, component in enumerate(components):
                client.send(f"<iq type='get' id='info-{index}' to='{component}'><query xmlns='{DISCO}'/></iq>")
                info = client.iq(f'info-{index}')
                assert any(node.get('var') == UPLOAD for node in info.iter())
                fields = {node.get('var'): node.find('{jabber:x:data}value').text for node in info.iter('{jabber:x:data}field')}
                assert fields['max-file-size'] == str(8 * (index + 1)), fields
                url, token = slot(client, component, f'slot-{index}')
                assert url.hostname == hosts[index] and url.path.startswith(mounts[index] + '/'), url
                slots.append((url, token))
                slot(client, component, f'quota-{index}', size=1, error=True)
            # A JWT issued by component A must not authorize B's valid slot.
            assert request(port, hosts[1], slots[1][0].path, 'PUT', b'hello', slots[0][1])[0] == 403
            for index, (url, token) in enumerate(slots):
                assert request(port, hosts[index], url.path, 'PUT', b'hello', token)[0] == 201
                assert request(port, hosts[index].upper() + f':{port}', url.path) == (200, b'hello')
                assert request(port, hosts[index], url.path, 'PUT', b'hello', token)[0] == 409
                assert request(port, 'unknown.example.test', url.path)[0] == 404
                other = 1 - index
                wrong_path = mounts[other] + url.path[len(mounts[index]):]
                assert request(port, hosts[other], wrong_path)[0] == 404
            # Transport and discovery middleware continue working around uploads.
            assert request(port, 'localhost', '/.well-known/host-meta')[0] == 200
            assert request(port, 'localhost', '/xmpp-websocket', extra_headers={'Connection': 'Upgrade', 'Upgrade': 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==', 'Sec-WebSocket-Protocol': 'xmpp'})[0] == 101
            assert request(port, 'localhost', '/http-bind', 'POST', b"<body xmlns='http://jabber.org/protocol/httpbind' to='localhost' rid='1' wait='1' hold='1' ver='1.6'/>")[0] == 200
        finally:
            client.close()
    with running(binary, config, root):
        for index, (url, _) in enumerate(slots):
            assert request(port, hosts[index], url.path) == (200, b'hello')
    log_text = (root / "server.log").read_text()
    assert '"route"="upload"' in log_text, "custom upload route missing from HTTP diagnostics"
    assert all(token not in log_text for _, token in slots), "upload credentials leaked to logs"
    if shared:
        for second_path in (mounts[0], mounts[0] + '/nested', '/'):
            ambiguous = copy.deepcopy(config)
            ambiguous['hosts'][components[1]]['options']['http_paths']['file_share'] = second_path
            path.write_text(json.dumps(ambiguous))
            result = subprocess.run([binary, 'serve', str(path), '--experimental'], capture_output=True, text=True, timeout=8)
            assert result.returncode != 0 and 'ambiguous HTTP upload components' in result.stderr, result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default=str(BIN))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='xmpp-upload-multi-') as temporary:
        for shared in (False, True):
            exercise(str(Path(args.binary).resolve()), Path(temporary) / str(shared), shared)
    print('PASS: multiple upload hosts/shared-host paths, discovery, quotas, JWT isolation, persistence, transport composition and conflict validation')


if __name__ == '__main__':
    main()
