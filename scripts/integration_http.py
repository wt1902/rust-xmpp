#!/usr/bin/env python3
"""Real binary integration: TLS WebSocket/BOSH auth, roster/chat and XEP-0363.
Requires Python websockets and openssl. Uses temporary data and loopback ports only.
"""
import argparse
import asyncio
import base64
import json
import http.client
import urllib.parse
import pathlib
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import websockets

CLIENT = 'jabber:client'
BIND = 'urn:ietf:params:xml:ns:xmpp-bind'
BOSH = 'http://jabber.org/protocol/httpbind'
SASL = 'urn:ietf:params:xml:ns:xmpp-sasl'
UPLOAD = 'urn:xmpp:http:upload:0'
SM = 'urn:xmpp:sm:3'
FRAMING = 'urn:ietf:params:xml:ns:xmpp-framing'


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def plain(user):
    return base64.b64encode(f'\0{user}\0integration-password'.encode()).decode()


class BoshClient:
    def __init__(self, url, context):
        self.url, self.context, self.sid, self.rid = url, context, None, 100

    def send(self, stanza='', **attributes):
        attributes.update({'xmlns': BOSH, 'rid': str(self.rid)})
        self.rid += 1
        if self.sid:
            attributes['sid'] = self.sid
        # Values are controlled constants in this integration fixture.
        attrs = ' '.join(f'{k}="{v}"' for k, v in attributes.items())
        request = urllib.request.Request(self.url, f'<body {attrs}>{stanza}</body>'.encode(),
                                         headers={'Content-Type': 'text/xml'}, method='POST')
        with urllib.request.urlopen(request, context=self.context, timeout=8) as response:
            xml = response.read()
        body = ET.fromstring(xml)
        assert body.get('type') != 'terminate' or attributes.get('type') == 'terminate', xml
        if body.get('sid'):
            self.sid = body.get('sid')
        return body

    def login(self, user):
        first = self.send(to='localhost', wait='1', hold='1', ver='1.11')
        assert first.find(f'.//{{{SASL}}}mechanism') is not None, ET.tostring(first)
        auth = self.send(f'<auth xmlns="{SASL}" mechanism="PLAIN">{plain(user)}</auth>')
        assert auth.find(f'{{{SASL}}}success') is not None, ET.tostring(auth)
        self.send(**{'xmlns:xmpp': 'urn:xmpp:xbosh', 'xmpp:restart': 'true', 'to': 'localhost'})
        bound = self.send(f'<iq xmlns="{CLIENT}" type="set" id="bind"><bind xmlns="{BIND}"><resource>bosh</resource></bind></iq>')
        jid = bound.find(f'.//{{{BIND}}}jid')
        assert jid is not None and jid.text == f'{user}@localhost/bosh', ET.tostring(bound)

    def enable_resume(self):
        body = self.send(f'<enable xmlns="{SM}" resume="true"/>')
        enabled = body.find(f'{{{SM}}}enabled')
        assert enabled is not None and enabled.get('id') and enabled.get('resume') in ('true', '1'), ET.tostring(body)


async def ws_receive(ws, predicate, timeout=8):
    async with asyncio.timeout(timeout):
        while True:
            raw = await ws.recv()
            node = ET.fromstring(raw)
            if predicate(node):
                return node


async def ws_login(ws, user):
    opening = f'<open xmlns="{FRAMING}" to="localhost" version="1.0"/>'
    await ws.send(opening)
    features = await ws_receive(ws, lambda n: n.tag.endswith('}features'))
    assert features.find(f'.//{{{SASL}}}mechanism') is not None
    await ws.send(f'<auth xmlns="{SASL}" mechanism="PLAIN">{plain(user)}</auth>')
    await ws_receive(ws, lambda n: n.tag == f'{{{SASL}}}success')
    await ws.send(opening)
    await ws_receive(ws, lambda n: n.tag.endswith('}features'))
    await ws.send(f'<iq xmlns="{CLIENT}" type="set" id="bind"><bind xmlns="{BIND}"><resource>websocket</resource></bind></iq>')
    result = await ws_receive(ws, lambda n: n.tag == f'{{{CLIENT}}}iq' and n.get('id') == 'bind')
    jid = result.find(f'.//{{{BIND}}}jid')
    assert result.get('type') == 'result' and jid is not None and jid.text == f'{user}@localhost/websocket', ET.tostring(result)


async def ws_enable_resume(ws):
    await ws.send(f'<enable xmlns="{SM}" resume="true"/>')
    enabled = await ws_receive(ws, lambda n: n.tag in (f'{{{SM}}}enabled', f'{{{SM}}}failed'))
    assert enabled.tag == f'{{{SM}}}enabled' and enabled.get('id') and enabled.get('resume') in ('true', '1'), ET.tostring(enabled)


async def exercise(https_port, context, custom_upload=False):
    endpoint = f'https://localhost:{https_port}'
    bosh = BoshClient(endpoint + '/http-bind', context)
    await asyncio.to_thread(bosh.login, 'alice')
    async with websockets.connect(f'wss://localhost:{https_port}/xmpp-websocket', ssl=context,
                                  subprotocols=['xmpp'], open_timeout=8) as ws:
        await ws_login(ws, 'bob')
        await ws.send('<inactive xmlns="urn:xmpp:csi:0"/>')
        await ws.send('<active xmlns="urn:xmpp:csi:0"/>')
        await ws.send(f'<iq xmlns="{CLIENT}" type="get" id="after-csi" to="localhost"><ping xmlns="urn:xmpp:ping"/></iq>')
        await ws_receive(ws, lambda n: n.get('id') == 'after-csi' and n.get('type') == 'result')
        namespaced = await asyncio.to_thread(bosh.send, '<c:iq type="get" id="inherited-ns" to="localhost"><ping xmlns="urn:xmpp:ping"/></c:iq>', **{'xmlns:c': CLIENT})
        assert any(n.get('id') == 'inherited-ns' and n.get('type') == 'result' for n in namespaced), ET.tostring(namespaced)
        # Both become available before ordinary bare-JID routing.
        await ws.send(f'<presence xmlns="{CLIENT}"/>')
        await asyncio.to_thread(bosh.send, f'<presence xmlns="{CLIENT}"/>')
        roster = await asyncio.to_thread(bosh.send, f'<iq xmlns="{CLIENT}" type="set" id="r1"><query xmlns="jabber:iq:roster"><item jid="bob@localhost" name="Bob"/></query></iq>')
        assert any(n.get('id') == 'r1' and n.get('type') == 'result' for n in roster), ET.tostring(roster)
        roster = await asyncio.to_thread(bosh.send, f'<iq xmlns="{CLIENT}" type="get" id="r2"><query xmlns="jabber:iq:roster"/></iq>')
        assert roster.find('.//{jabber:iq:roster}item').get('jid') == 'bob@localhost'
        await asyncio.to_thread(bosh.send, f'<message xmlns="{CLIENT}" to="bob@localhost" type="chat" id="hello"><body>from-bosh</body></message>')
        incoming = await ws_receive(ws, lambda n: n.tag == f'{{{CLIENT}}}message' and n.get('id') == 'hello')
        assert incoming.find(f'{{{CLIENT}}}body').text == 'from-bosh'
        await ws.send(f'<message xmlns="{CLIENT}" to="alice@localhost" type="chat" id="reply"><body>from-websocket</body></message>')
        poll = await asyncio.to_thread(bosh.send)
        assert any(n.get('id') == 'reply' for n in poll), ET.tostring(poll)
        await ws.send(f'<iq xmlns="{CLIENT}" type="get" id="ws-roster"><query xmlns="jabber:iq:roster"/></iq>')
        await ws_receive(ws, lambda n: n.tag == f'{{{CLIENT}}}iq' and n.get('id') == 'ws-roster' and n.get('type') == 'result')
        data = b'actual integrated HTTP upload\n' * 16384
        slots = await asyncio.to_thread(bosh.send, f'<iq xmlns="{CLIENT}" to="upload.localhost" type="get" id="slot"><request xmlns="{UPLOAD}" filename="sample.txt" size="{len(data)}" content-type="text/plain"/></iq>')
        slot = slots.find(f'.//{{{UPLOAD}}}slot')
        assert slot is not None, ET.tostring(slots)
        put = slot.find(f'{{{UPLOAD}}}put')
        if custom_upload:
            assert urllib.parse.urlsplit(put.get('url')).path.startswith('/custom/upload-upload.localhost/'), put.get('url')
        authorization = put.find(f'{{{UPLOAD}}}header').text
        request = urllib.request.Request(put.get('url'), data, headers={'Authorization': authorization}, method='PUT')
        def transfer():
            with urllib.request.urlopen(request, context=context, timeout=8) as response:
                assert response.status == 201
            with urllib.request.urlopen(slot.find(f'{{{UPLOAD}}}get').get('url'), context=context, timeout=8) as response:
                assert response.read() == data
            parsed = urllib.parse.urlsplit(put.get('url'))
            duplicate = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=8)
            duplicate.putrequest('PUT', parsed.path)
            duplicate.putheader('Authorization', authorization)
            duplicate.putheader('Content-Length', str(len(data)))
            duplicate.endheaders()
            # Server rejects a completed slot before accepting its body.
            assert duplicate.getresponse().status == 409
            duplicate.close()
        await asyncio.to_thread(transfer)
        # Graceful transport shutdown must release even a resumable SM resource.
        # kick_new makes an accidentally hibernating old resource fail this bind.
        await asyncio.to_thread(bosh.enable_resume)
        terminated = await asyncio.to_thread(bosh.send, type='terminate')
        assert terminated.get('type') == 'terminate', ET.tostring(terminated)
        again = BoshClient(endpoint + '/http-bind', context)
        await asyncio.to_thread(again.login, 'alice')
        await asyncio.to_thread(again.enable_resume)
        ping = await asyncio.to_thread(again.send, f'<iq xmlns="{CLIENT}" type="get" id="bosh-relogin"><ping xmlns="urn:xmpp:ping"/></iq>')
        assert any(n.get('id') == 'bosh-relogin' and n.get('type') == 'result' for n in ping), ET.tostring(ping)
        await asyncio.to_thread(again.send, type='terminate')
        await ws_enable_resume(ws)
        await ws.send(f'<close xmlns="{FRAMING}"/>')
        await ws_receive(ws, lambda n: n.tag == f'{{{FRAMING}}}close')
    async with websockets.connect(f'wss://localhost:{https_port}/xmpp-websocket', ssl=context,
                                  subprotocols=['xmpp'], open_timeout=8) as ws:
        await ws_login(ws, 'bob')
        await ws_enable_resume(ws)
        await ws.send(f'<iq xmlns="{CLIENT}" type="get" id="ws-relogin"><ping xmlns="urn:xmpp:ping"/></iq>')
        await ws_receive(ws, lambda n: n.get('id') == 'ws-relogin' and n.get('type') == 'result')
        await ws.send(f'<close xmlns="{FRAMING}"/>')
        await ws_receive(ws, lambda n: n.tag == f'{{{FRAMING}}}close')
    print('PASS: integrated WSS + HTTPS BOSH SASL/bind, CSI, inherited BOSH namespaces, roster, bidirectional chat, upload IQ/PUT/GET/reuse, graceful SM close and same-resource relogin under kick_new')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=str(pathlib.Path(__file__).resolve().parents[1] / 'target/release/rust-xmpp'))
    parser.add_argument('--custom-upload-path', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rust-xmpp-http-integration-') as work:
        work = pathlib.Path(work)
        cert, key = work / 'cert.pem', work / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:upload.localhost',
                        '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        tcp_port, http_port, https_port = port(), port(), port()
        config = {'global': {'data_path': str(work / 'data'), 'interfaces': ['127.0.0.1'], 'http_interfaces': ['127.0.0.1'],
                            'https_interfaces': ['127.0.0.1'], 'c2s_ports': [tcp_port], 's2s_ports': [],
                            'http_ports': [http_port], 'https_ports': [https_port], 'allow_registration': False,
                            'consider_bosh_secure': True, 'consider_websocket_secure': True,
                            'modules_enabled': ['tls', 'saslauth', 'disco', 'roster', 'websocket', 'bosh', 'csi_simple', 'smacks', 'ping'],
                            'ssl': {'certificate': str(cert), 'key': str(key)}},
                  'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256', 'conflict_resolve': 'kick_new'}},
                            'upload.localhost': {'component': 'http_file_share', 'options': {'http_host': 'localhost', 'http_external_url': f'https://localhost:{https_port}',
                                 'http_file_share_secret': 'integration-test-secret', 'http_file_share_size_limit': 1024*1024,
                                 'http_file_share_daily_quota': 10*1024*1024}}}}
        if args.custom_upload_path:
            config['hosts']['upload.localhost']['options']['http_paths'] = {'file_share': '/custom/upload-$host'}
        path = work / 'config.json'
        path.write_text(json.dumps(config))
        for user in ['alice', 'bob']:
            subprocess.run([args.binary, 'create-user', str(path), user, '--password-stdin'], input='integration-password\n', text=True, check=True, capture_output=True)
        log = open(work / 'server.log', 'w+')
        process = subprocess.Popen([args.binary, 'serve', str(path), '--experimental'], stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('server exited during startup')
                try:
                    with socket.create_connection(('127.0.0.1', tcp_port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('server startup timed out')
            context = ssl.create_default_context(cafile=str(cert))
            asyncio.run(exercise(https_port, context, args.custom_upload_path))
            if args.custom_upload_path:
                print('PASS: configured upload HTTP path with $host through integrated listener')
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
            log.close()


if __name__ == '__main__':
    main()
