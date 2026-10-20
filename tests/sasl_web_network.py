#!/usr/bin/env python3
"""Real WSS SCRAM regression: SASL1/SASL2, GS2 y, SSDP and session use.

Requires websockets and openssl. Runs an isolated loopback-only server.
Usage: python3 tests/sasl_web_network.py [--binary target/release/rust-xmpp]
"""
import argparse
import asyncio
import base64
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

import websockets

CLIENT = 'jabber:client'
SASL = 'urn:ietf:params:xml:ns:xmpp-sasl'
SASL2 = 'urn:xmpp:sasl:2'
CB = 'urn:xmpp:sasl-cb:0'
BIND = 'urn:ietf:params:xml:ns:xmpp-bind'
FRAMING = 'urn:ietf:params:xml:ns:xmpp-framing'
PASSWORD = 'integration-password'
OPEN = f'<open xmlns="{FRAMING}" to="localhost" version="1.0"/>'


def b64(data):
    return base64.b64encode(data).decode()


def port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


async def receive(ws, predicate):
    async with asyncio.timeout(8):
        while True:
            node = ET.fromstring(await ws.recv())
            assert node.tag not in (f'{{{SASL}}}failure', f'{{{SASL2}}}failure'), ET.tostring(node)
            if predicate(node):
                return node


async def authenticate(ws, sasl2):
    await ws.send(OPEN)
    features = await receive(ws, lambda n: n.tag.endswith('}features'))
    assert features.find(f'.//{{{CB}}}sasl-channel-binding') is None, ET.tostring(features)
    assert features.find(f'.//{{{CB}}}channel-binding') is None, ET.tostring(features)
    sasl1_mechs = sorted(n.text for n in features.findall(f'{{{SASL}}}mechanisms/{{{SASL}}}mechanism'))
    sasl2_mechs = sorted(n.text for n in features.findall(f'{{{SASL2}}}authentication/{{{SASL2}}}mechanism'))
    for mechs in (sasl1_mechs, sasl2_mechs):
        assert mechs == ['PLAIN', 'SCRAM-SHA-256'], mechs
        assert not any(m.endswith('-PLUS') for m in mechs), mechs
    mechs = sasl2_mechs if sasl2 else sasl1_mechs
    ns = SASL2 if sasl2 else SASL
    nonce = secrets.token_hex(18)
    bare = f'n=alice,r={nonce}'
    # Client supports CB but WSS cannot expose the TLS binding to XMPP.
    gs2 = b'y,,'
    initial = b64(gs2 + bare.encode())
    if sasl2:
        await ws.send(f'<authenticate xmlns="{ns}" mechanism="SCRAM-SHA-256"><initial-response>{initial}</initial-response></authenticate>')
    else:
        await ws.send(f'<auth xmlns="{ns}" mechanism="SCRAM-SHA-256">{initial}</auth>')
    challenge = await receive(ws, lambda n: n.tag == f'{{{ns}}}challenge')
    server_first = base64.b64decode(challenge.text, validate=True).decode()
    attrs = dict(item.split('=', 1) for item in server_first.split(','))
    assert attrs['r'].startswith(nonce) and len(attrs['r']) > len(nonce), server_first
    # No CB advertisement means the SSDP input ends after the mechanism list;
    # appending even an empty CB separator (0x1f) produces a different hash.
    ssdp_source = '\x1e'.join(mechs).encode()
    expected_ssdp = b64(hashlib.sha256(ssdp_source).digest())
    assert attrs.get('h') == expected_ssdp, (attrs.get('h'), expected_ssdp)
    assert attrs['h'] != b64(hashlib.sha256(ssdp_source + b'\x1f').digest())
    final_bare = f"c={b64(gs2)},r={attrs['r']}"
    auth_message = f'{bare},{server_first},{final_bare}'.encode()
    salted = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode(), base64.b64decode(attrs['s'], validate=True), int(attrs['i']))
    mac = lambda key, data: hmac.digest(key, data, 'sha256')
    client_key = mac(salted, b'Client Key')
    signature = mac(hashlib.sha256(client_key).digest(), auth_message)
    proof = bytes(a ^ b for a, b in zip(client_key, signature))
    final = final_bare + ',p=' + b64(proof)
    await ws.send(f'<response xmlns="{ns}">{b64(final.encode())}</response>')
    success = await receive(ws, lambda n: n.tag == f'{{{ns}}}success')
    data = success.find(f'{{{SASL2}}}additional-data').text if sasl2 else success.text
    expected_signature = 'v=' + b64(mac(mac(salted, b'Server Key'), auth_message))
    assert base64.b64decode(data, validate=True).decode() == expected_signature
    if sasl2:
        assert success.find(f'{{{SASL2}}}authorization-identifier').text == 'alice@localhost'
    else:
        await ws.send(OPEN)
    await receive(ws, lambda n: n.tag.endswith('}features'))
    resource = 'sasl2-wss' if sasl2 else 'sasl1-wss'
    await ws.send(f'<iq xmlns="{CLIENT}" type="set" id="bind"><bind xmlns="{BIND}"><resource>{resource}</resource></bind></iq>')
    bound = await receive(ws, lambda n: n.get('id') == 'bind')
    assert bound.get('type') == 'result', ET.tostring(bound)
    assert bound.find(f'.//{{{BIND}}}jid').text == f'alice@localhost/{resource}'
    await ws.send(f'<iq xmlns="{CLIENT}" type="get" id="ping" to="localhost"><ping xmlns="urn:xmpp:ping"/></iq>')
    pong = await receive(ws, lambda n: n.get('id') == 'ping')
    assert pong.get('type') == 'result', ET.tostring(pong)
    await ws.send(f'<close xmlns="{FRAMING}"/>')
    await receive(ws, lambda n: n.tag == f'{{{FRAMING}}}close')


async def exercise(https_port, context):
    for sasl2 in (False, True):
        async with websockets.connect(f'wss://localhost:{https_port}/xmpp-websocket', ssl=context,
                                      subprotocols=['xmpp'], open_timeout=8) as ws:
            await authenticate(ws, sasl2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default=str(Path(__file__).resolve().parents[1] / 'target/release/rust-xmpp'))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='xmpp-sasl-web-') as temporary:
        root = Path(temporary)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True)
        tcp_port, https_port = port(), port()
        config = {'global': {'data_path': str(root / 'data'), 'interfaces': ['127.0.0.1'],
                            'https_interfaces': ['127.0.0.1'], 'c2s_ports': [tcp_port], 's2s_ports': [],
                            'http_ports': [], 'https_ports': [https_port], 'consider_websocket_secure': True,
                            'modules_enabled': ['tls', 'websocket', 'sasl2', 'saslauth', 'sasl_ssdp', 'ping'],
                            'ssl': {'certificate': str(cert), 'key': str(key)}},
                  'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-256'}}}}
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        subprocess.run([args.binary, 'create-user', str(path), 'alice', '--password-stdin'],
                       input=PASSWORD + '\n', text=True, check=True, capture_output=True)
        with (root / 'server.log').open('w+') as log:
            server = subprocess.Popen([args.binary, 'serve', str(path), '--experimental'], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    assert server.poll() is None, 'server stopped during startup'
                    try:
                        with socket.create_connection(('127.0.0.1', tcp_port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError('server startup timed out')
                asyncio.run(exercise(https_port, ssl.create_default_context(cafile=str(cert))))
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
    print('PASS: WSS SCRAM-SHA-256 SASL1/SASL2 with GS2 y, absent CB/PLUS, SSDP without CB separator, server signatures, bind and ping')


if __name__ == '__main__':
    main()
