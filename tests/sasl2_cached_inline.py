#!/usr/bin/env python3
"""Cached Conversations/monocles SASL2 inline requests over real STARTTLS.

Usage: python3 tests/sasl2_cached_inline.py BINARY [--expect-070-failure]
Independent SCRAM-SHA-1 proof and server-signature validation; no client
assertion that current features advertise the previously cached Bind2 feature.
"""
import base64
import hashlib
import hmac
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from android_sasl_network import Connection, SASL, SASL2, b64

BIND2 = 'urn:xmpp:bind:0'
SM = 'urn:xmpp:sm:3'
CB = 'urn:xmpp:sasl-cb:0'
CACHED_BIND = (f"<bind xmlns='{BIND2}'><tag>monocles chat</tag>"
               "<enable xmlns='urn:xmpp:carbons:2'/>"
               f"<enable xmlns='{SM}' resume='true'/></bind>")
CACHED_RESUME = f"<resume xmlns='{SM}' previd='previous-server-stream' h='0'/>"


def auth(client, mechanism, inline, password='secret', ssdp=False):
    parent = client.features.find('.//{' + SASL2 + '}authentication')
    mechanisms = [n.text for n in parent.findall('{' + SASL2 + '}mechanism')]
    assert mechanism in mechanisms, mechanisms
    if mechanism == 'PLAIN':
        initial = b64(('\0alice\0' + password).encode())
    else:
        gs2 = 'n,,'
        bare = 'n=alice,r=independent-cached-inline-nonce'
        initial = b64((gs2 + bare).encode())
    client.send(f"<authenticate xmlns='{SASL2}' mechanism='{mechanism}'>"
                f"<initial-response>{initial}</initial-response>"
                "<user-agent id='d4565fa7-4d72-4749-b3d3-740edbf87770'>"
                "<software>monocles chat</software></user-agent>"
                f"{inline}</authenticate>")
    result = client.stanza()
    if mechanism == 'PLAIN' or result.tag != '{' + SASL2 + '}challenge':
        return result
    first = base64.b64decode(result.text).decode()
    attrs = dict(item.split('=', 1) for item in first.split(','))
    if ssdp:
        bindings = [n.get('type') for n in client.features.findall('.//{' + CB + '}channel-binding')]
        protected = '\x1e'.join(sorted(mechanisms)) + '\x1f' + '\x1e'.join(sorted(bindings))
        assert attrs['h'] == b64(hashlib.sha1(protected.encode()).digest())
    else:
        assert 'h' not in attrs
    assert attrs['r'].startswith('independent-cached-inline-nonce')
    assert int(attrs['i']) >= 4096
    final = 'c=' + b64(gs2.encode()) + ',r=' + attrs['r']
    salted = hashlib.pbkdf2_hmac('sha1', password.encode(), base64.b64decode(attrs['s']), int(attrs['i']))
    mac = lambda key, data: hmac.new(key, data, hashlib.sha1).digest()
    key = mac(salted, b'Client Key')
    transcript = (bare + ',' + first + ',' + final).encode()
    signature = mac(hashlib.sha1(key).digest(), transcript)
    proof = bytes(a ^ b for a, b in zip(key, signature))
    client.send(f"<response xmlns='{SASL2}'>{b64((final + ',p=' + b64(proof)).encode())}</response>")
    result = client.stanza()
    if result.tag == '{' + SASL2 + '}success':
        expected = 'v=' + b64(mac(mac(salted, b'Server Key'), transcript))
        assert base64.b64decode(result.findtext('{' + SASL2 + '}additional-data')).decode() == expected
    return result


def finish(client, result, bound):
    assert result.tag == '{' + SASL2 + '}success', ET.tostring(result)
    jid = result.findtext('{' + SASL2 + '}authorization-identifier')
    assert (result.find('{' + BIND2 + '}bound') is not None) == bound
    features = client.until(b'</stream:features>')
    if bound:
        assert jid.startswith('alice@localhost/monocles chat/'), jid
        assert b'xmpp-bind' not in features
    else:
        assert jid == 'alice@localhost', jid
        assert b'xmpp-bind' in features
        client.send("<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>cached-fallback</resource></bind></iq>")
        reply = client.stanza()
        assert reply.get('type') == 'result', ET.tostring(reply)
        assert reply.findtext('.//{urn:ietf:params:xml:ns:xmpp-bind}jid') == 'alice@localhost/cached-fallback'
    client.send("<iq type='get' to='localhost' id='ping'><ping xmlns='urn:xmpp:ping'/></iq>")
    reply = client.stanza()
    assert reply.get('id') == 'ping' and reply.get('type') == 'result', ET.tostring(reply)


def run(binary, old=False):
    cases = [('bind2-disabled', False, True), ('bind2-enabled', True, True), ('sm-disabled', False, False)]
    for label, bind2, sm in cases:
        for ssdp in (False, True):
            with tempfile.TemporaryDirectory(prefix='xmpp-cached-inline-') as tmp:
                root = Path(tmp)
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 0))
                    port = probe.getsockname()[1]
                modules = ['tls', 'saslauth', 'sasl2', 'carbons', 'ping']
                modules += (['smacks'] if sm else []) + (['sasl2_bind2'] if bind2 else []) + (['sasl_ssdp'] if ssdp else [])
                cfg = {'global': {'data_path': str(root/'data'), 'interfaces': ['127.0.0.1'], 'c2s_ports': [port], 'http_ports': [], 'https_ports': [], 's2s_ports': [], 'modules_enabled': modules}, 'hosts': {'localhost': {'options': {'authentication': 'internal_hashed', 'password_hash': 'SHA-1', 'ssl': {'key': str(root/'key.pem'), 'certificate': str(root/'cert.pem')}}}}}
                config = root/'config.json'
                config.write_text(json.dumps(cfg))
                subprocess.run([binary, 'create-user', str(config), 'alice', '--password-stdin'], input='secret\n', text=True, check=True, capture_output=True)
                with (root/'server.log').open('w+') as log:
                    server = subprocess.Popen([binary, 'serve', str(config), '--experimental'], stdout=log, stderr=log)
                    try:
                        for _ in range(100):
                            assert server.poll() is None, 'server stopped'
                            try:
                                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                    break
                            except OSError:
                                time.sleep(.05)
                        else:
                            raise AssertionError('server did not start')
                        inline = CACHED_BIND + (CACHED_RESUME if not sm else '')
                        for mechanism in ('SCRAM-SHA-1', 'PLAIN'):
                            for wrong in (False, True):
                                c = Connection(port, root/'cert.pem', ssl.TLSVersion.TLSv1_3)
                                try:
                                    advertised = c.features.find('.//{' + BIND2 + '}bind')
                                    assert (advertised is not None) == bind2
                                    result = auth(c, mechanism, inline, 'wrong' if wrong else 'secret', ssdp)
                                    if old:
                                        assert result.tag == '{' + SASL2 + '}failure', ET.tostring(result)
                                        assert result.find('{' + SASL + '}malformed-request') is not None
                                        print('PASS: reproduced 0.7.0 cached Bind2 rejection before SASL')
                                        return
                                    if wrong:
                                        assert result.tag == '{' + SASL2 + '}failure', ET.tostring(result)
                                        assert result.find('{' + SASL + '}not-authorized') is not None
                                        assert result.find('{' + BIND2 + '}bound') is None
                                    else:
                                        finish(c, result, bind2)
                                finally:
                                    c.sock.close()
                        log.flush()
                        log.seek(0)
                        logs = log.read()
                        if not bind2:
                            assert 'inline-request-ignored' in logs and 'bind2-disabled' in logs, logs
                        if not sm:
                            assert 'sm-disabled' in logs, logs
                        assert 'inline-request-malformed' not in logs, logs
                        print(f'PASS: {label}, SSDP={ssdp}, SCRAM-SHA-1/PLAIN success and wrong-password rejection')
                    except BaseException:
                        log.flush()
                        log.seek(0)
                        print(log.read())
                        raise
                    finally:
                        server.terminate()
                        try:
                            server.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            server.kill()
                            server.wait()


if __name__ == '__main__':
    run(str(Path(sys.argv[1]).resolve()), '--expect-070-failure' in sys.argv[2:])
