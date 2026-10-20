#!/usr/bin/env python3
"""Real TCP/TLS integration test; stdlib only; requires make-demo.sh first."""
import base64
import hashlib
import hmac
import re
import signal
import socket
import ssl
import subprocess
import time
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
STREAM="<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>"
class Client:
    def __init__(self):
        self.sock=socket.create_connection(('127.0.0.1',55222),timeout=5)
        self.buf=b''
        self.send(STREAM)
        assert b'<required' in self.until(b'</stream:features>')
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        assert b'proceed' in self.until(b'/>')
        ctx=ssl.create_default_context(cafile=str(ROOT/'demo/cert.pem'))
        self.sock=ctx.wrap_socket(self.sock,server_hostname='localhost')
        self.send(STREAM)
        assert b'PLAIN' in self.until(b'</stream:features>')
    def send(self,s): self.sock.sendall(s.encode())
    def until(self,mark):
        while mark not in self.buf:
            chunk=self.sock.recv(65536)
            if not chunk: raise RuntimeError('unexpected EOF')
            self.buf+=chunk
        end=self.buf.index(mark)+len(mark)
        out,self.buf=self.buf[:end],self.buf[end:]
        return out
    def auth(self,user,password,fail=False):
        encoded=base64.b64encode(('\0'+user+'\0'+password).encode()).decode()
        self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{encoded}</auth>")
        if fail:
            assert b'not-authorized' in self.until(b'</failure>');return
        assert b'success' in self.until(b'/>')
        self.send(STREAM)
        assert b'xmpp-bind' in self.until(b'</stream:features>')
        self.send("<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>smoke</resource></bind></iq>")
        assert f'{user}@localhost/smoke'.encode() in self.until(b'</iq>')
    def close(self): self.sock.close()

def account_hash_crosscheck():
    record=(ROOT/'demo/data/localhost/accounts/alice.dat').read_text()
    def value(k): return re.search(rf'{k}\s*=\s*"([^"]+)"',record).group(1)
    iterations=int(re.search(r'iteration_count\s*=\s*(\d+)',record).group(1))
    salted=hashlib.pbkdf2_hmac('sha256',b'alice-test-only',value('salt').encode(),iterations)
    stored=hashlib.sha256(hmac.new(salted,b'Client Key','sha256').digest()).hexdigest()
    server=hmac.new(salted,b'Server Key','sha256').hexdigest()
    assert stored==value('stored_key') and server==value('server_key')

p=subprocess.Popen([str(ROOT/'target/release/rust-xmpp'),'serve',str(ROOT/'demo/config.toml'),'--experimental'],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
clients=[]
try:
    for _ in range(100):
        if p.poll() is not None: raise RuntimeError(p.stderr.read().decode())
        try:
            probe=socket.create_connection(('127.0.0.1',55222),timeout=.1);probe.close();break
        except OSError: time.sleep(.05)
    else: raise RuntimeError('server did not start')
    account_hash_crosscheck()
    a=Client();clients.append(a)
    a.auth('alice','wrong',fail=True);a.auth('alice','alice-test-only')
    b=Client();clients.append(b);b.auth('bob','bob-test-only')
    a.send("<presence/>");b.send("<presence/>")
    b.send("<iq type='get' id='ready'><ping xmlns='urn:xmpp:ping'/></iq>");b.until(b'</iq>')
    a.send("<iq type='get' id='p1'><ping xmlns='urn:xmpp:ping'/></iq>")
    assert b"type='result'" in a.until(b'</iq>')
    a.send("<message type='chat' id='m1' from='admin@localhost' to='bob@localhost'><body>Hello &amp; привет</body></message>")
    xml=b.until(b'</message>');m=ET.fromstring(xml)
    assert m.attrib['from']=='alice@localhost/smoke'
    assert m.find('{jabber:client}body').text=='Hello & привет'
    b.send("<message type='chat' id='m2' to='alice@localhost/smoke'><body>Reply</body></message>")
    assert ET.fromstring(a.until(b'</message>')).find('{jabber:client}body').text=='Reply'
    # Forwarding keeps extension namespace declarations from the stanza root.
    a.send("<message xmlns:ext='urn:test:extension' xml:lang='ru' to='bob@localhost'><ext:payload>data</ext:payload></message>")
    extension=ET.fromstring(b.until(b'</message>'))
    assert extension.find('{urn:test:extension}payload').text=='data'
    assert extension.attrib['{http://www.w3.org/XML/1998/namespace}lang']=='ru'
    a.send("<message id='offline' to='missing@localhost'><body>test</body></message>")
    assert b'service-unavailable' in a.until(b'</message>')
    a.send("<iq type='get' id='mam'><query xmlns='urn:xmpp:mam:2'/></iq>")
    assert b'service-unavailable' in a.until(b'</iq>')
    # Passwords must never be accepted on a plaintext stream.
    raw=socket.create_connection(('127.0.0.1',55222),timeout=3)
    raw.sendall(STREAM.encode());raw.recv(65536)
    raw.sendall(b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>eA==</auth>")
    while True:
        chunk=raw.recv(65536)
        assert b'<success' not in chunk
        if not chunk: break
    raw.close()
    print('PASS: TLS certificate validation, login, wrong-password rejection, independent account hash check, binding, ping, bidirectional chat, sender rewriting, offline error, unsupported MAM error, plaintext auth rejection')
finally:
    for c in clients:c.close()
    p.send_signal(signal.SIGINT)
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()
