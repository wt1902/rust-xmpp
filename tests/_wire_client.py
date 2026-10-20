#!/usr/bin/env python3
"""Independent TCP integration tests for integrated Rust XMPP modules (isolated data)."""
import base64, json, signal, socket, ssl, subprocess, tempfile, time
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
BIN=ROOT/'target/release/rust-xmpp'
C='jabber:client'; S='http://etherx.jabber.org/streams'
OPEN=f"<stream:stream xmlns='{C}' xmlns:stream='{S}' to='localhost' version='1.0'>"
def local(e):return e.tag.split('}')[-1]
class Client:
 def __init__(self,port,cert,user,password,resource='main',bind=True):
  self.sock=socket.create_connection(('127.0.0.1',port),timeout=5);self.buf=b'';self.queue=[];self.user=user;self.port=port;self.cert=cert;self.password=password
  self.send(OPEN);self.until(b'</stream:features>');self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");self.until(b'/>')
  self.sock=ssl.create_default_context(cafile=str(cert)).wrap_socket(self.sock,server_hostname='localhost');self.send(OPEN);self.until(b'</stream:features>')
  payload=base64.b64encode(f'\0{user}\0{password}'.encode()).decode();self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{payload}</auth>");self.until(b'/>');self.send(OPEN);self.post_auth_features=self.until(b'</stream:features>')
  self.jid=f'{user}@localhost/{resource}'
  if bind:self.send(f"<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>");self.iq('bind')
 def send(self,s):self.sock.sendall(s.encode())
 def until(self,mark):
  while mark not in self.buf:
   chunk=self.sock.recv(65536)
   if not chunk:raise RuntimeError('EOF '+repr(self.buf))
   self.buf+=chunk
  end=self.buf.index(mark)+len(mark);out,self.buf=self.buf[:end],self.buf[end:];return out
 def read(self):
  parser=ET.XMLPullParser(events=('start','end'));parser.feed(f"<root xmlns='{C}' xmlns:stream='{S}'>");list(parser.read_events());depth=0
  while True:
   if not self.buf:
    self.buf=self.sock.recv(65536)
    if not self.buf:raise RuntimeError('EOF')
   byte,self.buf=self.buf[:1],self.buf[1:];parser.feed(byte)
   # Expat reparse deferral may withhold a short end-tag when fed bytewise.
   # Flush at markup boundaries so an empty IQ result needs no following stanza.
   if byte==b'>' and hasattr(parser,'flush'):parser.flush()
   for event,node in parser.read_events():
    depth+=1 if event=='start' else -1
    if event=='end' and depth==0:return node
 def take(self,predicate):
  for i,e in enumerate(self.queue):
   if predicate(e):return self.queue.pop(i)
  while True:
   e=self.read()
   if predicate(e):return e
   self.queue.append(e)
 def iq(self,id,error=False):
  e=self.take(lambda e:local(e)=='iq' and e.get('id')==id and e.get('type') in ('result','error'))
  assert e.get('type')==('error' if error else 'result'),ET.tostring(e)
  return e
 def sync(self):self.send("<iq type='get' id='sync'><ping xmlns='urn:xmpp:ping'/></iq>");self.iq('sync')
 def available(self):self.send('<presence/>');self.sync()
 def body(self,text):return self.take(lambda e:local(e)=='message' and any(local(c)=='body' and c.text==text for c in e))
 def close(self):self.sock.close()

