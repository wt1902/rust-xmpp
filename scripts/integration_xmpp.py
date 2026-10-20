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
  payload=base64.b64encode(f'\0{user}\0{password}'.encode()).decode();self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{payload}</auth>");self.until(b'/>');self.send(OPEN);self.until(b'</stream:features>')
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

with tempfile.TemporaryDirectory(prefix='rust-xmpp-network-') as folder:
 path=Path(folder);port=socket.socket();port.bind(('127.0.0.1',0));portnum=port.getsockname()[1];port.close()
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',str(path/'key.pem'),'-out',str(path/'cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 modules=['tls','saslauth','sasl2','sasl_ssdp','roster','disco','private','vcard_legacy','blocklist','mam','pep','bookmarks','smacks','carbons','ping','version','register','cloud_notify','time','uptime','csi_simple']
 config={'global':{'data_path':str(path/'data'),'interfaces':['127.0.0.1'],'c2s_ports':[portnum],'s2s_ports':[],'http_ports':[],'https_ports':[],'allow_registration':False,'default_archive_policy':True,'modules_enabled':modules},'hosts':{'localhost':{'options':{'authentication':'internal_hashed','password_hash':'SHA-256','ssl':{'key':str(path/'key.pem'),'certificate':str(path/'cert.pem')}}},'conference.localhost':{'component':'muc','options':{'modules_enabled':['muc_mam'],'muc_room_default_persistent':True}},'pubsub.localhost':{'component':'pubsub','options':{'restrict_node_creation':False}}}}
 (path/'config.json').write_text(json.dumps(config))
 for user in ['alice','bob']:
  subprocess.run([str(BIN),'create-user',str(path/'config.json'),user,'--password-stdin'],input=f'{user}-secret\n',text=True,check=True,stdout=subprocess.DEVNULL)
 server=subprocess.Popen([str(BIN),'serve',str(path/'config.json'),'--experimental'],stdout=subprocess.PIPE,stderr=subprocess.PIPE);clients=[]
 try:
  for _ in range(100):
   if server.poll() is not None:raise RuntimeError(server.stderr.read().decode())
   try:s=socket.create_connection(('127.0.0.1',portnum),timeout=.1);s.close();break
   except OSError:time.sleep(.05)
  a=Client(portnum,path/'cert.pem','alice','alice-secret');b=Client(portnum,path/'cert.pem','bob','bob-secret');clients=[a,b];a.available();b.available()
  a.send("<iq type='set' id='roster'><query xmlns='jabber:iq:roster'><item jid='bob@localhost' name='Bob'><group>Friends</group></item></query></iq>");a.iq('roster')
  a.send("<iq type='get' id='getroster'><query xmlns='jabber:iq:roster'/></iq>");assert any(e.get('jid')=='bob@localhost' for e in a.iq('getroster').iter())
  a.send("<presence type='subscribe' to='bob@localhost'/>");b.take(lambda e:local(e)=='presence' and e.get('type')=='subscribe')
  b.send("<presence type='subscribed' to='alice@localhost'/>");b.sync();a.sync()
  a.send("<iq type='get' id='substate'><query xmlns='jabber:iq:roster'/></iq>");assert any(e.get('subscription')=='to' for e in a.iq('substate').iter())
  a.send(f"<iq type='get' id='client-iq' to='{b.jid}'><query xmlns='jabber:iq:version'/></iq>")
  ask=b.take(lambda e:local(e)=='iq' and e.get('id')=='client-iq');assert ask.get('from')==a.jid
  b.send(f"<iq type='result' id='client-iq' from='forged@localhost' to='{a.jid}'><query xmlns='jabber:iq:version'><name>Bob Client</name></query></iq>");assert a.iq('client-iq').get('from')==b.jid
  a.send("<message type='chat' id='chat1' to='bob@localhost'><body>archived</body></message>");b.body('archived')
  a.send("<message to='bob@localhost/obsolete-resource' type='chat'><body>resource fallback</body></message>");assert b.body('resource fallback').get('to')=='bob@localhost/obsolete-resource'
  # Inactive CSI holds chat-state noise, but a real message flushes it in order.
  b.send("<inactive xmlns='urn:xmpp:csi:0'/>");time.sleep(.05)
  a.send("<message to='bob@localhost' id='csi-noise'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>");a.sync()
  assert not b.buf,repr(b.buf)
  b.sock.settimeout(.15)
  try:
   unexpected=b.sock.recv(1);raise AssertionError(('CSI leaked unimportant output',unexpected))
  except socket.timeout:pass
  finally:b.sock.settimeout(5)
  a.send("<message to='bob@localhost'><body>CSI flush</body></message>")
  noise=b.take(lambda e:e.get('id')=='csi-noise');assert any(n.tag=='{urn:xmpp:delay}delay' for n in noise)
  b.body('CSI flush')
  b.send("<inactive xmlns='urn:xmpp:csi:0'/>");time.sleep(.05)
  a.send("<message to='bob@localhost' id='csi-keepalive'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>");a.sync();time.sleep(.05)
  b.send(' ');b.take(lambda e:e.get('id')=='csi-keepalive')
  b.send("<active xmlns='urn:xmpp:csi:0'/>")
  a.send("<iq type='set' id='mam'><query xmlns='urn:xmpp:mam:2' queryid='q1'/></iq>");a.iq('mam');assert any(any(n.tag=='{urn:xmpp:mam:2}result' for n in e) for e in a.queue)
  b.send("<iq type='set' id='block'><block xmlns='urn:xmpp:blocking'><item jid='alice@localhost'/></block></iq>");b.iq('block')
  a.send("<message to='bob@localhost'><body>blocked</body></message>");a.sync()
  b.send("<iq type='set' id='unblock'><unblock xmlns='urn:xmpp:blocking'/></iq>");b.iq('unblock')
  a.send("<iq type='set' id='pep'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'><list xmlns='eu.siacs.conversations.axolotl'><device id='123'/></list></item></publish></pubsub></iq>");a.iq('pep')
  a.send("<iq type='get' id='pepget'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist'/></pubsub></iq>");assert any(n.tag=='{eu.siacs.conversations.axolotl}device' for n in a.iq('pepget').iter())
  for c,nick in [(a,'Alice'),(b,'Bob')]:
   c.send(f"<presence to='room@conference.localhost/{nick}'><x xmlns='http://jabber.org/protocol/muc'/></presence>");c.take(lambda e:local(e)=='presence' and any(n.get('code')=='110' for n in e.iter()))
   if c is a:c.send("<iq type='set' id='unlock' to='room@conference.localhost'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'/></query></iq>");c.iq('unlock')
  a.send("<message to='room@conference.localhost' type='groupchat'><body>room chat</body></message>");assert b.body('room chat').get('from')=='room@conference.localhost/Alice'
  b.close();clients.remove(b);time.sleep(.1)
  a.send("<message to='bob@localhost'><body>offline replay</body></message>");a.sync()
  a.send("<message to='bob@localhost' type='headline' id='offline-headline'><body>discard headline</body></message>");a.sync()
  assert not any(e.get('id')=='offline-headline' and e.get('type')=='error' for e in a.queue),'offline headline must be silently discarded'
  # no-permanent-store forbids MAM, but must not discard transient offline delivery.
  a.send("<message to='bob@localhost' id='offline-transient'><body>transient offline</body><no-permanent-store xmlns='urn:xmpp:hints'/></message>")
  # Bodyless receipts are also messages handled by native mod_message/mod_offline.
  a.send("<message to='bob@localhost' id='offline-receipt'><received xmlns='urn:xmpp:receipts' id='old-message'/></message>");a.sync()
  b=Client(portnum,path/'cert.pem','bob','bob-secret','second');clients.append(b);b.available();b.body('offline replay');b.body('transient offline')
  receipt=b.take(lambda e:e.get('id')=='offline-receipt');assert any(n.tag=='{urn:xmpp:receipts}received' for n in receipt)
  b.send("<iq type='set' id='offline-mam'><query xmlns='urn:xmpp:mam:2' queryid='offline-mam'/></iq>");b.iq('offline-mam')
  assert not any(n.tag=='{jabber:client}body' and n.text=='transient offline' for e in b.queue for n in e.iter()),'no-permanent-store leaked into MAM' 
  b.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>");enabled=b.take(lambda e:e.tag=='{urn:xmpp:sm:3}enabled');resume=enabled.get('id');b.close();clients.remove(b);time.sleep(.1)
  a.send("<message to='bob@localhost'><body>resume replay</body></message>");a.sync()
  b=Client(portnum,path/'cert.pem','bob','bob-secret',bind=False);clients.append(b);b.send(f"<resume xmlns='urn:xmpp:sm:3' previd='{resume}' h='0'/>");b.take(lambda e:e.tag=='{urn:xmpp:sm:3}resumed');b.body('resume replay');b.send("<a xmlns='urn:xmpp:sm:3' h='1'/>");b.sync()
  print('PASS: integrated TCP roster/subscriptions, client IQ routing, CSI buffering/keepalive flush, MAM, blocking, OMEMO PEP, MUC, offline replay and SM resumption')
 finally:
  for c in clients:c.close()
  server.send_signal(signal.SIGTERM)
  try:server.wait(timeout=5)
  except subprocess.TimeoutExpired:server.kill();server.wait()

 assert server.returncode==0, f'SIGTERM shutdown failed: {server.returncode}: '+server.stderr.read().decode()
 print('PASS: graceful SIGTERM shutdown')
