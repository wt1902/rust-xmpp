#!/usr/bin/env python3
"""Independent stdlib SCRAM client; --spawn creates an isolated TLS test server.
Tests SHA-1/SHA-256 with SASL1, SASL2, SSDP and server signature validation.
"""
import argparse,base64,hashlib,hmac,secrets,socket,ssl,xml.etree.ElementTree as ET
import json,subprocess,tempfile,signal,time,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=55222);p.add_argument('--cafile',default=str(Path(__file__).resolve().parents[1]/'demo/cert.pem'));p.add_argument('--user',default='alice');p.add_argument('--password',default='alice-test-only');p.add_argument('--spawn',action='store_true');p.add_argument('--hash',choices=['sha1','sha256'],default='sha256');p.add_argument('--require-ssdp',action='store_true');p.add_argument('--test-push',action='store_true');p.add_argument('--binary',default=str(Path(__file__).resolve().parents[1]/'target/release/rust-xmpp'));args=p.parse_args()
mechanism='SCRAM-SHA-1' if args.hash=='sha1' else 'SCRAM-SHA-256'
if args.spawn:
 with tempfile.TemporaryDirectory(prefix='xmpp-sasl-') as tmp:
  root=Path(tmp);probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  config={'global':{'data_path':str(root/'data'),'interfaces':['127.0.0.1'],'c2s_ports':[port],'s2s_ports':[],'http_ports':[],'https_ports':[],'modules_enabled':['tls','saslauth','sasl2','sasl_ssdp','cloud_notify','smacks']},'hosts':{'localhost':{'options':{'authentication':'internal_hashed','password_hash':'SHA-1' if args.hash=='sha1' else 'SHA-256','ssl':{'key':str(root/'key.pem'),'certificate':str(root/'cert.pem')}}}}}
  (root/'config.json').write_text(json.dumps(config))
  subprocess.run([args.binary,'create-user',str(root/'config.json'),args.user,'--password-stdin'],input=args.password+'\n',text=True,check=True,stdout=subprocess.DEVNULL)
  server=subprocess.Popen([args.binary,'serve',str(root/'config.json'),'--experimental'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   for _ in range(100):
    if server.poll() is not None:raise RuntimeError(server.stderr.read().decode())
    try:probe=socket.create_connection(('127.0.0.1',port),timeout=.1);probe.close();break
    except OSError:time.sleep(.05)
   else:raise RuntimeError('SASL server did not start')
   subprocess.run([sys.executable,__file__,'--port',str(port),'--cafile',str(root/'cert.pem'),'--user',args.user,'--password',args.password,'--hash',args.hash,'--require-ssdp','--test-push'],check=True)
   stored=next((root/'data').glob('*/cloud_notify/*.dat')).read_text()
   assert 'test-stable-device' in stored and 'client_id' in stored
   assert 'resource' not in stored,stored
  finally:
   server.send_signal(signal.SIGINT)
   try:server.wait(timeout=5)
   except subprocess.TimeoutExpired:server.kill();server.wait()
 sys.exit(0)
b64=lambda x:base64.b64encode(x).decode()
stream="<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>"
class Client:
 def __init__(self):
  self.s=socket.create_connection(('127.0.0.1',args.port),timeout=5);self.buf=b''
  self.send(stream);self.until(b'</stream:features>')
  self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");assert b'proceed' in self.until(b'/>')
  self.s=ssl.create_default_context(cafile=args.cafile).wrap_socket(self.s,server_hostname='localhost')
  self.send(stream);features=self.until(b'</stream:features>');assert mechanism.encode() in features
  part=features[features.index(b'<stream:features'):];tree=ET.fromstring(b"<root xmlns:stream='http://etherx.jabber.org/streams'>"+part+b'</root>')
  self.mechs=sorted({n.text for n in tree.iter() if n.tag=='{urn:ietf:params:xml:ns:xmpp-sasl}mechanism'})
  self.bindings=sorted({n.get('type') for n in tree.iter() if n.tag=='{urn:xmpp:sasl-cb:0}channel-binding'})
 def send(self,data):self.s.sendall(data.encode())
 def until(self,mark):
  while mark not in self.buf:
   chunk=self.s.recv(65536)
   if not chunk:raise RuntimeError('Unexpected EOF: '+repr(self.buf))
   self.buf+=chunk
  end=self.buf.index(mark)+len(mark);out,self.buf=self.buf[:end],self.buf[end:];return out
 def auth(self,sasl2=False,bad=False):
  ns='urn:xmpp:sasl:2' if sasl2 else 'urn:ietf:params:xml:ns:xmpp-sasl'
  nonce=secrets.token_hex(18);bare=f'n={args.user},r={nonce}';initial=b64(('n,,'+bare).encode())
  if sasl2:self.send(f"<authenticate xmlns='{ns}' mechanism='{mechanism}'><initial-response>{initial}</initial-response><user-agent id='test-stable-device'/></authenticate>")
  else:self.send(f"<auth xmlns='{ns}' mechanism='{mechanism}'>{initial}</auth>")
  node=ET.fromstring(self.until(b'</challenge>'));server_first=base64.b64decode(node.text).decode();attrs=dict(x.split('=',1) for x in server_first.split(','))
  assert attrs['r'].startswith(nonce) and len(attrs['r'])>len(nonce)
  if args.require_ssdp:assert 'h' in attrs,'SSDP challenge missing'
  if 'h' in attrs:
   source='\x1e'.join(self.mechs)+('\x1f'+'\x1e'.join(self.bindings) if self.bindings else '')
   assert attrs['h']==b64(hashlib.new(args.hash,source.encode()).digest()),'SSDP mechanism hash mismatch'
  final=f"c=biws,r={attrs['r']}";authmsg=f'{bare},{server_first},{final}'.encode()
  salted=hashlib.pbkdf2_hmac(args.hash,('wrong-password' if bad else args.password).encode(),base64.b64decode(attrs['s']),int(attrs['i']))
  mac=lambda k,s:hmac.digest(k,s,args.hash)
  client_key=mac(salted,b'Client Key');signature=mac(hashlib.new(args.hash,client_key).digest(),authmsg)
  proof=bytes(a^b for a,b in zip(client_key,signature));final+=',p='+b64(proof)
  self.send(f"<response xmlns='{ns}'>{b64(final.encode())}</response>")
  if bad:
   failure=ET.fromstring(self.until(b'</failure>'))
   assert failure.tag=='{'+ns+'}failure'
   assert failure.find('{urn:ietf:params:xml:ns:xmpp-sasl}not-authorized') is not None, ET.tostring(failure)
   return
  result=ET.fromstring(self.until(b'</success>'))
  data=result.find('{urn:xmpp:sasl:2}additional-data').text if sasl2 else result.text
  expected='v='+b64(mac(mac(salted,b'Server Key'),authmsg));assert base64.b64decode(data).decode()==expected
  if sasl2:assert result.find('{urn:xmpp:sasl:2}authorization-identifier').text==args.user+'@localhost'
  else:self.send(stream)
  assert b'xmpp-bind' in self.until(b'</stream:features>')
  if sasl2 and args.test_push:
   self.send("<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>mobile</resource></bind></iq>")
   assert b"type='result'" in self.until(b'</iq>')
   self.send("<iq type='set' id='push'><enable xmlns='urn:xmpp:push:0' jid='push.localhost' node='phone'/></iq>")
   assert b"type='result'" in self.until(b'</iq>')
   self.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
   enabled=ET.fromstring(self.until(b'/>'));assert enabled.get('max')=='259200',ET.tostring(enabled)

 def close(self):self.s.close()
for sasl2,bad in [(False,False),(True,False),(False,True),(True,True)]:
 c=Client()
 try:c.auth(sasl2,bad)
 finally:c.close()
print(f'PASS: independent {mechanism} over TLS, SASL1/SASL2, SSDP verification, server signatures and wrong-password rejection')
