#!/usr/bin/env python3
"""Isolated TLS contact invitation, token forwarding and roster regression."""
import json, socket, subprocess, tempfile, time, sys
from pathlib import Path
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from _wire_client import Client, local, BIN

COMMANDS='http://jabber.org/protocol/commands'
DISCO='http://jabber.org/protocol/disco#items'
PARS='urn:xmpp:pars:0'

def roster(client, identifier):
    client.send(f"<iq type='get' id='{identifier}'><query xmlns='jabber:iq:roster'/></iq>")
    return {e.get('jid'):e.get('subscription') for e in client.iq(identifier).iter() if e.tag=='{jabber:iq:roster}item'}

def run():
    with tempfile.TemporaryDirectory(prefix='xmpp-preauth-') as tmp:
        root=Path(tmp)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        cfg={'global':{'data_path':str(root/'data'),'interfaces':['127.0.0.1'],'c2s_ports':[port],'http_ports':[],'https_ports':[],'s2s_ports':[],'modules_enabled':['tls','saslauth','roster','disco','pep','cloud_notify','mam','ping','smacks']},'hosts':{'localhost':{'options':{'authentication':'internal_hashed','password_hash':'SHA-256','ssl':{'key':str(root/'key.pem'),'certificate':str(root/'cert.pem')}}}}}
        config=root/'config.json';config.write_text(json.dumps(cfg))
        for user in ['alice','bob','carol']:
            subprocess.run([str(BIN),'create-user',str(config),user,'--password-stdin'],input=user+'-secret\n',text=True,check=True,capture_output=True)
        with (root/'server.log').open('w+') as log:
            server=subprocess.Popen([str(BIN),'serve',str(config),'--experimental'],stdout=log,stderr=log);clients=[]
            try:
                for _ in range(100):
                    assert server.poll() is None,'server stopped'
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                    except OSError:time.sleep(.05)
                a,b,c=[Client(port,root/'cert.pem',u,u+'-secret') for u in ['alice','bob','carol']];clients=[a,b,c]
                for client in clients:
                    features=ET.fromstring(client.post_auth_features[client.post_auth_features.index(b'<stream:features'):].replace(b'<stream:features',b"<stream:features xmlns:stream='http://etherx.jabber.org/streams'",1))
                    assert features.find('{urn:xmpp:features:pre-approval}sub') is not None
                    client.available();roster(client,'initial-roster')
                a.send(f"<iq type='get' id='commands' to='localhost'><query xmlns='{DISCO}' node='{COMMANDS}'/></iq>")
                assert any(n.get('node')=='urn:xmpp:invite#invite' for n in a.iq('commands').iter())
                a.send(f"<iq type='set' id='invite' to='localhost'><command xmlns='{COMMANDS}' node='urn:xmpp:invite#invite' action='execute'/></iq>")
                result=a.iq('invite');fields={n.get('var'):n.find('{jabber:x:data}value').text for n in result.iter('{jabber:x:data}field')}
                uri=fields['uri'];assert uri.startswith('xmpp:alice@localhost?roster;preauth=') and 'ibr=y' not in uri
                token=uri.split('preauth=',1)[1];assert len(token)==32 and fields['expire']
                b.send("<presence to='alice@localhost' type='subscribed'/>");b.sync()
                b.send(f"<presence to='alice@localhost' type='subscribe'><preauth xmlns='{PARS}' token='{token}'/></presence>");b.sync();a.sync()
                assert roster(a,'alice-after').get('bob@localhost')=='both'
                assert roster(b,'bob-after').get('alice@localhost')=='both'
                c.send(f"<presence to='alice@localhost' type='subscribe' id='replay'><preauth xmlns='{PARS}' token='{token}'/></presence>");c.sync();a.sync()
                assert roster(a,'replay-denied').get('carol@localhost')=='none'
                replay=a.take(lambda n:local(n)=='presence' and n.get('id')=='replay')
                assert replay.find('{'+PARS+'}preauth').get('token')==token
                # Unknown client-generated tokens must reach the owner even after offline replay.
                a.close();clients.remove(a);time.sleep(.1)
                c.send(f"<presence to='alice@localhost' type='subscribe' id='manual'><preauth xmlns='{PARS}' token='client-generated-token'/></presence>");c.sync()
                a=Client(port,root/'cert.pem','alice','alice-secret','again');clients.append(a);a.available()
                pending=a.take(lambda n:local(n)=='presence' and n.get('id')=='manual')
                assert pending.find('{'+PARS+'}preauth').get('token')=='client-generated-token'
                # A different authenticated account cannot issue invitations in Alice's name.
                c.send(f"<iq type='set' id='foreign' to='alice@localhost'><command xmlns='{COMMANDS}' node='urn:xmpp:invite#invite'/></iq>");c.iq('foreign',error=True)
                print('PASS: TLS invitation command discovery, preapproval, single-use mutual roster, replay denial, unknown preauth forwarding/offline pending, account isolation')
            except BaseException:
                log.flush();log.seek(0);print(log.read());raise
            finally:
                for client in clients:client.close()
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()

if __name__=='__main__':
    if len(sys.argv)>1:BIN=Path(sys.argv[1]).resolve()
    run()
