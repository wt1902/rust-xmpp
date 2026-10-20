#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p demo
if [ -e demo/config.toml ]; then
  echo 'demo/config.toml already exists; refusing to replace demo' >&2
  exit 1
fi
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout demo/key.pem -out demo/cert.pem \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>/dev/null
python3 - <<'PY'
from pathlib import Path
import json
p=Path('demo').resolve()
config={'global':{'data_path':str(p/'data'),'interfaces':['127.0.0.1'],'c2s_ports':[55222],
's2s_ports':[],'http_ports':[],'https_ports':[],'allow_registration':False,
'modules_enabled':['tls','saslauth','disco','ping','version']},
'hosts':{'localhost':{'options':{'authentication':'internal_hashed','password_hash':'SHA-256',
'ssl':{'key':str(p/'key.pem'),'certificate':str(p/'cert.pem')}}}}}
(p/'config.json').write_text(json.dumps(config,indent=2))
PY
./target/release/rust-xmpp convert demo/config.json toml demo/config.toml
printf '%s\n' 'alice-test-only' | ./target/release/rust-xmpp create-user demo/config.toml alice --password-stdin
printf '%s\n' 'bob-test-only' | ./target/release/rust-xmpp create-user demo/config.toml bob --password-stdin
cat <<'TEXT'
Demo created. Local test credentials:
  alice@localhost / alice-test-only
  bob@localhost   / bob-test-only
Start: ./target/release/rust-xmpp serve demo/config.toml --experimental
Manual clients: server localhost, port 55222, STARTTLS; trust demo/cert.pem.
Automated test: python3 scripts/smoke.py (starts and stops its own server).
TEXT
