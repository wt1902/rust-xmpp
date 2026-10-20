-- Runs the supplied Prosody's REAL bootstrap/module manager/storage/auth implementations.
local source, root, phase = assert(arg[1]), assert(arg[2]), assert(arg[3]);
package.path = source .. '/?.lua;' .. package.path;
package.cpath = source .. '/?.so;' .. package.cpath;
dofile(source .. '/loader.lua');
CFG_SOURCEDIR, CFG_PLUGINDIR, CFG_DATADIR = source, source .. '/plugins', root;
local startup = require 'prosody.util.startup';
startup.init_global_state();
local config = require 'prosody.core.configmanager';
config.set('*', 'data_path', root);
config.set('*', 'network_backend', 'select');
config.set('example.org', 'authentication', 'internal_hashed');
config.set('example.org', 'password_hash', arg[4] or 'SHA-256');
startup.setup_datadir();
startup.load_libraries();
startup.make_dummy_hosts(); -- The original prosodyctl bootstrap, not a test replacement.
local sm = require 'prosody.core.storagemanager';
sm.initialize_host('example.org');
local kv = assert(sm.open('example.org', 'oracle'));
local archive = assert(sm.open('example.org', 'archive', 'archive'));
local st = require 'prosody.util.stanza';
local mm = require 'prosody.core.modulemanager';
assert(mm.load('example.org', 'auth_internal_hashed'));
local authmod = assert(mm.get_module('example.org', 'auth_internal_hashed'));
local auth = assert(mm.get_items('auth-provider', 'example.org')[1]);
if phase == 'probe' then
  assert(kv:set('probe', {hello='actual Prosody'}));
  assert(kv:get('probe').hello == 'actual Prosody');
  print('PROSODY_NATIVE_PROBE_OK');
elseif phase == 'roundtrip' then
  local value = assert(kv:get('alice'));
  assert(value[false] == 'roster');
  assert(value[3] == 'sparse');
  assert(value.binary == string.char(0, 1, 10, 255));
  assert(value.text == 'Привет & <xml>');
  value.native = {changed=true, number=1.25};
  assert(kv:set('alice', value));
  local prefs = assert(sm.open('example.org', 'archive_prefs'));
  assert(prefs:get('alice')[false] == 'roster');
  assert(prefs:set('alice', {[false]=false, ['bob@example.org']=true}));
  assert(auth.test_password('alice', 'пароль-Original'));
  assert(not auth.test_password('alice', 'wrong'));
  assert(auth.set_password('alice', 'пароль-Native'));
  assert(auth.create_user('bob', 'native-bob'));
  local ok, stored, server = require('prosody.util.sasl.scram').hashers[arg[4] or 'SHA-256']('binary-password', string.char(0,255)..'salt', 10000);
  assert(ok);
  local hex = require 'prosody.util.hex';
  assert(sm.open('example.org', 'accounts'):set('binary', {salt=string.char(0,255)..'salt', iteration_count=10000,stored_key=hex.encode(stored),server_key=hex.encode(server)}));
  assert(auth.test_password('binary', 'binary-password'));
  local found = {};
  for id, stanza, when, peer in assert(archive:find('alice')) do
    found[#found+1] = id;
    assert(stanza.name == 'message');
    assert(stanza.attr['xml:lang'] == 'ru');
    assert(stanza.attr['urn:oracle'..string.char(1)..'flag'] == 'yes');
    assert(stanza:get_child_text('body') == 'Rust body');
    assert(when == 1767225600 + #found - 1);
    assert(peer == 'bob@example.org');
    assert(stanza.attr.stamp == nil);
  end
  assert(#found == 2 and found[1]=='rust-one' and found[2]=='rust-two');
  local native = st.message({xmlns='jabber:client',from='bob@example.org',to='alice@example.org',['xml:lang']='ru', ['urn:oracle'..string.char(1)..'flag']='native'}, 'Native body');
  assert(archive:append('alice', 'native-three', native, 1767225602, 'bob@example.org'));
  assert(archive:append('alice', 'rust-two', st.message({xmlns='jabber:client'}, 'Replaced by native'), 1767225603, 'bob@example.org'));
  local iter = assert(archive:find('alice', {after='rust-one', with='bob@example.org'}));
  assert(iter() == 'native-three');assert(iter() == 'rust-two');assert(iter() == nil);
  -- This exercises original binary .lidx creation, not just .list loading.
  print('PROSODY_NATIVE_ROUNDTRIP_OK '..(arg[4] or 'SHA-256'));
elseif phase == 'verify-final' then
  assert(kv:get('alice').rust_final == true);
  assert(auth.test_password('bob', 'rust-bob-new'));
  local count=0;for id, stanza in assert(archive:find('alice')) do count=count+1;if count==4 then assert(id=='rust-final');assert(stanza:get_child_text('body')=='Final');end end
  assert(count==4);
  print('PROSODY_NATIVE_FINAL_OK '..(arg[4] or 'SHA-256'));
else
  error('unknown phase');
end
