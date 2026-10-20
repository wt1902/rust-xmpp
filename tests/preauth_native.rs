//! Interoperability with the supplied, unmodified Prosody mod_invites.
use rust_xmpp::{auth, preauth};
#[test]
#[ignore = "requires PROSODY_REFERENCE_SOURCE and PROSODY_REFERENCE_LUA"]
fn native_prosody_invitation_tokens_roundtrip() {
    let data = tempfile::tempdir().unwrap();
    auth::create(data.path(), "example.org", "alice", "secret", "SHA-256").unwrap();
    let now = chrono::Utc::now().timestamp();
    let rust = preauth::create_invite(
        data.path(),
        "example.org",
        "alice@example.org",
        None,
        120,
        now,
    )
    .unwrap();
    let scoped = preauth::create_invite(
        data.path(),
        "example.org",
        "alice@example.org",
        Some("bob@remote.test"),
        120,
        now,
    )
    .unwrap();
    let bootstrap = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/prosody_compat/oracle.lua"
    ))
    .unwrap();
    let bootstrap = bootstrap.split("if phase == 'probe' then").next().unwrap();
    let script = format!(
        "{bootstrap}\n{}",
        r#"
config.set('*', 'modules_enabled', {});
prosody.shutdown = function() end; -- mod_invites' real-server storage bootstrap condition.
assert(mm.load('example.org', 'invites'));
local invites = assert(mm.get_module('example.org', 'invites'));
if phase == 'invites' then
  local invite = assert(invites.get(arg[5], 'alice'));
  assert(invite.username == 'alice');
  assert(not invites.get(arg[5], 'other'));
  assert(not invites.get(arg[6], 'alice')); -- Scoped Rust token cannot be redeemed by unaware native code.
  assert(invite:use());
  assert(not invites.get(arg[5], 'alice'));
  local native = assert(invites.create_contact('alice', false, nil, 120));
  assert(not native.allow_registration);
  print('NATIVE_INVITE_TOKEN '..native.token);
else
  assert(not invites.get(arg[5], 'alice')); -- Rust consumed the native token.
  print('NATIVE_INVITE_FINAL_OK');
end
"#
    );
    let path = data.path().join("native-invites.lua");
    std::fs::write(&path, script).unwrap();
    let source = std::env::var("PROSODY_REFERENCE_SOURCE").unwrap();
    let lua = std::env::var("PROSODY_REFERENCE_LUA").unwrap_or("lua5.4".into());
    let run = |phase: &str, token: &str| {
        let result = std::process::Command::new(&lua)
            .arg(&path)
            .arg(&source)
            .arg(data.path())
            .arg(phase)
            .arg("SHA-256")
            .arg(token)
            .arg(&scoped.token)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap()
    };
    let result = run("invites", &rust.token);
    let token = result
        .lines()
        .find_map(|line| line.strip_prefix("NATIVE_INVITE_TOKEN "))
        .unwrap();
    assert!(
        !preauth::consume(
            data.path(),
            "example.org",
            "alice@example.org",
            "bob@remote.test",
            &rust.token,
            chrono::Utc::now().timestamp()
        )
        .unwrap()
    );
    assert!(
        preauth::consume(
            data.path(),
            "example.org",
            "alice@example.org",
            "bob@remote.test",
            token,
            chrono::Utc::now().timestamp()
        )
        .unwrap()
    );
    assert!(run("verify-invites", token).contains("NATIVE_INVITE_FINAL_OK"));
    assert!(
        preauth::consume(
            data.path(),
            "example.org",
            "alice@example.org",
            "bob@remote.test",
            &scoped.token,
            chrono::Utc::now().timestamp()
        )
        .unwrap()
    );
}
