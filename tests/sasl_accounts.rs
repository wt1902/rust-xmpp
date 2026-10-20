use rust_xmpp::{
    auth,
    storage::{self, LuaValue},
};
#[test]
fn disabled_legacy_and_unicode_accounts() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    let mut disabled = LuaValue::table();
    disabled.set("disabled", LuaValue::Bool(true));
    storage::save(path, "example.com", Some("disabled"), "accounts", &disabled).unwrap();
    assert!(
        auth::load_scram(path, "example.com", "disabled", "SHA-256")
            .unwrap()
            .is_none()
    );
    assert!(!auth::verify(path, "example.com", "disabled", "password", "SHA-256").unwrap());
    let mut legacy = LuaValue::table();
    legacy.set("password", "pencil".into());
    legacy.set("custom-field", "preserve".into());
    storage::save(path, "example.com", Some("legacy"), "accounts", &legacy).unwrap();
    assert!(auth::verify(path, "example.com", "legacy", "pencil", "SHA-256").unwrap());
    auth::set_password(path, "example.com", "legacy", "changed", "SHA-256").unwrap();
    assert!(auth::verify(path, "example.com", "legacy", "changed", "SHA-256").unwrap());
    assert!(!auth::verify(path, "example.com", "legacy", "pencil", "SHA-256").unwrap());
    let data = storage::load(path, "example.com", Some("legacy"), "accounts")
        .unwrap()
        .unwrap();
    assert!(data.get("password").is_none());
    assert_eq!(
        data.get("custom-field").and_then(LuaValue::as_str),
        Some("preserve")
    );
    assert!(auth::set_password(path, "example.com", "missing", "password", "SHA-256").is_err());
    auth::create(path, "example.com", "пользователь", "пароль", "SHA-256").unwrap();
    assert!(auth::verify(path, "example.com", "пользователь", "пароль", "SHA-256").unwrap());
}
