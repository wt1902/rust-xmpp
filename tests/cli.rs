use std::process::Command;
fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rust-xmpp"))
}
#[test]
fn conversion_preserves_source_and_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("config.lua");
    let output = dir.path().join("config.yaml");
    let input = "VirtualHost 'test.local'\npassword='TEST-SECRET'";
    std::fs::write(&source, input).unwrap();
    let result = command()
        .args([
            "convert",
            source.to_str().unwrap(),
            "yaml",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("TEST-SECRET"));
    assert!(
        std::fs::read_to_string(&output)
            .unwrap()
            .contains("TEST-SECRET")
    );
    assert_eq!(std::fs::read_to_string(&source).unwrap(), input);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let bytes = std::fs::read(&output).unwrap();
    assert!(
        !command()
            .args([
                "convert",
                source.to_str().unwrap(),
                "yaml",
                output.to_str().unwrap()
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
}
#[test]
fn server_cannot_be_mistaken_for_running_service() {
    let output = command().arg("serve").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not implemented"));
}
