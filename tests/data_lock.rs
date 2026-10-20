use rust_xmpp::data_lock::DataDirectoryGuard;
use std::process::Command;

#[test]
fn child_process_probe() {
    let Some(root) = std::env::var_os("XMPP_LOCK_TEST_DIRECTORY") else {
        return;
    };
    let acquired = DataDirectoryGuard::acquire(std::path::Path::new(&root)).is_ok();
    assert_eq!(
        acquired,
        std::env::var("XMPP_LOCK_TEST_AVAILABLE").unwrap() == "yes"
    );
}

fn probe(root: &std::path::Path, available: bool) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_process_probe", "--nocapture"])
        .env("XMPP_LOCK_TEST_DIRECTORY", root)
        .env(
            "XMPP_LOCK_TEST_AVAILABLE",
            if available { "yes" } else { "no" },
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn excludes_another_process_and_releases_on_drop() {
    let root = tempfile::tempdir().unwrap();
    let native = root.path().join("existing-prosody-data");
    std::fs::write(&native, b"unchanged").unwrap();
    let guard = DataDirectoryGuard::acquire(root.path()).unwrap();
    probe(root.path(), false);
    #[cfg(unix)]
    {
        let aliases = tempfile::tempdir().unwrap();
        let alias = aliases.path().join("same-volume");
        std::os::unix::fs::symlink(root.path(), &alias).unwrap();
        probe(&alias, false);
    }
    drop(guard);
    probe(root.path(), true);
    assert_eq!(std::fs::read(&native).unwrap(), b"unchanged");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}
