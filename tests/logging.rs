use rust_xmpp::logging::{Level, Logger};
use serde_json::json;

#[test]
fn filters_appends_escapes_and_redacts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.log");
    std::fs::write(&path, "existing\n").unwrap();
    let logger = Logger::from_config(Some(&json!({"info":path.to_str().unwrap()}))).unwrap();
    logger.event(Level::Debug, "test", None, "hidden", &[]);
    logger.event(
        Level::Info,
        "test\nmodule",
        Some("c1"),
        "connected",
        &[
            ("password", "supersecret"),
            ("access_token", "token-secret"),
            ("raw_xml", "<auth>secret</auth>"),
            ("peer", "a\n\r\u{1b}\"b"),
        ],
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("existing\n"));
    assert_eq!(text.lines().count(), 2);
    assert!(!text.contains("hidden"));
    assert!(!text.contains("supersecret"));
    assert!(!text.contains("token-secret"));
    assert!(!text.contains("<auth>"));
    assert!(text.contains("[REDACTED]"));
    assert!(text.contains("test\\nmodule"));
    assert!(text.contains("\\u001b"));
    assert!(text.contains("level=info"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn json_records_and_bounded_ranges() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("debug.log");
    let config = json!([{"levels":{"min":"debug","max":"info"},"to":"file","filename":path}]);
    let logger = Logger::from_config_with_format(Some(&config), Some("json")).unwrap();
    logger.event(Level::Error, "net", None, "excluded", &[]);
    logger.event(
        Level::Debug,
        "net",
        Some("42"),
        "accepted",
        &[("client_proof", "secret"), ("peer", "localhost")],
    );
    let text = std::fs::read_to_string(path).unwrap();
    let record: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(record["level"], "debug");
    assert_eq!(record["connection"], "42");
    assert_eq!(record["fields"][0]["value"], "[REDACTED]");
    let timestamp = record["timestamp"].as_str().unwrap();
    assert!(timestamp.ends_with('Z'));
    assert_eq!(timestamp.len(), 24);
    chrono::DateTime::parse_from_rfc3339(timestamp).unwrap();
}

#[test]
fn cloned_loggers_serialize_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("threads.log");
    let logger = Logger::from_config(Some(&json!({"debug":path}))).unwrap();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let logger = logger.clone();
            std::thread::spawn(move || {
                for _ in 0..40 {
                    logger.event(
                        Level::Info,
                        "worker",
                        None,
                        "complete",
                        &[("text", "x".repeat(4096).as_str())],
                    );
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let text = std::fs::read_to_string(path).unwrap();
    assert_eq!(text.lines().count(), 160);
    assert!(
        text.lines()
            .all(|line| line.starts_with("timestamp=") && line.ends_with('"'))
    );
}

#[test]
fn rejects_malformed_configuration() {
    for config in [
        json!(42),
        json!({"bogus":"*console"}),
        json!({"info":42}),
        json!("*unknown"),
        json!([{"to":"file"}]),
        json!([{"to":"console","levels":{"min":"error","max":"debug"}}]),
    ] {
        assert!(
            Logger::from_config(Some(&config)).is_err(),
            "accepted {config}"
        );
    }
    assert!(Logger::from_config(None).is_ok());
    assert!(Logger::from_config(Some(&json!("debug"))).is_ok());
    assert!(Logger::from_config(Some(&json!("*console"))).is_ok());
    assert!(Logger::from_config_with_format(None, Some("invalid")).is_err());
}

#[test]
fn explicit_sink_levels_select_exactly_and_deduplicate() {
    let dir = tempfile::tempdir().unwrap();
    for (name, selection, expected) in [
        ("single", json!("warn"), vec!["warn"]),
        (
            "set",
            json!(["debug", "error", "debug"]),
            vec!["debug", "error"],
        ),
        (
            "all",
            serde_json::Value::Null,
            vec!["debug", "info", "warn", "error"],
        ),
    ] {
        let path = dir.path().join(name);
        let mut config = json!({"to":"file", "filename":path});
        if !selection.is_null() {
            config["levels"] = selection;
        }
        let logger = Logger::from_config_with_format(Some(&config), Some("json")).unwrap();
        for level in [Level::Debug, Level::Info, Level::Warn, Level::Error] {
            logger.event(level, "test", None, "selection", &[]);
        }
        let text = std::fs::read_to_string(path).unwrap();
        let actual: Vec<String> = text
            .lines()
            .map(|line| {
                let record: serde_json::Value = serde_json::from_str(line).unwrap();
                record["level"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(actual, expected, "selection {name}");
    }
}

#[test]
fn native_console_shorthands_are_accepted() {
    assert!(Logger::from_config(Some(&json!("*console"))).is_ok());
    assert!(Logger::from_config(Some(&json!(["*console"]))).is_ok());
    assert!(Logger::from_config(Some(&json!(["*unknown"]))).is_err());
}

#[test]
fn overlapping_shorthand_destinations_receive_each_record_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.log");
    let config = json!({"debug":path,"info":path,"error":path});
    let logger = Logger::from_config_with_format(Some(&config), Some("json")).unwrap();
    for level in [Level::Debug, Level::Info, Level::Warn, Level::Error] {
        logger.event(level, "test", None, "selection", &[]);
    }
    let text = std::fs::read_to_string(path).unwrap();
    let levels: Vec<String> = text
        .lines()
        .map(|line| {
            let record: serde_json::Value = serde_json::from_str(line).unwrap();
            record["level"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(levels, ["debug", "info", "warn", "error"]);
}

#[test]
fn shared_sink_unions_levels_and_preserves_distinct_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("shared.log");
    let other = dir.path().join("other.log");
    let config = json!([
        {"to":"file","filename":shared,"levels":["debug","error"]},
        {"to":"file","filename":shared,"levels":["warn","error"]},
        {"to":"file","filename":other,"levels":{"min":"info","max":"error"}}
    ]);
    let logger = Logger::from_config_with_format(Some(&config), Some("json")).unwrap();
    for level in [Level::Debug, Level::Info, Level::Warn, Level::Error] {
        logger.event(level, "test", None, "selection", &[]);
    }
    for (path, expected) in [
        (shared, vec!["debug", "warn", "error"]),
        (other, vec!["info", "warn", "error"]),
    ] {
        let text = std::fs::read_to_string(path).unwrap();
        let levels: Vec<String> = text
            .lines()
            .map(|line| {
                let record: serde_json::Value = serde_json::from_str(line).unwrap();
                record["level"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(levels, expected);
    }
}

#[test]
fn reopen_rotated_files_updates_clones() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.log");
    let rotated = dir.path().join("events.log.1");
    let logger = Logger::from_config(Some(&json!({"info":path}))).unwrap();
    let clone = logger.clone();
    logger.event(Level::Info, "test", None, "before_rotation", &[]);
    std::fs::rename(&path, &rotated).unwrap();
    logger.reopen().unwrap();
    clone.event(Level::Info, "test", None, "after_rotation", &[]);
    let old = std::fs::read_to_string(rotated).unwrap();
    let new = std::fs::read_to_string(path).unwrap();
    assert!(old.contains("before_rotation"));
    assert!(!old.contains("after_rotation"));
    assert!(new.contains("after_rotation"));
    assert!(!new.contains("before_rotation"));
}

#[test]
fn failed_reopen_keeps_all_original_handles() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.log");
    let second = dir.path().join("second.log");
    let first_old = dir.path().join("first.log.1");
    let second_old = dir.path().join("second.log.1");
    let logger = Logger::from_config(Some(&json!([
        {"to":"file","filename":first},
        {"to":"file","filename":second}
    ])))
    .unwrap();
    std::fs::rename(&first, &first_old).unwrap();
    std::fs::rename(&second, &second_old).unwrap();
    std::fs::create_dir(&second).unwrap();
    assert!(logger.reopen().is_err());
    logger.event(Level::Info, "test", None, "retained_handles", &[]);
    assert!(
        std::fs::read_to_string(first_old)
            .unwrap()
            .contains("retained_handles")
    );
    assert!(
        std::fs::read_to_string(second_old)
            .unwrap()
            .contains("retained_handles")
    );
    assert!(std::fs::read_to_string(first).unwrap().is_empty());
}
