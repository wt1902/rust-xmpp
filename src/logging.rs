//! Small, instance-owned structured logger with Prosody-style sink configuration.
//!
//! Shorthand level keys mean that level and above; explicit sink strings select
//! exactly one level. `*console` and `*stderr` write to
//! stderr; other destinations are append-only files. Array entries also accept
//! `{ "levels": { "min": "debug", "max": "error" }, "to": "file",
//! "filename": "server.log" }`. No process-global logger is installed.
use anyhow::{Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use serde_json::Value;
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}
impl Level {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => bail!("unknown log level: {value}"),
        }
    }
}
impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        })
    }
}
struct Sink {
    levels: u8,
    output: Output,
}
enum Output {
    Stderr,
    File { file: File, path: String },
}
struct State {
    sinks: Vec<Sink>,
    json: bool,
    reported_failure: bool,
}
/// Clones share sinks and serialize complete records, including file writes.
#[derive(Clone)]
pub struct Logger {
    state: Arc<Mutex<State>>,
}
impl Logger {
    pub fn from_config(config: Option<&Value>) -> Result<Self> {
        Self::from_config_with_format(config, None)
    }
    /// `format` is the separate `log_format` option: `plain` (default) or `json`.
    pub fn from_config_with_format(config: Option<&Value>, format: Option<&str>) -> Result<Self> {
        let json = match format.unwrap_or("plain") {
            "plain" => false,
            "json" => true,
            other => bail!("unknown log format: {other}"),
        };
        let mut specs = Vec::new();
        match config {
            None | Some(Value::Null) => {
                specs.push((level_range(Level::Info, Level::Error), "*stderr".to_owned()))
            }
            Some(Value::String(s)) => {
                if s.starts_with('*') {
                    specs.push((level_range(Level::Debug, Level::Error), s.clone()));
                } else if let Ok(level) = Level::parse(s) {
                    specs.push((level_range(level, Level::Error), "*stderr".to_owned()));
                } else {
                    specs.push((level_range(Level::Info, Level::Error), s.clone()));
                }
            }
            Some(Value::Object(map)) if !map.contains_key("to") => {
                for (level, destination) in map {
                    let min = Level::parse(level)?;
                    let path = destination
                        .as_str()
                        .ok_or_else(|| anyhow!("log destination for {level} must be a string"))?;
                    specs.push((level_range(min, Level::Error), path.to_owned()));
                }
            }
            Some(Value::Object(_)) => specs.push(parse_sink(config.unwrap())?),
            Some(Value::Array(entries)) => {
                for entry in entries {
                    specs.push(parse_sink(entry)?);
                }
            }
            _ => bail!("log must be a level, destination, table, or array of sinks"),
        }
        // Validate all destinations before opening any file.
        for (_, destination) in &specs {
            if destination.is_empty()
                || (destination.starts_with('*')
                    && destination != "*console"
                    && destination != "*stderr")
            {
                bail!("unsupported log destination: {destination}");
            }
        }
        // Each destination owns one handle and receives each record once, even
        // when several shorthand ranges or explicit level sets overlap.
        let mut destinations: Vec<(u8, String)> = Vec::new();
        for (levels, destination) in specs {
            let destination = if destination == "*console" {
                "*stderr".to_owned()
            } else {
                destination
            };
            if let Some((mask, _)) = destinations
                .iter_mut()
                .find(|(_, existing)| *existing == destination)
            {
                *mask |= levels;
            } else {
                destinations.push((levels, destination));
            }
        }
        let mut sinks = Vec::new();
        for (levels, destination) in destinations {
            let output = if destination.starts_with('*') {
                Output::Stderr
            } else {
                let file = open_log_file(&destination)?;
                Output::File {
                    file,
                    path: destination,
                }
            };
            sinks.push(Sink { levels, output });
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                sinks,
                json,
                reported_failure: false,
            })),
        })
    }
    /// Reopen files after external log rotation. All replacements are prepared
    /// before any sink is changed; clones immediately share the new handles.
    pub fn reopen(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut replacements = Vec::new();
        for (index, sink) in state.sinks.iter().enumerate() {
            if let Output::File { path, .. } = &sink.output {
                replacements.push((index, open_log_file(path)?));
            }
        }
        for (index, replacement) in replacements {
            if let Output::File { file, .. } = &mut state.sinks[index].output {
                *file = replacement;
            }
        }
        Ok(())
    }
    /// Emit one record. Values of credential-bearing fields are always redacted.
    /// I/O failures are reported once per logger to stderr and never panic.
    pub fn event(
        &self,
        level: Level,
        module: &str,
        connection: Option<&str>,
        event: &str,
        fields: &[(&str, &str)],
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !state
            .sinks
            .iter()
            .any(|sink| sink.levels & level_bit(level) != 0)
        {
            return;
        }
        let record = format_record(state.json, level, module, connection, event, fields);
        let mut failure = false;
        for sink in &mut state.sinks {
            if sink.levels & level_bit(level) == 0 {
                continue;
            }
            let result = match &mut sink.output {
                Output::Stderr => io::stderr().lock().write_all(record.as_bytes()),
                Output::File { file, .. } => file.write_all(record.as_bytes()),
            };
            failure |= result.is_err();
        }
        if failure && !state.reported_failure {
            state.reported_failure = true;
            let _ = io::stderr()
                .lock()
                .write_all(b"logging error: failed to write a log record\n");
        }
    }
}
fn open_log_file(path: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|err| anyhow!("cannot open log file {path}: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}
fn level_bit(level: Level) -> u8 {
    1 << level as u8
}
fn level_range(min: Level, max: Level) -> u8 {
    [Level::Debug, Level::Info, Level::Warn, Level::Error]
        .iter()
        .filter(|&&level| level >= min && level <= max)
        .fold(0, |mask, &level| mask | level_bit(level))
}
fn parse_sink(value: &Value) -> Result<(u8, String)> {
    if let Some(destination) = value.as_str() {
        if !destination.starts_with('*') {
            bail!("array log destinations must name a sink with *");
        }
        return Ok((
            level_range(Level::Debug, Level::Error),
            destination.to_owned(),
        ));
    }
    let sink = value
        .as_object()
        .ok_or_else(|| anyhow!("log sink must be an object or sink name"))?;
    let levels = match sink.get("levels") {
        None => level_range(Level::Debug, Level::Error),
        Some(Value::String(level)) => level_bit(Level::parse(level)?),
        Some(Value::Array(levels)) => {
            let mut mask = 0;
            for level in levels {
                mask |= level_bit(Level::parse(
                    level
                        .as_str()
                        .ok_or_else(|| anyhow!("log level must be a string"))?,
                )?);
            }
            mask
        }
        Some(Value::Object(range)) => {
            let parse_bound = |name: &str, default| -> Result<Level> {
                match range.get(name) {
                    None => Ok(default),
                    Some(value) => Level::parse(
                        value
                            .as_str()
                            .ok_or_else(|| anyhow!("log {name} must be a string"))?,
                    ),
                }
            };
            let min = parse_bound("min", Level::Debug)?;
            let max = parse_bound("max", Level::Error)?;
            if min > max {
                bail!("log minimum exceeds maximum");
            }
            level_range(min, max)
        }
        _ => bail!("log levels must be a string, level array, or range"),
    };
    let destination = match sink.get("to").and_then(Value::as_str) {
        Some("file") => sink
            .get("filename")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("file log sink requires filename"))?
            .to_owned(),
        Some("console" | "stderr") => "*stderr".to_owned(),
        _ => bail!("unsupported log sink type"),
    };
    Ok((levels, destination))
}
fn sensitive(key: &str) -> bool {
    let key: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "proof",
        "credential",
        "authxml",
        "raw",
        "authorization",
        "cookie",
        "sasl",
        "payload",
    ]
    .iter()
    .any(|word| key.contains(word))
}
fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"[invalid]\"".into())
}
fn format_record(
    json: bool,
    level: Level,
    module: &str,
    connection: Option<&str>,
    event: &str,
    fields: &[(&str, &str)],
) -> String {
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    if json {
        let fields: Vec<Value> = fields.iter().map(|(key, value)| serde_json::json!({"key": key, "value": if sensitive(key) { "[REDACTED]" } else { value }})).collect();
        return format!(
            "{}\n",
            serde_json::json!({"timestamp":timestamp,"level":level.to_string(),"module":module,"connection":connection,"event":event,"fields":fields})
        );
    }
    let mut line = format!(
        "timestamp={} level={} module={} event={}",
        quoted(&timestamp),
        level,
        quoted(module),
        quoted(event)
    );
    if let Some(connection) = connection {
        line.push_str(&format!(" connection={}", quoted(connection)));
    }
    for (key, value) in fields {
        line.push_str(&format!(
            " {}={}",
            quoted(key),
            quoted(if sensitive(key) { "[REDACTED]" } else { value })
        ));
    }
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_aliases_share_one_sink_with_combined_levels() {
        let config = serde_json::json!([
            "*console",
            "*stderr",
            {"to":"console","levels":"info"},
            {"to":"stderr","levels":"error"}
        ]);
        let logger = Logger::from_config(Some(&config)).unwrap();
        let state = logger.state.lock().unwrap();
        assert_eq!(state.sinks.len(), 1);
        assert!(matches!(state.sinks[0].output, Output::Stderr));
        assert_eq!(
            state.sinks[0].levels,
            level_range(Level::Debug, Level::Error)
        );
    }
}
