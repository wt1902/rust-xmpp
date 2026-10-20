use crate::lua::{bounded_vm, json_value};
use anyhow::{Context, Result, bail, ensure};
use mlua::{Lua, Table, Value};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};

const MAX_FILE: u64 = 1024 * 1024;
pub type Options = Map<String, Json>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub global: Options,
    #[serde(default)]
    pub hosts: BTreeMap<String, Host>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    #[serde(default)]
    pub component: Option<String>,
    #[serde(default)]
    pub options: Options,
}
#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub level: String,
    pub scope: String,
    pub message: String,
}

pub fn load(path: &Path) -> Result<Config> {
    let text = read_small(path)?;
    let config: Config = match path.extension().and_then(|s| s.to_str()) {
        Some("lua") => load_lua(path)?,
        Some("json") => serde_json::from_str(&text).context("invalid JSON configuration")?,
        Some("yaml" | "yml") => {
            serde_yaml_ng::from_str(&text).context("invalid YAML configuration")?
        }
        Some("toml") => toml::from_str(&text).context("invalid TOML configuration")?,
        _ => bail!("expected .lua, .json, .yaml, .yml or .toml"),
    };
    config.validate()?;
    Ok(config)
}
fn read_small(path: &Path) -> Result<String> {
    ensure!(
        fs::metadata(path)?.len() <= MAX_FILE,
        "configuration file exceeds 1 MiB"
    );
    fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
}
fn host_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.is_ascii()
            && name != "*"
            && !name.contains(['/', '\\', '@', ':'])
            && !name.chars().any(char::is_whitespace),
        "invalid/unsupported host name (use ASCII/punycode)"
    );
    Ok(())
}
impl Config {
    pub fn option(&self, host: &str, key: &str) -> Option<&Json> {
        self.hosts
            .get(host)
            .and_then(|h| h.options.get(key))
            .or_else(|| self.global.get(key))
    }
    /// Explicit configured modules only; implicit dependencies are not claimed as resolved.
    pub fn modules(&self, name: &str) -> Result<BTreeSet<String>> {
        let host = self.hosts.get(name).context("unknown host")?;
        let mut enabled = BTreeSet::new();
        let inherit = host
            .options
            .get("load_global_modules")
            .and_then(Json::as_bool)
            .unwrap_or(host.component.is_none());
        if inherit {
            enabled.extend(string_list(self.global.get("modules_enabled"))?);
        }
        enabled.extend(string_list(host.options.get("modules_enabled"))?);
        let mut disabled = string_list(self.global.get("modules_disabled"))?;
        disabled.extend(string_list(host.options.get("modules_disabled"))?);
        for item in disabled {
            enabled.remove(&item);
        }
        if let Some(component) = &host.component {
            enabled.insert(component.clone());
        }
        Ok(enabled)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.hosts.is_empty(),
            "no virtual hosts or components configured"
        );
        for (name, host) in &self.hosts {
            host_name(name)?;
            ensure!(
                name == &name.to_ascii_lowercase(),
                "host names must be lowercase"
            );
            if let Some(c) = &host.component {
                ensure!(!c.is_empty(), "empty component module");
            }
        }
        for (scope, options) in std::iter::once(("*", &self.global))
            .chain(self.hosts.iter().map(|(n, h)| (n.as_str(), &h.options)))
        {
            for key in ["modules_enabled", "modules_disabled"] {
                string_list(options.get(key)).with_context(|| format!("{scope}: {key}"))?;
            }
            for key in ["c2s_ports", "s2s_ports", "http_ports", "https_ports"] {
                if let Some(value) = options.get(key) {
                    if value.as_object().is_some_and(Map::is_empty) {
                        continue;
                    }
                    let list = value
                        .as_array()
                        .with_context(|| format!("{scope}: {key} must be a list"))?;
                    let mut seen = BTreeSet::new();
                    for port in list {
                        let p = port
                            .as_u64()
                            .filter(|n| (1..=65535).contains(n))
                            .context("port must be an integer in 1..65535")?;
                        ensure!(seen.insert(p), "duplicate port in {scope}: {key}");
                    }
                }
            }
            for key in [
                "allow_registration",
                "load_global_modules",
                "c2s_require_encryption",
                "s2s_require_encryption",
                "advertise_bosh",
                "advertise_websocket",
            ] {
                if let Some(v) = options.get(key) {
                    ensure!(v.is_boolean(), "{scope}: {key} must be boolean");
                }
            }
        }
        crate::http_config::validate(self)?;
        crate::http_proxy::ProxyConfig::from_options(&self.global)?;
        Ok(())
    }
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let mut out = vec![];
        for (name, h) in &self.hosts {
            let modules = self.modules(name).unwrap_or_default();
            if self.option(name, "allow_registration") == Some(&Json::Bool(true))
                && modules.contains("register")
            {
                out.push(Diagnostic {
                    level: "info".into(),
                    scope: name.clone(),
                    message: "Public registration is enabled by configuration".into(),
                });
            }
            if modules.contains("seclabels")
                && self
                    .option(name, "security_labels")
                    .and_then(|v| v.get("policies"))
                    .is_some()
            {
                out.push(Diagnostic { level:"warning".into(), scope:name.clone(), message:"security_labels policies/classifications supplies catalog metadata only; no access-control enforcement. Invalid schemas are rejected.".into() });
            }
            if h.component.is_none() && modules.contains("pep_simple") {
                out.push(Diagnostic {
                    level: "info".into(),
                    scope: name.clone(),
                    message: "mod_pep_simple is empty in the supplied Prosody revision".into(),
                });
            }
        }
        out
    }
}
fn string_list(v: Option<&Json>) -> Result<Vec<String>> {
    match v {
        None => Ok(vec![]),
        Some(Json::Object(m)) if m.is_empty() => Ok(vec![]),
        Some(Json::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .context("expected string list entry")
            })
            .collect(),
        _ => bail!("expected a list of strings"),
    }
}

#[derive(Clone)]
struct State {
    scopes: Table,
    stack: Rc<RefCell<Vec<PathBuf>>>,
    files: Rc<RefCell<usize>>,
}
fn load_lua(path: &Path) -> Result<Config> {
    let lua = bounded_vm().map_err(|e| anyhow::anyhow!("{e}"))?;
    let scopes = lua.create_table().map_err(|e| anyhow::anyhow!("{e}"))?;
    scopes
        .set("*", lua.create_table().map_err(|e| anyhow::anyhow!("{e}"))?)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let state = State {
        scopes,
        stack: Default::default(),
        files: Default::default(),
    };
    evaluate(&lua, path, state.clone()).map_err(|e| anyhow::anyhow!("Lua configuration: {e}"))?;
    let mut config = Config::default();
    for pair in state.scopes.pairs::<String, Table>() {
        let (name, table) = pair.map_err(|e| anyhow::anyhow!("{e}"))?;
        let Json::Object(mut options) =
            json_value(Value::Table(table), 0).map_err(|e| anyhow::anyhow!("{e}"))?
        else {
            bail!("scope is not a table");
        };
        if name == "*" {
            config.global = options;
        } else {
            let component = options
                .remove("component_module")
                .and_then(|v| v.as_str().map(str::to_owned));
            options.remove("defined");
            config.hosts.insert(name, Host { component, options });
        }
    }
    Ok(config)
}
fn evaluate(lua: &Lua, path: &Path, state: State) -> mlua::Result<()> {
    let path = path.canonicalize().map_err(mlua::Error::external)?;
    if state.stack.borrow().contains(&path) || state.stack.borrow().len() >= 16 {
        return Err(mlua::Error::runtime("Include cycle/depth limit"));
    }
    *state.files.borrow_mut() += 1;
    if *state.files.borrow() > 128 {
        return Err(mlua::Error::runtime("Include file count limit"));
    }
    let source = read_small(&path).map_err(|e| mlua::Error::runtime(e.to_string()))?;
    state.stack.borrow_mut().push(path.clone());
    let env = lua.create_table()?;
    let current = Rc::new(RefCell::new("*".to_owned()));
    for (alias, component) in [
        ("VirtualHost", false),
        ("Host", false),
        ("host", false),
        ("Component", true),
        ("component", true),
    ] {
        let scopes = state.scopes.clone();
        let current = current.clone();
        env.set(
            alias,
            lua.create_function(move |lua, name: String| {
                host_name(&name).map_err(|e| mlua::Error::runtime(e.to_string()))?;
                let name = name.to_ascii_lowercase();
                let existing: Option<Table> = scopes.get(name.as_str())?;
                let t = existing.unwrap_or(lua.create_table()?);
                let previous_component: Option<String> = t.get("component_module")?;
                let defined: Option<bool> = t.get("defined")?;
                if (component && defined == Some(true) && previous_component.is_none())
                    || (!component && previous_component.is_some())
                {
                    return Err(mlua::Error::runtime("VirtualHost/Component name clash"));
                }
                t.set("defined", true)?;
                if component {
                    t.set("component_module", "component")?;
                    t.set("load_global_modules", false)?;
                }
                scopes.set(name.as_str(), t.clone())?;
                *current.borrow_mut() = name;
                let reset = current.clone();
                lua.create_function(move |lua, value: Value| {
                    let apply_table = {
                        let t = t.clone();
                        let reset = reset.clone();
                        move |_: &Lua, opts: Table| {
                            for p in opts.pairs::<String, Value>() {
                                let (k, v) = p?;
                                t.set(k, v)?;
                            }
                            *reset.borrow_mut() = "*".into();
                            Ok(())
                        }
                    };
                    match value {
                        Value::String(s) if component => {
                            t.set("component_module", s)?;
                            Ok(Value::Function(lua.create_function(apply_table)?))
                        }
                        Value::Table(opts) => {
                            apply_table(lua, opts)?;
                            Ok(Value::Nil)
                        }
                        _ => Err(mlua::Error::runtime(
                            "invalid VirtualHost/Component declaration",
                        )),
                    }
                })
            })?,
        )?;
    }
    let parent = path.parent().unwrap().to_path_buf();
    let include_state = state.clone();
    let include = lua.create_function(move |lua, pattern: String| {
        let target = parent.join(pattern);
        let pattern = target
            .to_str()
            .ok_or_else(|| mlua::Error::runtime("non-UTF8 Include path"))?;
        let mut matches = glob::glob(pattern)
            .map_err(mlua::Error::external)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(mlua::Error::external)?;
        matches.sort();
        if matches.is_empty() {
            return Err(mlua::Error::runtime("Include matched no files"));
        }
        for file in matches {
            evaluate(lua, &file, include_state.clone())?;
        }
        Ok(())
    })?;
    env.set("Include", include.clone())?;
    env.set("include", include)?;
    let mt = lua.create_table()?;
    let read_scopes = state.scopes.clone();
    let read_current = current.clone();
    mt.set(
        "__index",
        lua.create_function(move |_, (_, key): (Table, String)| {
            let scope: Table = read_scopes.get(read_current.borrow().as_str())?;
            let value: Value = scope.get(key.as_str())?;
            if matches!(value, Value::Nil) {
                return Err(mlua::Error::runtime(format!(
                    "undefined or unsupported config symbol: {key}"
                )));
            }
            Ok(value)
        })?,
    )?;
    let scopes = state.scopes.clone();
    mt.set(
        "__newindex",
        lua.create_function(move |_, (_, key, value): (Table, String, Value)| {
            let scope: Table = scopes.get(current.borrow().as_str())?;
            scope.set(key, value)
        })?,
    )?;
    env.set_metatable(Some(mt))?;
    let result = lua
        .load(&source)
        .set_name(path.to_string_lossy().as_ref())
        .set_environment(env)
        .exec();
    state.stack.borrow_mut().pop();
    result
}
