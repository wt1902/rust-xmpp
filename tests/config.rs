use rust_xmpp::config::{self, Config};
use serde_json::json;
use std::path::Path;

fn lua(text: &str) -> anyhow::Result<Config> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("config.lua");
    std::fs::write(&path, text)?;
    config::load(&path)
}
#[test]
fn supplied_configuration_scopes_arithmetic_and_modules() {
    let cfg = config::load(Path::new("tests/fixtures/prosody.cfg.lua")).unwrap();
    assert_eq!(cfg.hosts.len(), 4);
    assert_eq!(
        cfg.option("wthome.ru", "authentication"),
        Some(&json!("internal_hashed"))
    );
    assert_eq!(
        cfg.option("upload.wthome.ru", "http_file_share_size_limit"),
        Some(&json!(10737418240_u64))
    );
    assert_eq!(
        cfg.option("upload.wthome.ru", "http_file_share_global_quota"),
        Some(&json!(107374182400_u64))
    );
    assert!(cfg.modules("wthome.ru").unwrap().contains("sasl2"));
    assert_eq!(
        cfg.modules("conference.wthome.ru")
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["muc", "muc_mam"]
    );
    assert_eq!(
        cfg.modules("upload.wthome.ru")
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["http_file_share"]
    );
    assert!(
        cfg.diagnostics()
            .iter()
            .any(|d| d.message.contains("security_labels"))
    );
}
#[test]
fn all_formats_round_trip_actual_config() {
    let c = config::load(Path::new("tests/fixtures/prosody.cfg.lua")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for (ext, text) in [
        ("json", serde_json::to_string(&c).unwrap()),
        ("yaml", serde_yaml_ng::to_string(&c).unwrap()),
        ("toml", toml::to_string(&c).unwrap()),
    ] {
        let p = dir.path().join(format!("c.{ext}"));
        std::fs::write(&p, text).unwrap();
        assert_eq!(
            serde_json::to_value(&c).unwrap(),
            serde_json::to_value(config::load(&p).unwrap()).unwrap()
        );
    }
}
#[test]
fn include_has_own_global_scope_and_parent_scope_is_restored() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("main.lua"),
        "VirtualHost 'one.test'\nInclude 'child.lua'\nname='one'",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("child.lua"),
        "archive_expires_after='never'\nVirtualHost 'two.test'\nname='two'",
    )
    .unwrap();
    let c = config::load(&dir.path().join("main.lua")).unwrap();
    assert_eq!(c.global["archive_expires_after"], json!("never"));
    assert_eq!(c.hosts["one.test"].options["name"], json!("one"));
    assert_eq!(c.hosts["two.test"].options["name"], json!("two"));
}
#[test]
fn include_cycles_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("c.lua");
    std::fs::write(&p, "Include 'c.lua'").unwrap();
    assert!(config::load(&p).unwrap_err().to_string().contains("cycle"));
}
#[test]
fn declarations_and_overrides() {
    let c=lua("modules_enabled={'roster','mam'}\nVirtualHost 'ONE.TEST' {modules_disabled={'mam'}}\nComponent 'muc.test' 'muc' {name='Rooms'}\nallow_registration=false").unwrap();
    assert_eq!(
        c.modules("one.test")
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["roster"]
    );
    assert_eq!(c.global["allow_registration"], json!(false));
    assert_eq!(c.hosts["muc.test"].component.as_deref(), Some("muc"));
}
#[test]
fn runtime_capabilities_are_unavailable() {
    for source in [
        "os.execute('true')",
        "io.open('/etc/passwd')",
        "require('socket')",
        "RunScript 'x'",
        "Lua.os.execute('true')",
    ] {
        assert!(lua(source).is_err(), "{source}");
    }
}
#[test]
fn loops_are_bounded() {
    assert!(
        lua("while true do end")
            .unwrap_err()
            .to_string()
            .contains("budget")
    );
}
#[test]
fn malformed_values_rejected() {
    for text in [
        "VirtualHost 'x.test'\nc2s_ports={0}",
        "VirtualHost 'x.test'\nc2s_ports={65536}",
        "VirtualHost 'x.test'\nc2s_ports={5222,5222}",
        "VirtualHost 'x.test'\nmodules_enabled='mam'",
        "VirtualHost 'x.test'\nallow_registration='false'",
        "VirtualHost 'x.test'\nComponent 'x.test' 'muc'",
        "VirtualHost '../x'",
        "VirtualHost 'x.test'\nx={ [2]='hole' }",
        "VirtualHost 'x.test'\nx={ 'item', key='value' }",
    ] {
        assert!(lua(text).is_err(), "accepted {text}");
    }
}
#[test]
fn tables_cannot_recurse_forever() {
    assert!(lua("local t={}\nt.self=t\nVirtualHost 'x.test'\nx=t").is_err());
}
#[test]
fn component_can_explicitly_enable_global_modules() {
    let c = lua("modules_enabled={'ping'}\nComponent 'muc.test' 'muc'\nload_global_modules=true")
        .unwrap();
    assert!(c.modules("muc.test").unwrap().contains("ping"));
}
#[test]
fn storage_paths_encode_like_prosody() {
    use rust_xmpp::storage::encode_name;
    assert_eq!(encode_name("wthome.ru"), "wthome%2eru");
    assert_eq!(encode_name("../x_y"), "%2e%2e%2fx%5fy");
    assert_eq!(encode_name("я"), "%d1%8f");
}

#[test]
fn supplied_config_matches_original_prosody_loader() {
    // The original loader is run only as a reference in tests, with stubs for
    // helpers unused by this fixture. This is not a runtime dependency.
    let vm = mlua::Lua::new();
    vm.load(
        r#"
      package.preload['prosody.util.envload'] = function()
        return { envload=function(s,n,e) return load(s,n,'t',e) end }
      end
      package.preload['prosody.util.dependencies'] = function()
        return { softreq=function() return nil end }
      end
      package.preload['prosody.util.iterators'] = function() return {} end
      package.preload['prosody.util.paths'] = function()
        return { resolve_relative_path=function(p,f) return p..f end }
      end
      package.preload['prosody.util.debug'] = function()
        return { get_traceback_table=function() return {} end }
      end
      package.preload['prosody.util.error'] = function()
        return { is_error=function() return false end }
      end
      package.preload['prosody.util.logger'] = function()
        return { init=function() return function() end end }
      end
    "#,
    )
    .exec()
    .unwrap();
    let reference: mlua::Table = vm
        .load(include_str!("reference/configmanager.lua"))
        .eval()
        .unwrap();
    let load: mlua::Function = reference.get("load").unwrap();
    let (ok, _, _): (bool, mlua::Value, mlua::Value) = load
        .call(("tests/fixtures/prosody.cfg.lua", "lua"))
        .unwrap();
    assert!(ok);
    let get: mlua::Function = reference.get("getconfig").unwrap();
    let table: mlua::Table = get.call(()).unwrap();
    let parsed = config::load(Path::new("tests/fixtures/prosody.cfg.lua")).unwrap();
    let global: mlua::Value = table.get("*").unwrap();
    assert_eq!(
        rust_xmpp::lua::json_value(global, 0).unwrap(),
        json!(parsed.global)
    );
    for (name, host) in &parsed.hosts {
        let v: mlua::Value = table.get(name.as_str()).unwrap();
        let mut reference = rust_xmpp::lua::json_value(v, 0).unwrap();
        let object = reference.as_object_mut().unwrap();
        object.remove("defined");
        let component = object.remove("component_module");
        assert_eq!(component, host.component.as_ref().map(|v| json!(v)));
        assert_eq!(reference, json!(host.options));
    }
}
