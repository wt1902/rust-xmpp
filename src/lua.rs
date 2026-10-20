//! Bounded Lua evaluation for configuration and legacy data. Never executes plugins.
use mlua::{HookTriggers, Lua, Value, VmState};
use serde_json::{Map, Number, Value as Json};
use std::{cell::Cell, rc::Rc};

pub fn bounded_vm() -> mlua::Result<Lua> {
    let lua = Lua::new();
    lua.set_memory_limit(16 * 1024 * 1024)?;
    let count = Rc::new(Cell::new(0_u32));
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(1000),
        move |_, _| {
            count.set(count.get() + 1);
            if count.get() > 2000 {
                return Err(mlua::Error::runtime("Lua instruction budget exceeded"));
            }
            Ok(VmState::Continue)
        },
    )?;
    Ok(lua)
}

/// Reject mixed/holey tables rather than silently dropping numeric keys.
/// Empty tables become objects (module-list readers accept empty objects).
pub fn json_value(value: Value, depth: usize) -> mlua::Result<Json> {
    if depth > 64 {
        return Err(mlua::Error::runtime("table nesting/cycle limit exceeded"));
    }
    Ok(match value {
        Value::Nil => Json::Null,
        Value::Boolean(v) => Json::Bool(v),
        Value::Integer(v) => Json::Number(v.into()),
        Value::Number(v) => Json::Number(
            Number::from_f64(v).ok_or_else(|| mlua::Error::runtime("non-finite number"))?,
        ),
        Value::String(v) => Json::String(v.to_str()?.to_string()),
        Value::Table(t) => {
            let mut object = Map::new();
            let mut sequence = std::collections::BTreeMap::new();
            for pair in t.pairs::<Value, Value>() {
                let (key, value) = pair?;
                let value = json_value(value, depth + 1)?;
                match key {
                    Value::String(s) => {
                        object.insert(s.to_str()?.to_string(), value);
                    }
                    Value::Integer(i) if i > 0 => {
                        sequence.insert(i, value);
                    }
                    _ => return Err(mlua::Error::runtime("unsupported Lua table key")),
                }
            }
            if sequence.is_empty() {
                Json::Object(object)
            } else {
                if !object.is_empty() || sequence.keys().copied().ne(1..=sequence.len() as i64) {
                    return Err(mlua::Error::runtime(
                        "mixed or sparse Lua tables are not supported in configuration",
                    ));
                }
                Json::Array(sequence.into_values().collect())
            }
        }
        _ => {
            return Err(mlua::Error::runtime(
                "configuration contains executable or unsupported values",
            ));
        }
    })
}
