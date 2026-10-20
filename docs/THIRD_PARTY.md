The original Prosody configuration loader in tests/reference/configmanager.lua
is from commit cafd74b9c5ead46eb58910359eb266e1732b0aa1, supplied by the user.
It is used for differential testing only. Its copyright notices are preserved;
its MIT/X11 license is in tests/reference/COPYING.
Rust runtime code is a new implementation. Dependency licenses remain with
those dependencies; Cargo.lock records exact versions used.

API references consulted:
- https://docs.rs/mlua/0.12.2/mlua/struct.Lua.html
- https://docs.rs/serde_yaml_ng/0.10.0/serde_yaml_ng/
