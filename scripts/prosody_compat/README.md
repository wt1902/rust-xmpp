# Exact Prosody compatibility oracle

This harness executes the supplied **Prosody cafd74b9c5ea** implementation with a real Lua 5.4 interpreter and its compiled native modules. It uses the original `startup.make_dummy_hosts` (the upstream prosodyctl bootstrap), `core.modulemanager`, `mod_storage_internal`, and `mod_auth_internal_hashed`. Storage, authentication, stanza serialization and binary archive indexing are not replaced with test doubles. It does not launch a network listener or access a production data directory.

The storage/auth ignored integration test creates a new temporary directory for each of SHA-1 and SHA-256. It verifies:

1. Rust creates mixed-key/binary key/value data, preferences, accounts and archives.
2. Original Prosody loads those records, verifies passwords, rotates passwords, creates another account with a binary salt, reads XML namespace attributes, appends and replaces archive entries, and builds a real `.lidx` binary index.
3. Rust reads the modified records and verifies the new passwords, appends another record without rewriting history, and invalidates the upstream index.
4. Original Prosody reads the final records again and authenticates the password changed by Rust.

This caught and fixed real namespace interoperability problems: canonical Prosody attributes use the `\1` namespace separator, and reserved XML attributes are represented as literal `xml:lang`, etc. Reading also accepts the historical `|` separator.

## Reproduce on Debian/Ubuntu

Install build dependencies using your normal package manager: `lua5.4`, `liblua5.4-dev`, `lua-filesystem`, `lua-expat`, `lua-socket`, `lua-sec`, `libssl-dev`, `libicu-dev`, a C compiler, and `make`.

Extract the supplied source archive into a new test-only directory, then build:

```bash
cd prosody-cafd74b9c5ea
./configure --ostype=debian --lua-version=5.4 --lua-suffix=5.4
make -j2
```

From the Rust project:

```bash
scripts/prosody_compat/verify.sh /absolute/path/to/prosody-cafd74b9c5ea lua5.4
```

`CARGO` can select a cargo executable. `RUSTUP_TOOLCHAIN` defaults to the project toolchain `1.99.1`. If Lua dependencies are extracted to a private prefix instead of installed, set `LUA_PATH` and `LUA_CPATH` to that prefix before invoking the script.

## Validation performed in this workspace

The source was built with GCC against Lua 5.4.6, OpenSSL 3, and ICU 74. Real Lua modules came from Ubuntu packages extracted into a private prefix. The oracle completed all four native phases for SHA-1 and SHA-256 successfully. This verifies the tested persistence and password interoperability, **not full Prosody protocol parity**.

## Additional native module oracles

The same verification script also runs additional ignored tests against unmodified native modules:

- `preauth_native`: actual mod_invites consumes a Rust token and creates a native token consumed by Rust; scoped tokens remain inaccessible to native code.
- `pubsub_native`: actual `mod_pep`/`util.pubsub` read Rust items, publish a replacement, and Rust reads it.
- `muc_native`: actual `mod_muc` restores a Rust room/affiliations; `mod_muc_mam` reads Rust `message<groupchat` records and archives a real native room broadcast; Rust reads the result.
- `push` (ignored native lookup): original `util.stanza` confirms body extraction excludes foreign namespaces and nested extension elements.
- `csi_native`: fifteen importance decisions are compared with the actual `mod_csi_simple`, including presence, chatstates, carbons, EME, Jingle, MUC invites and a configured custom payload.

These use actual Prosody modules and storage. They do not emulate a networked fleet of real clients or external servers.

## Native federation transport test

The optional harness launches the built original Prosody in a temporary directory
and exchanges real stanzas with Rust over two TCP STARTTLS + SASL EXTERNAL
connections. A generated test CA anchors both certificate chains. Identity and
chain checks remain enabled. Only the test TCP routing resolver is overridden;
the asserted XMPP domain is unchanged.

```bash
PROSODY_SOURCE=/absolute/path/to/built/prosody-cafd74b9c5ea \
PROSODY_LUA=lua5.4 scripts/native-federation.sh
```

For dependencies extracted to a private prefix, set `PROSODY_NATIVE_PREFIX` to
its `usr` directory. The test checks the expected archive revision before
launching. It is isolated from live configuration/data and validates both message
IDs and bodies, plus Prosody's TLS/EXTERNAL authentication status.
