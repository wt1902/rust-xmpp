# Native reference test source

`prosody-cafd74b9c5ea.tar.gz` is the original, unmodified source archive supplied
with this project. Revision: `cafd74b9c5ead46eb58910359eb266e1732b0aa1`.
SHA-256: `1e558d3d2211ea0228596aced2b71306503190c454ec4cb44f172045b3513c34`.

The source is bundled so CI cannot silently skip native oracle tests when a
private upload URL expires. Prosody's MIT/X11 license and copyright notices
are retained inside the archive (`COPYING`). No compiled shared objects are
bundled. `prepare-reference.sh` checks the archive hash and builds native
modules against the runner's Lua/OpenSSL/ICU installation.
