#!/bin/sh
set -eu
# Never recursively chown an existing Prosody volume. Match its existing owner.
if [ "$(id -u)" = 0 ]; then
    data_dir=${XMPP_DATA_DIR:-/var/lib/prosody}
    if [ ! -d "$data_dir" ]; then
        mkdir -p "$data_dir"
        chown "${XMPP_UID:-1000}:${XMPP_GID:-1000}" "$data_dir"
    fi
    runtime_uid=${XMPP_UID:-$(stat -c %u "$data_dir")}
    runtime_gid=${XMPP_GID:-$(stat -c %g "$data_dir")}
    case "$runtime_uid:$runtime_gid" in
        *[!0-9:]*|:*|*:) echo 'XMPP_UID and XMPP_GID must be numeric' >&2; exit 1 ;;
    esac
    if [ "$runtime_uid" != 0 ]; then
        exec gosu "$runtime_uid:$runtime_gid" rust-xmpp "$@"
    fi
fi
exec rust-xmpp "$@"
