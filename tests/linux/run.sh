#!/bin/sh
# The plugin end to end inside Stoker's real Linux hook host: an install laid out as the agent lays it, and a stand-in
# game started as the launcher starts a native game with plugins - LD_PRELOAD and STOKER_INSTALL_DIR.
#
#   sh tests/linux/run.sh <libstoker_hookhost.so> <plugin .so>
#
# The blocked name is this machine's own host name, given in extraHosts: it resolves locally with no network, so a
# "not found" can only be the plugin's. Exit code 0 is a pass.
set -u
host=$(readlink -f "$1")
plugin=$(readlink -f "$2")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

install="$work/game"
data="$install/.stoker"
id=0123456789abcdef0123456789abcdef
mkdir -p "$data/injected/stoker-hook-plugins/$id/x64"
cc -O2 -Wall -o "$install/target" "$here/resolve_target.c" || exit 1
cp "$plugin" "$data/injected/stoker-hook-plugins/$id/x64/plugin.so"
sha=$(sha256sum "$plugin" | cut -d' ' -f1)
log="$data/logs/stoker_inject.log"
self=$(hostname | tr 'A-Z' 'a-z')
apis="getaddrinfo gethostbyname gethostbyname2 gethostbyname_r gethostbyname2_r getaddrinfo_a"

configure() {   # configure <options JSON, quotes escaped for a JSON string>
    printf '{"hooks":[],"plugins":[{"id":"%s","architecture":"X64","sha256":"%s","configJson":"%s","name":"Analytics blocker"}]}' \
        "$id" "$sha" "$1" > "$data/injected/stoker_hooks.x64.json"
}
run() { STOKER_INSTALL_DIR="$data" LD_PRELOAD="$host" "$install/target" "$@"; }

failed=0
every() {   # every <description> <output> <who> <name> answered|refused
    bad=""
    for api in $apis; do
        status=$(printf '%s\n' "$2" | awk -v w="$3" -v a="$api" -v n="$4" '$1==w && $2==a && $3==n {print $4; exit}')
        if [ -z "$status" ]; then bad="$bad $api(missing)"
        elif [ "$5" = answered ] && [ "$status" != 0 ]; then bad="$bad $api($status)"
        elif [ "$5" = refused ] && [ "$status" = 0 ]; then bad="$bad $api(answered)"; fi
    done
    if [ -z "$bad" ]; then echo "  ok   $1"; else echo "  FAIL $1:$bad"; printf '%s\n' "$2" | sed 's/^/       /'; failed=1; fi
}
logged() {   # logged <description> <pattern>
    if grep -q "$2" "$log"; then echo "  ok   $1"; else echo "  FAIL $1 (no \"$2\")"; sed 's/^/       /' "$log"; failed=1; fi
}

echo "control: no host"
every "every function answers $self" "$("$install/target" "$self")" parent "$self" answered

echo "blocking"
configure "{\\\"extraHosts\\\":\\\"$self\\\"}"
out=$(run "$self" localhost)
every "every function refuses a blocked name" "$out" parent "$self" refused
every "localhost still answers" "$out" parent localhost answered
logged "the log names the block, with the caller" "blocked $self (getaddrinfo, from target): extra, extraHosts"
logged "the plugin's hooks went in, the last of the five too" "libc.so.6!gethostbyname2_r installed"
[ "$(grep -c "blocked $self " "$log")" = 1 ] && echo "  ok   once" || { echo "  FAIL logged more than once"; failed=1; }

echo "a child of the game"
out=$(run spawn "$self")
every "is blocked too" "$out" child "$self" refused

echo "allowHosts"
configure "{\\\"extraHosts\\\":\\\"$self\\\",\\\"allowHosts\\\":\\\"$self\\\"}"
every "beats extraHosts" "$(run "$self")" parent "$self" answered

echo "STOKER_URL"
configure "{\\\"extraHosts\\\":\\\"$self\\\"}"
every "its host is never blocked" "$(STOKER_URL="http://$self:1/" run "$self")" parent "$self" answered

echo "observe mode"
rm -f "$log"
configure "{\\\"extraHosts\\\":\\\"$self\\\",\\\"mode\\\":\\\"observe\\\"}"
every "answers" "$(run "$self")" parent "$self" answered
logged "and logs what it would block" "would block $self "

if [ "$failed" -ne 0 ]; then echo "analytics blocker, Linux hook host: FAIL"; exit 1; fi
echo "analytics blocker, Linux hook host: PASS"
