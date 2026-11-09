#!/bin/sh
# build.sh - builds the Linux target into build/linux/analytics-blocker-linux-x64.so with the same g++ line the SDK's
# reusable workflow uses, against the SDK stoker-plugin.yaml pins (scripts/fetch-sdk.sh; STOKER_PLUGIN_SDK names a
# local SDK folder or zip instead).
set -eu
root=$(cd "$(dirname "$0")" && pwd)
sdk=$(sh "$root/scripts/fetch-sdk.sh" "$root/stoker-plugin.yaml")
mkdir -p "$root/build/linux"
g++ -std=c++20 -shared -fPIC -fvisibility=hidden -O2 -Wall -Wextra -I"$sdk/include" -DSTOKER_HOOK_PLUGIN_BUILD \
    "$root/src/analytics_blocker_linux.cpp" -o "$root/build/linux/analytics-blocker-linux-x64.so"
echo "Built $root/build/linux/analytics-blocker-linux-x64.so"
