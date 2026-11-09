# Analytics blocker

`app.stokerhq.analytics-blocker`: a [Stoker](https://github.com/StokerHQ) hook plugin that keeps a game's analytics
offline - product analytics SDKs, install attribution, third-party crash reporters and the engine's own telemetry.
Inside the game, the hosts they report to do not resolve, so to them the machine is offline. It changes no file of the
game and nothing outside the game's own processes.

## What it does

- Hooks the functions a program asks for a host's address with, in the game and every process it starts. On Windows
  (and under Proton or Wine): `getaddrinfo`, `GetAddrInfoW`, `GetAddrInfoExA`, `GetAddrInfoExW`, `gethostbyname` in
  `ws2_32`, and `DnsQuery_W`, `DnsQuery_A`, `DnsQuery_UTF8`, `DnsQueryEx` in `dnsapi`. On Linux (x86-64): `getaddrinfo`,
  `gethostbyname`, `gethostbyname2`, `gethostbyname_r`, `gethostbyname2_r` in libc; `getaddrinfo_a` goes through
  `getaddrinfo`.
- A host on the list gets the ordinary "not found" answer (`WSAHOST_NOT_FOUND`, `DNS_ERROR_RCODE_NAME_ERROR`,
  `EAI_NONAME`, `HOST_NOT_FOUND`) - the answer every SDK already handles, because players are offline. Never a fake
  address: Stoker's own services listen on loopback.
- **Never blocked**, whatever the options say: `localhost` and its subdomains, address literals, and the host of every
  `STOKER_*` environment variable that holds a URL - `STOKER_URL`, the Stoker instance, above all.
- Every engine reaches the network through these functions (Unity's and Unreal's HTTP stacks, .NET and Mono, WinHTTP,
  WinINet, libcurl, vendors' native SDKs), so one set of hooks covers engines nobody has looked at yet.

It runs in Stoker's `injected` hook host only: the hook host Stoker loads into every game it starts, before the game's
first instruction. So it is not in a game that ships an anti-cheat, nor in one a player starts without Stoker's in-game
modules.

## The list

`rules/hosts.yaml`, compiled into the plugin by `tools/gen_rules.py` (`src/generated/rules.h`). Only hosts that exist
to collect; a host that also serves gameplay is never blocked by name. Each rule has a category - `analytics`,
`attribution`, `crash`, `engine` - and says how it was learned. No rule names a game.

The first list is the vendors' documented collection hosts, each to be confirmed in observe mode. To add what a game
turns out to call: run it with `mode: observe`, read the log, add the rules, run `python3 tools/gen_rules.py` (needs
PyYAML), release.

## Options

| Option | Default | |
|---|---|---|
| `mode` | `block` | `observe` blocks nothing and logs every host the game resolves, with the module that asked. |
| `analytics`, `attribution`, `crash`, `engine` | `true` | Each switches its category's rules. |
| `allowHosts` | | One host per line; `*.name` for a name and every subdomain of it. These resolve even when a rule matches. |
| `extraHosts` | | One host per line, same syntax: blocked in addition. |
| `log` | `blocked` | `blocked`, `all` or `none`. Each name is logged once per process. |
| `process` | | The file name of the one executable to act in. Empty: every process of the game. |

Log lines go to the install's `logs/stoker_inject.log`, for example
`blocked o1.ingest.sentry.io (getaddrinfo, from sentry.dll): crash, Sentry`.

## Tests

- `tests/core_tests.cpp` - names, patterns, the order of the decision, the option lists; CI runs it under MSVC x86
  and x64 and under g++.
- `tests/windows/Test-InHookHost.ps1 -Stoker <checkout>` - the plugin inside Stoker's real Windows hook host, both
  architectures, started by `stoker-inject` with the carrier, and a 64-bit child of a 32-bit game. Needs the Stoker
  checkout's Release builds of `stoker_loader`, `stoker_hookhost` and `stoker-inject`.
- `tests/linux/run.sh <libstoker_hookhost.so> <plugin .so>` - the same in Stoker's Linux hook host, with a forked child.

Both end-to-end tests block the machine's own host name, which resolves without a network, so a "not found" can only
be the plugin's.

## Releases

A release is tagged `v<version>`, the version `src/manifest.h` declares; CI refuses a tag that differs. The release's
assets are built by CI from the tagged commit (`analytics-blocker-windows-x86.dll`,
`analytics-blocker-windows-x64.dll`, `analytics-blocker-linux-x64.so`) and are what the StokerHQ plugin registry
(`app.stokerhq.analytics-blocker` in [StokerHQ/plugins](https://github.com/StokerHQ/plugins)) lists by SHA-256 and
BLAKE3, signed by the StokerHQ publisher key.

## Building

```powershell
./build.ps1          # Windows x86 and x64, into build\
./build.ps1 -Linux   # and Linux x64 through WSL
```

```sh
sh build.sh          # Linux x64 only
```

Needs Visual Studio with the C++ workload for Windows, g++ for Linux. The SDK is the release `stoker-plugin.yaml`
pins, fetched once and checked by SHA-256; `STOKER_PLUGIN_SDK` names a local SDK folder or zip instead.

## Licence

AGPL-3.0-or-later (`LICENSE`).
