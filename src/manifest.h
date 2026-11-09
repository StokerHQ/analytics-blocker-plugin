// The manifest every file of a version carries byte for byte, and the options both backends read the same way.
#pragma once

#ifndef STOKER_HOOK_PLUGIN_BUILD
#define STOKER_HOOK_PLUGIN_BUILD
#endif
#include "stoker/hook_plugin.h"

#include <cstdio>

#include "core/blocker.h"

STOKER_PLUGIN_MANIFEST(R"json({
  "manifestVersion": 1,
  "id": "app.stokerhq.analytics-blocker",
  "name": "Analytics blocker",
  "type": "hook",
  "version": "0.1.0",
  "abi": 1,
  "description": "Keeps a game's analytics, install-attribution and crash-reporting SDKs and its engine's own telemetry offline: their hosts do not resolve inside the game. Changes no file of the game.",
  "hosts": ["injected"],
  "config": {
    "type": "object",
    "properties": {
      "mode": { "type": "string", "enum": ["block", "observe"], "default": "block", "title": "Mode",
                "description": "observe blocks nothing and logs every host the game resolves, with the module that asked." },
      "analytics": { "type": "boolean", "default": true, "title": "Block product analytics" },
      "attribution": { "type": "boolean", "default": true, "title": "Block install attribution" },
      "crash": { "type": "boolean", "default": true, "title": "Block third-party crash reporters" },
      "engine": { "type": "boolean", "default": true, "title": "Block engine telemetry" },
      "allowHosts": { "type": "string", "maxLength": 2048, "x-stoker-widget": "multiline", "title": "Always allow",
                      "description": "One host per line; *.name for a name and every subdomain of it. These resolve even when a rule matches." },
      "extraHosts": { "type": "string", "maxLength": 2048, "x-stoker-widget": "multiline", "title": "Also block",
                      "description": "One host per line; *.name for a name and every subdomain of it." },
      "log": { "type": "string", "enum": ["blocked", "all", "none"], "default": "blocked", "title": "Log",
               "description": "Each name is logged once per process." },
      "process": { "type": "string", "title": "Only in process",
                   "description": "The file name of the one executable to act in. Empty: every process of the game." }
    }
  }
})json");

namespace analytics_blocker
{
    inline const stoker_hook_host_v1* g_host = nullptr;
    inline Policy g_policy;
    inline OnceSet g_logged;

    inline void Log(const char* line)
    {
        if (g_host) g_host->log(g_host->user, line);
    }

    /// A top-level string option into `out`; false when it is absent. `invalid` is set when it is present but not a
    /// string that fits.
    inline bool StringOption(const char* key, char* out, uint32_t capacity, bool& invalid)
    {
        const int status = g_host->config_string(g_host->user, key, out, capacity);
        if (status == STOKER_HOOK_NOT_FOUND) return false;
        if (status != STOKER_HOOK_OK) { invalid = true; return false; }
        return true;
    }

    inline bool BoolOption(const char* key, bool fallback, bool& invalid)
    {
        if (!STOKER_HOOK_HAS(g_host, config_bool)) return fallback;
        int value = 0;
        const int status = g_host->config_bool(g_host->user, key, &value);
        if (status == STOKER_HOOK_NOT_FOUND) return fallback;
        if (status != STOKER_HOOK_OK) { invalid = true; return fallback; }
        return value != 0;
    }

    /// Reads every option into g_policy except the protected hosts, which come from the environment (the backend's).
    /// False, with the reason logged, when an option is unusable - the plugin then registers nothing.
    inline bool ReadOptions()
    {
        bool invalid = false;
        char text[4096];
        char line[512];

        if (StringOption("mode", text, sizeof text, invalid))
        {
            if (!std::strcmp(text, "block")) g_policy.mode = Mode::Block;
            else if (!std::strcmp(text, "observe")) g_policy.mode = Mode::Observe;
            else { Log("option mode is neither block nor observe; nothing registered"); return false; }
        }
        if (StringOption("log", text, sizeof text, invalid))
        {
            if (!std::strcmp(text, "blocked")) g_policy.log = LogLevel::Blocked;
            else if (!std::strcmp(text, "all")) g_policy.log = LogLevel::All;
            else if (!std::strcmp(text, "none")) g_policy.log = LogLevel::None;
            else { Log("option log is not blocked, all or none; nothing registered"); return false; }
        }
        const char* names[] = {"analytics", "attribution", "crash", "engine"};
        for (int i = 0; i < 4; ++i) g_policy.categories[i] = BoolOption(names[i], true, invalid);

        if (StringOption("allowHosts", text, sizeof text, invalid))
            if (const int rejected = g_policy.allow.AddLines(text))
            {
                std::snprintf(line, sizeof line, "allowHosts: %d entries are not host names and were left out", rejected);
                Log(line);
            }
        if (StringOption("extraHosts", text, sizeof text, invalid))
            if (const int rejected = g_policy.extra.AddLines(text))
            {
                std::snprintf(line, sizeof line, "extraHosts: %d entries are not host names and were left out", rejected);
                Log(line);
            }
        if (invalid) { Log("an option has the wrong type or is too long; nothing registered"); return false; }
        return true;
    }

    /// The summary line init ends with.
    inline void LogPolicy()
    {
        char line[512];
        std::snprintf(line, sizeof line, "%s: %zu rules; analytics %s, attribution %s, crash %s, engine %s; %zu allowed, %zu extra, %zu protected",
                      g_policy.mode == Mode::Block ? "blocking" : "observing", sizeof generated::kRules / sizeof generated::kRules[0],
                      g_policy.categories[0] ? "on" : "off", g_policy.categories[1] ? "on" : "off",
                      g_policy.categories[2] ? "on" : "off", g_policy.categories[3] ? "on" : "off",
                      g_policy.allow.Count(), g_policy.extra.Count(), g_policy.protect.Count());
        Log(line);
    }

    /// Whether this decision gets its line now: it is one worth logging, and its name has not been logged before. The
    /// backend then finds the calling module, which costs a lookup, and calls Emit.
    inline bool FirstReport(const Decision& decision)
    {
        return g_policy.Logs(decision) && g_logged.Insert(decision.name);
    }

    inline void Emit(const Decision& decision, const char* api, const char* module)
    {
        char line[512];
        Describe(g_policy, decision, api, module, line, sizeof line);
        Log(line);
    }
}
