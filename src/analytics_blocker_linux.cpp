// The Linux backend, for native x86-64 games under the Linux hook host: libc's resolver functions, answered "not found"
// for a blocked host. The hook host patches each function's own code, so a call that reaches it from inside libc - the
// worker getaddrinfo_a starts, a statically linked libcurl calling the exported getaddrinfo - is judged too. glibc's
// gethostbyname family does not go through getaddrinfo, so each of its functions is hooked on its own.
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>

#include "manifest.h"

extern char** environ;

namespace analytics_blocker
{
    namespace
    {
        constexpr const char* kLibc = "libc.so.6";

        /// The file name of the object `address` is in, for the log line.
        void ModuleOf(void* address, char (&out)[128])
        {
            out[0] = '\0';
            Dl_info info{};
            if (!dladdr(address, &info) || !info.dli_fname) return;
            const char* name = info.dli_fname;
            for (const char* c = info.dli_fname; *c; ++c)
                if (*c == '/') name = c + 1;
            std::snprintf(out, sizeof out, "%s", *name ? name : "the executable");
        }

        /// The decision for a name, its log line written if it is the first of its kind. errno is left as it was.
        Decision Judge(const char* name, const char* api, void* caller)
        {
            const int error = errno;
            Decision decision = g_policy.Decide(name);
            if (FirstReport(decision))
            {
                char module[128];
                ModuleOf(caller, module);
                Emit(decision, api, module);
            }
            errno = error;
            return decision;
        }

        using GetAddrInfo_t = int (*)(const char*, const char*, const addrinfo*, addrinfo**);
        using GetHostByName_t = hostent* (*)(const char*);
        using GetHostByName2_t = hostent* (*)(const char*, int);
        using GetHostByNameR_t = int (*)(const char*, hostent*, char*, size_t, hostent**, int*);
        using GetHostByName2R_t = int (*)(const char*, int, hostent*, char*, size_t, hostent**, int*);

        alignas(void*) GetAddrInfo_t g_getaddrinfo = nullptr;
        alignas(void*) GetHostByName_t g_gethostbyname = nullptr;
        alignas(void*) GetHostByName2_t g_gethostbyname2 = nullptr;
        alignas(void*) GetHostByNameR_t g_gethostbyname_r = nullptr;
        alignas(void*) GetHostByName2R_t g_gethostbyname2_r = nullptr;

        int HookGetAddrInfo(const char* name, const char* service, const addrinfo* hints, addrinfo** result)
        {
            if (!g_policy.Refuses(Judge(name, "getaddrinfo", __builtin_return_address(0)))) return g_getaddrinfo(name, service, hints, result);
            if (result) *result = nullptr;
            return EAI_NONAME;
        }

        hostent* HookGetHostByName(const char* name)
        {
            if (!g_policy.Refuses(Judge(name, "gethostbyname", __builtin_return_address(0)))) return g_gethostbyname(name);
            h_errno = HOST_NOT_FOUND;
            return nullptr;
        }

        hostent* HookGetHostByName2(const char* name, int family)
        {
            if (!g_policy.Refuses(Judge(name, "gethostbyname2", __builtin_return_address(0)))) return g_gethostbyname2(name, family);
            h_errno = HOST_NOT_FOUND;
            return nullptr;
        }

        // As glibc answers a name that does not exist: no result, HOST_NOT_FOUND, and ENOENT as the return value.
        int HookGetHostByNameR(const char* name, hostent* entry, char* buffer, size_t length, hostent** result, int* error)
        {
            if (!g_policy.Refuses(Judge(name, "gethostbyname_r", __builtin_return_address(0))))
                return g_gethostbyname_r(name, entry, buffer, length, result, error);
            if (result) *result = nullptr;
            if (error) *error = HOST_NOT_FOUND;
            return ENOENT;
        }

        int HookGetHostByName2R(const char* name, int family, hostent* entry, char* buffer, size_t length, hostent** result, int* error)
        {
            if (!g_policy.Refuses(Judge(name, "gethostbyname2_r", __builtin_return_address(0))))
                return g_gethostbyname2_r(name, family, entry, buffer, length, result, error);
            if (result) *result = nullptr;
            if (error) *error = HOST_NOT_FOUND;
            return ENOENT;
        }

        /// The `process` option: only in the executable of that file name. False for a value that is not a plain file
        /// name.
        bool ForThisProcess(bool& here)
        {
            here = true;
            char wanted[256] = "";
            bool invalid = false;
            if (!StringOption("process", wanted, sizeof wanted, invalid)) return !invalid;
            if (!wanted[0]) return true;
            if (std::strchr(wanted, '/') || !std::strcmp(wanted, ".") || !std::strcmp(wanted, "..")) return false;
            char self[4096];
            const ssize_t length = readlink("/proc/self/exe", self, sizeof self - 1);
            if (length <= 0) return false;
            self[length] = '\0';
            const char* name = std::strrchr(self, '/');
            here = std::strcmp(name ? name + 1 : self, wanted) == 0;
            if (!here)
            {
                char line[320];
                std::snprintf(line, sizeof line, "not %s; nothing to do in this process", wanted);
                Log(line);
            }
            return true;
        }

        /// Adds the host of every STOKER_* variable that holds a URL - STOKER_URL, the instance, above all - to the
        /// hosts that are never blocked.
        void ProtectStokerHosts()
        {
            for (char** entry = environ; entry && *entry; ++entry)
            {
                if (std::strncmp(*entry, "STOKER_", 7) != 0) continue;
                const char* value = std::strchr(*entry, '=');
                if (value && std::strstr(value, "://")) g_policy.protect.AddUrlHost(value + 1);
            }
        }

        struct Target { const char* function; void* detour; void** original; };
    }
}

STOKER_HOOK_PLUGIN_ENTRY int STOKER_HOOK_CALL stoker_hook_plugin_init(const stoker_hook_host_v1* host)
{
    using namespace analytics_blocker;
    if (!host || host->abi_version != STOKER_HOOK_PLUGIN_ABI || host->struct_size < STOKER_HOOK_HOST_V1_MIN_SIZE) return STOKER_HOOK_ERROR;
    g_host = host;

    bool here = true;
    if (!ForThisProcess(here)) { Log("option process is not a plain file name; nothing registered"); return STOKER_HOOK_INVALID_ARGUMENT; }
    if (!here) return STOKER_HOOK_OK;
    if (!ReadOptions()) return STOKER_HOOK_INVALID_ARGUMENT;
    ProtectStokerHosts();

    const Target targets[] = {
        {"getaddrinfo", reinterpret_cast<void*>(&HookGetAddrInfo), reinterpret_cast<void**>(&g_getaddrinfo)},
        {"gethostbyname", reinterpret_cast<void*>(&HookGetHostByName), reinterpret_cast<void**>(&g_gethostbyname)},
        {"gethostbyname2", reinterpret_cast<void*>(&HookGetHostByName2), reinterpret_cast<void**>(&g_gethostbyname2)},
        {"gethostbyname_r", reinterpret_cast<void*>(&HookGetHostByNameR), reinterpret_cast<void**>(&g_gethostbyname_r)},
        {"gethostbyname2_r", reinterpret_cast<void*>(&HookGetHostByName2R), reinterpret_cast<void**>(&g_gethostbyname2_r)},
    };
    for (const Target& target : targets)
    {
        const int status = host->hook_export(host->user, kLibc, target.function, target.detour, target.original);
        if (status != STOKER_HOOK_OK)
        {
            char line[256];
            std::snprintf(line, sizeof line, "could not register %s!%s (status %d); nothing registered", kLibc, target.function, status);
            Log(line);
            return status;
        }
    }
    LogPolicy();
    return STOKER_HOOK_OK;
}
