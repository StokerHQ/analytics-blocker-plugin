// The Windows backend (also what runs under Proton and Wine): every way a Windows program asks for a host's address,
// answered "not found" for a blocked host. All by named export, so ws2_32 and dnsapi are hooked whether the game loads
// them at start or later. The rules and options are the portable core's (core/blocker.h, manifest.h).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <intrin.h>

#include "stoker/plugin_support.h"

#include "manifest.h"

#pragma intrinsic(_ReturnAddress)

namespace analytics_blocker
{
    namespace
    {
        /// The file name of the module `address` is in, as UTF-8, for the log line.
        void ModuleOf(void* address, char (&out)[128])
        {
            out[0] = '\0';
            HMODULE module = nullptr;
            wchar_t path[MAX_PATH];
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    static_cast<LPCWSTR>(address), &module)) return;
            const DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
            if (!length || length >= MAX_PATH) return;
            const wchar_t* name = stoker::plugin::FileName(path);
            if (!WideCharToMultiByte(CP_UTF8, 0, name, -1, out, sizeof out, nullptr, nullptr)) out[0] = '\0';
        }

        /// The decision for a name, its log line written if it is the first of its kind. Leaves the thread's last
        /// error as it found it, so a call passed on to the original sees the state the game left.
        Decision Judge(const char* name, const char* api, void* caller)
        {
            const DWORD error = GetLastError();
            Decision decision = g_policy.Decide(name);
            if (FirstReport(decision))
            {
                char module[128];
                ModuleOf(caller, module);
                Emit(decision, api, module);
            }
            SetLastError(error);
            return decision;
        }

        Decision Judge(const wchar_t* name, const char* api, void* caller)
        {
            if (!name) return {};
            const DWORD error = GetLastError();
            char utf8[kMaxName];
            const bool converted = WideCharToMultiByte(CP_UTF8, 0, name, -1, utf8, sizeof utf8, nullptr, nullptr) > 0;
            SetLastError(error);
            return converted ? Judge(utf8, api, caller) : Decision{};
        }

        using GetAddrInfoA_t = INT(WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
        using GetAddrInfoW_t = INT(WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
        using GetAddrInfoExA_t = INT(WSAAPI*)(PCSTR, PCSTR, DWORD, LPGUID, const ADDRINFOEXA*, PADDRINFOEXA*, timeval*,
                                              LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
        using GetAddrInfoExW_t = INT(WSAAPI*)(PCWSTR, PCWSTR, DWORD, LPGUID, const ADDRINFOEXW*, PADDRINFOEXW*, timeval*,
                                              LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
        using GetHostByName_t = hostent*(WSAAPI*)(const char*);
        using DnsQueryW_t = DNS_STATUS(WINAPI*)(PCWSTR, WORD, DWORD, PVOID, PDNS_RECORD*, PVOID*);
        using DnsQueryA_t = DNS_STATUS(WINAPI*)(PCSTR, WORD, DWORD, PVOID, PDNS_RECORD*, PVOID*);
        using DnsQueryEx_t = DNS_STATUS(WINAPI*)(PDNS_QUERY_REQUEST, PDNS_QUERY_RESULT, PDNS_QUERY_CANCEL);

        alignas(void*) GetAddrInfoA_t g_getaddrinfo = nullptr;
        alignas(void*) GetAddrInfoW_t g_GetAddrInfoW = nullptr;
        alignas(void*) GetAddrInfoExA_t g_GetAddrInfoExA = nullptr;
        alignas(void*) GetAddrInfoExW_t g_GetAddrInfoExW = nullptr;
        alignas(void*) GetHostByName_t g_gethostbyname = nullptr;
        alignas(void*) DnsQueryW_t g_DnsQuery_W = nullptr;
        alignas(void*) DnsQueryA_t g_DnsQuery_A = nullptr;
        alignas(void*) DnsQueryA_t g_DnsQuery_UTF8 = nullptr;
        alignas(void*) DnsQueryEx_t g_DnsQueryEx = nullptr;

        // ws2_32. "Not found" is WSAHOST_NOT_FOUND, which is EAI_NONAME on Windows, returned and set as the last error.

        INT WSAAPI HookGetAddrInfoA(PCSTR name, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result)
        {
            if (!g_policy.Refuses(Judge(name, "getaddrinfo", _ReturnAddress()))) return g_getaddrinfo(name, service, hints, result);
            if (result) *result = nullptr;
            SetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }

        INT WSAAPI HookGetAddrInfoW(PCWSTR name, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result)
        {
            if (!g_policy.Refuses(Judge(name, "GetAddrInfoW", _ReturnAddress()))) return g_GetAddrInfoW(name, service, hints, result);
            if (result) *result = nullptr;
            SetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }

        // A refused GetAddrInfoEx fails synchronously, which the API allows even for an overlapped call: no completion
        // is queued and no handle is handed out, so the caller has nothing to wait for or cancel.
        INT WSAAPI HookGetAddrInfoExA(PCSTR name, PCSTR service, DWORD space, LPGUID provider, const ADDRINFOEXA* hints, PADDRINFOEXA* result,
                                      timeval* timeout, LPOVERLAPPED overlapped, LPLOOKUPSERVICE_COMPLETION_ROUTINE completion, LPHANDLE handle)
        {
            if (!g_policy.Refuses(Judge(name, "GetAddrInfoExA", _ReturnAddress())))
                return g_GetAddrInfoExA(name, service, space, provider, hints, result, timeout, overlapped, completion, handle);
            if (result) *result = nullptr;
            if (handle) *handle = nullptr;
            SetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }

        INT WSAAPI HookGetAddrInfoExW(PCWSTR name, PCWSTR service, DWORD space, LPGUID provider, const ADDRINFOEXW* hints, PADDRINFOEXW* result,
                                      timeval* timeout, LPOVERLAPPED overlapped, LPLOOKUPSERVICE_COMPLETION_ROUTINE completion, LPHANDLE handle)
        {
            if (!g_policy.Refuses(Judge(name, "GetAddrInfoExW", _ReturnAddress())))
                return g_GetAddrInfoExW(name, service, space, provider, hints, result, timeout, overlapped, completion, handle);
            if (result) *result = nullptr;
            if (handle) *handle = nullptr;
            SetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }

        hostent* WSAAPI HookGetHostByName(const char* name)
        {
            if (!g_policy.Refuses(Judge(name, "gethostbyname", _ReturnAddress()))) return g_gethostbyname(name);
            SetLastError(WSAHOST_NOT_FOUND);
            return nullptr;
        }

        // dnsapi. "Not found" is the server's NXDOMAIN, DNS_ERROR_RCODE_NAME_ERROR.

        DNS_STATUS WINAPI HookDnsQueryW(PCWSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD* results, PVOID* reserved)
        {
            if (!g_policy.Refuses(Judge(name, "DnsQuery_W", _ReturnAddress()))) return g_DnsQuery_W(name, type, options, extra, results, reserved);
            if (results) *results = nullptr;
            return DNS_ERROR_RCODE_NAME_ERROR;
        }

        DNS_STATUS WINAPI HookDnsQueryA(PCSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD* results, PVOID* reserved)
        {
            if (!g_policy.Refuses(Judge(name, "DnsQuery_A", _ReturnAddress()))) return g_DnsQuery_A(name, type, options, extra, results, reserved);
            if (results) *results = nullptr;
            return DNS_ERROR_RCODE_NAME_ERROR;
        }

        DNS_STATUS WINAPI HookDnsQueryUtf8(PCSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD* results, PVOID* reserved)
        {
            if (!g_policy.Refuses(Judge(name, "DnsQuery_UTF8", _ReturnAddress()))) return g_DnsQuery_UTF8(name, type, options, extra, results, reserved);
            if (results) *results = nullptr;
            return DNS_ERROR_RCODE_NAME_ERROR;
        }

        // Answered synchronously, as GetAddrInfoEx is: a status other than DNS_REQUEST_PENDING means the callback of an
        // asynchronous query is never called.
        DNS_STATUS WINAPI HookDnsQueryEx(PDNS_QUERY_REQUEST request, PDNS_QUERY_RESULT result, PDNS_QUERY_CANCEL cancel)
        {
            if (!request || !g_policy.Refuses(Judge(request->QueryName, "DnsQueryEx", _ReturnAddress()))) return g_DnsQueryEx(request, result, cancel);
            if (result)
            {
                result->QueryStatus = DNS_ERROR_RCODE_NAME_ERROR;
                result->pQueryRecords = nullptr;
            }
            return DNS_ERROR_RCODE_NAME_ERROR;
        }

        /// Adds the host of every STOKER_* variable that holds a URL - STOKER_URL, the instance, above all - to the
        /// hosts that are never blocked. Children inherit the environment, so they protect the same hosts.
        void ProtectStokerHosts()
        {
            wchar_t* block = GetEnvironmentStringsW();
            if (!block) return;
            for (const wchar_t* entry = block; *entry; entry += wcslen(entry) + 1)
            {
                if (_wcsnicmp(entry, L"STOKER_", 7) != 0) continue;
                const wchar_t* value = wcschr(entry, L'=');
                if (!value || !wcsstr(value, L"://")) continue;
                char utf8[2048];
                if (WideCharToMultiByte(CP_UTF8, 0, value + 1, -1, utf8, sizeof utf8, nullptr, nullptr) > 0) g_policy.protect.AddUrlHost(utf8);
            }
            FreeEnvironmentStringsW(block);
        }

        struct Target { const char* module; const char* function; void* detour; void** original; };
    }
}

STOKER_HOOK_PLUGIN_ENTRY int STOKER_HOOK_CALL stoker_hook_plugin_init(const stoker_hook_host_v1* host)
{
    using namespace analytics_blocker;
    if (!stoker::plugin::Accept(host)) return STOKER_HOOK_ERROR;
    g_host = host;

    bool here = true;
    if (!stoker::plugin::ForThisProcess(here)) { Log("option process is not a plain file name; nothing registered"); return STOKER_HOOK_INVALID_ARGUMENT; }
    if (!here) return STOKER_HOOK_OK;
    if (!ReadOptions()) return STOKER_HOOK_INVALID_ARGUMENT;
    ProtectStokerHosts();

    const Target targets[] = {
        {"ws2_32.dll", "getaddrinfo", reinterpret_cast<void*>(&HookGetAddrInfoA), reinterpret_cast<void**>(&g_getaddrinfo)},
        {"ws2_32.dll", "GetAddrInfoW", reinterpret_cast<void*>(&HookGetAddrInfoW), reinterpret_cast<void**>(&g_GetAddrInfoW)},
        {"ws2_32.dll", "GetAddrInfoExA", reinterpret_cast<void*>(&HookGetAddrInfoExA), reinterpret_cast<void**>(&g_GetAddrInfoExA)},
        {"ws2_32.dll", "GetAddrInfoExW", reinterpret_cast<void*>(&HookGetAddrInfoExW), reinterpret_cast<void**>(&g_GetAddrInfoExW)},
        {"ws2_32.dll", "gethostbyname", reinterpret_cast<void*>(&HookGetHostByName), reinterpret_cast<void**>(&g_gethostbyname)},
        {"dnsapi.dll", "DnsQuery_W", reinterpret_cast<void*>(&HookDnsQueryW), reinterpret_cast<void**>(&g_DnsQuery_W)},
        {"dnsapi.dll", "DnsQuery_A", reinterpret_cast<void*>(&HookDnsQueryA), reinterpret_cast<void**>(&g_DnsQuery_A)},
        {"dnsapi.dll", "DnsQuery_UTF8", reinterpret_cast<void*>(&HookDnsQueryUtf8), reinterpret_cast<void**>(&g_DnsQuery_UTF8)},
        {"dnsapi.dll", "DnsQueryEx", reinterpret_cast<void*>(&HookDnsQueryEx), reinterpret_cast<void**>(&g_DnsQueryEx)},
    };
    for (const Target& target : targets)
    {
        const int status = host->hook_export(host->user, target.module, target.function, target.detour, target.original);
        if (status != STOKER_HOOK_OK)
        {
            char line[256];
            std::snprintf(line, sizeof line, "could not register %s!%s (status %d); nothing registered", target.module, target.function, status);
            Log(line);
            return status;
        }
    }
    LogPolicy();
    return STOKER_HOOK_OK;
}
