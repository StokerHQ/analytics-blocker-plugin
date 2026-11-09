// A stand-in game for Test-InHookHost.ps1: resolves each name it is given through every API the plugin hooks and
// appends "<arch> <api> <name> <status>" to the file AB_OUT names (status 0 is an answer). "spawn <exe> <names...>"
// first starts <exe> with the names and waits for it - a child of the game, which the carrier gives the same modules.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

#ifdef _WIN64
static const char* kArch = "x64";
#else
static const char* kArch = "x86";
#endif

static void Write(const char* api, const char* name, long status)
{
    char path[1024];
    if (!GetEnvironmentVariableA("AB_OUT", path, sizeof path)) return;
    FILE* out = nullptr;
    for (int attempt = 0; attempt < 50 && !out; ++attempt)
        if (fopen_s(&out, path, "a") != 0) { out = nullptr; Sleep(20); }
    if (!out) return;
    std::fprintf(out, "%s %s %s %ld\n", kArch, api, name, status);
    std::fclose(out);
}

static void Resolve(const char* name)
{
    wchar_t wide[256];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wide, 256);

    ADDRINFOA* a = nullptr;
    int status = getaddrinfo(name, "80", nullptr, &a);
    Write("getaddrinfo", name, status);
    if (!status) freeaddrinfo(a);

    ADDRINFOW* w = nullptr;
    status = GetAddrInfoW(wide, L"80", nullptr, &w);
    Write("GetAddrInfoW", name, status);
    if (!status) FreeAddrInfoW(w);

    ADDRINFOEXW* exw = nullptr;
    status = GetAddrInfoExW(wide, L"80", NS_ALL, nullptr, nullptr, &exw, nullptr, nullptr, nullptr, nullptr);
    Write("GetAddrInfoExW", name, status);
    if (!status) FreeAddrInfoExW(exw);

    ADDRINFOEXA* exa = nullptr;
    status = GetAddrInfoExA(name, "80", NS_ALL, nullptr, nullptr, &exa, nullptr, nullptr, nullptr, nullptr);
    Write("GetAddrInfoExA", name, status);
    if (!status) FreeAddrInfoEx(exa);

#pragma warning(suppress : 4996)
    const hostent* host = gethostbyname(name);
    Write("gethostbyname", name, host ? 0 : WSAGetLastError());

    PDNS_RECORD records = nullptr;
    DNS_STATUS dns = DnsQuery_W(wide, DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
    Write("DnsQuery_W", name, dns);
    if (!dns && records) DnsRecordListFree(records, DnsFreeRecordList);

    records = nullptr;
    dns = DnsQuery_A(name, DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
    Write("DnsQuery_A", name, dns);
    if (!dns && records) DnsRecordListFree(records, DnsFreeRecordList);

    records = nullptr;
    dns = DnsQuery_UTF8(name, DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
    Write("DnsQuery_UTF8", name, dns);
    if (!dns && records) DnsRecordListFree(records, DnsFreeRecordList);

    DNS_QUERY_REQUEST request{};
    request.Version = DNS_QUERY_REQUEST_VERSION1;
    request.QueryName = wide;
    request.QueryType = DNS_TYPE_A;
    request.QueryOptions = DNS_QUERY_STANDARD;
    DNS_QUERY_RESULT result{};
    result.Version = DNS_QUERY_REQUEST_VERSION1;
    dns = DnsQueryEx(&request, &result, nullptr);
    Write("DnsQueryEx", name, dns);
    if (!dns && result.pQueryRecords) DnsRecordListFree(result.pQueryRecords, DnsFreeRecordList);
}

int main(int argc, char** argv)
{
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
    int first = 1;
    if (argc > 2 && !std::strcmp(argv[1], "spawn"))
    {
        std::string command = std::string("\"") + argv[2] + "\"";
        for (int i = 3; i < argc; ++i) command += std::string(" ") + argv[i];
        STARTUPINFOA startup{sizeof startup};
        PROCESS_INFORMATION process{};
        if (CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &process))
        {
            WaitForSingleObject(process.hProcess, 60000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        else Write("spawn", argv[2], static_cast<long>(GetLastError()));
        return 0;
    }
    for (int i = first; i < argc; ++i) Resolve(argv[i]);
    return 0;
}
