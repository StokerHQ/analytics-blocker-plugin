// The portable core's tests: names, patterns, the order of the decision, the option lists, the log-once table.
// Built with MSVC and g++ (CI runs both); exit code 0 is a pass.
#include <cstdio>
#include <cstring>
#include <string>

#include "../src/core/blocker.h"

using namespace analytics_blocker;

static int g_failures = 0;
#define CHECK(condition)                                                                   \
    do {                                                                                   \
        if (!(condition)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #condition); ++g_failures; } \
    } while (0)

static std::string Normal(const char* raw)
{
    char out[kMaxName];
    return NormalizeName(raw, out) ? std::string(out) : std::string("<none>");
}

static void Names()
{
    CHECK(Normal("API.GameAnalytics.COM") == "api.gameanalytics.com");
    CHECK(Normal("o1.ingest.sentry.io.") == "o1.ingest.sentry.io");
    CHECK(Normal("") == "<none>");
    CHECK(Normal(".") == "<none>");
    CHECK(Normal(nullptr) == "<none>");
    CHECK(Normal("bad host") == "<none>");
    CHECK(Normal("::1") == "<none>");
    CHECK(Normal("b\xc3\xbc" "cher.example") == "<none>");
    CHECK(Normal(std::string(253, 'a').c_str()) == std::string(253, 'a'));
    CHECK(Normal(std::string(254, 'a').c_str()) == "<none>");
    CHECK(IsAddressLiteral("127.0.0.1"));
    CHECK(IsAddressLiteral("2130706433"));
    CHECK(!IsAddressLiteral("1.example.com"));
}

static void Patterns()
{
    CHECK(PatternMatches("sentry.io", false, "sentry.io"));
    CHECK(!PatternMatches("sentry.io", false, "o1.sentry.io"));
    CHECK(PatternMatches("ingest.sentry.io", true, "ingest.sentry.io"));
    CHECK(PatternMatches("ingest.sentry.io", true, "o1.ingest.sentry.io"));
    CHECK(!PatternMatches("sentry.io", true, "notsentry.io"));
    CHECK(!PatternMatches("sentry.io", true, "sentry.io.example.com"));
    CHECK(IsLoopbackName("localhost"));
    CHECK(IsLoopbackName("agent.localhost"));
    CHECK(!IsLoopbackName("localhost.example.com"));
}

static void Lists()
{
    HostList list;
    CHECK(list.AddLines("# comment\n*.Example.com, other.net\r\n  third.org # trailing\nnot/a/host\n*.\n") == 2);
    CHECK(list.Count() == 3);
    CHECK(list.Matches("a.example.com"));
    CHECK(list.Matches("example.com"));
    CHECK(list.Matches("other.net"));
    CHECK(!list.Matches("a.other.net"));
    CHECK(list.Matches("third.org"));

    HostList urls;
    CHECK(urls.AddUrlHost("https://Games.Example.net:8443/v1/x"));
    CHECK(urls.AddUrlHost("http://user:pw@stoker.lan/"));
    CHECK(urls.AddUrlHost("https://bare.example"));
    CHECK(!urls.AddUrlHost("https://[::1]:5000/"));
    CHECK(!urls.AddUrlHost("no scheme here"));
    CHECK(urls.Matches("games.example.net"));
    CHECK(urls.Matches("stoker.lan"));
    CHECK(urls.Matches("bare.example"));
    CHECK(!urls.Matches("sub.games.example.net"));

    HostList full;
    int added = 0;
    for (int i = 0; i < 100; ++i)
    {
        const std::string name = "host" + std::to_string(i) + ".example";
        added += full.Add(name.c_str(), name.size());
    }
    CHECK(added == static_cast<int>(HostList::kCapacity));
}

static void Decisions()
{
    Policy policy;
    CHECK(policy.Decide("api.gameanalytics.com").verdict == Verdict::Block);
    CHECK(policy.Decide("API.GAMEANALYTICS.COM.").verdict == Verdict::Block);
    CHECK(policy.Decide("gameanalytics.com").verdict == Verdict::Block);
    CHECK(policy.Decide("o123.ingest.us.sentry.io").category == Category::Crash);
    CHECK(policy.Decide("datarouter.ol.epicgames.com").category == Category::Engine);
    CHECK(policy.Decide("store.epicgames.com").verdict == Verdict::Pass);
    CHECK(policy.Decide("config.unity3d.com").verdict == Verdict::Pass);
    CHECK(policy.Decide("example.com").verdict == Verdict::Pass);
    CHECK(policy.Decide("127.0.0.1").verdict == Verdict::NotAName);
    CHECK(policy.Decide("localhost").verdict == Verdict::Protected);

    // A category switched off lets its hosts through; the others still block.
    policy.categories[static_cast<int>(Category::Crash)] = false;
    CHECK(policy.Decide("o1.ingest.sentry.io").verdict == Verdict::Pass);
    CHECK(policy.Decide("api.gameanalytics.com").verdict == Verdict::Block);

    // allowHosts beats a rule; extraHosts adds one; neither touches what is protected.
    policy.allow.AddLines("api.gameanalytics.com");
    policy.extra.AddLines("*.telemetry.example\nlocalhost\ngames.example.net");
    policy.protect.AddUrlHost("https://games.example.net/");
    CHECK(policy.Decide("api.gameanalytics.com").verdict == Verdict::Allowed);
    CHECK(policy.Decide("eu.gameanalytics.com").verdict == Verdict::Block);
    const Decision extra = policy.Decide("a.telemetry.example");
    CHECK(extra.verdict == Verdict::Block && extra.category == Category::Extra);
    CHECK(policy.Decide("localhost").verdict == Verdict::Protected);
    CHECK(policy.Decide("games.example.net").verdict == Verdict::Protected);

    // Refused only in block mode; logged as the level says.
    const Decision blocked = policy.Decide("eu.gameanalytics.com");
    const Decision passed = policy.Decide("example.com");
    CHECK(policy.Refuses(blocked));
    CHECK(!policy.Refuses(passed));
    CHECK(policy.Logs(blocked) && !policy.Logs(passed));
    policy.log = LogLevel::None;
    CHECK(!policy.Logs(blocked));
    policy.log = LogLevel::All;
    CHECK(policy.Logs(passed) && !policy.Logs(policy.Decide("1.2.3.4")));
    policy.mode = Mode::Observe;
    policy.log = LogLevel::None;
    CHECK(!policy.Refuses(blocked));
    CHECK(policy.Logs(passed));

    char line[256];
    Describe(policy, blocked, "getaddrinfo", "sentry.dll", line, sizeof line);
    CHECK(std::strcmp(line, "would block eu.gameanalytics.com (getaddrinfo, from sentry.dll): analytics, GameAnalytics") == 0);
    policy.mode = Mode::Block;
    Describe(policy, passed, "GetAddrInfoW", nullptr, line, sizeof line);
    CHECK(std::strcmp(line, "resolved example.com (GetAddrInfoW, from ?)") == 0);
    Describe(policy, blocked, "getaddrinfo", "x.dll", line, 12);
    CHECK(std::strlen(line) == 11);
}

static void Once()
{
    static OnceSet set;
    CHECK(set.Insert("a.example"));
    CHECK(!set.Insert("a.example"));
    CHECK(set.Insert("b.example"));
    int inserted = 0;
    for (int i = 0; i < 5000; ++i) inserted += set.Insert(("n" + std::to_string(i)).c_str());
    CHECK(inserted <= static_cast<int>(OnceSet::kSlots));
    CHECK(!set.Insert("a.example"));
}

static void GeneratedRules()
{
    for (const Rule& rule : generated::kRules)
    {
        char out[kMaxName];
        CHECK(NormalizeName(rule.name, out) && std::strcmp(out, rule.name) == 0);
        CHECK(rule.vendor && *rule.vendor);
        CHECK(rule.category != Category::Extra);
    }
}

int main()
{
    Names();
    Patterns();
    Lists();
    Decisions();
    Once();
    GeneratedRules();
    if (g_failures) { std::printf("%d failed\n", g_failures); return 1; }
    std::printf("core tests: PASS\n");
    return 0;
}
