// The portable core: what a name is, whether it is blocked, and what is never blocked. No OS calls and no allocation,
// so the hooks can ask it from any thread, inside any resolver call; both backends and the unit tests include it.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "rules.h"
#include "../generated/rules.h"

namespace analytics_blocker
{
    constexpr size_t kMaxName = 254;   // 253 characters and the terminator

    inline char Lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

    /// `raw` as the rules compare names: lower case, a trailing dot removed. False for what is not a host name the
    /// rules could match - empty, too long, or with a character outside letters, digits, '-', '_' and '.' (a name in
    /// Unicode reaches the resolver as punycode only after this point, and no rule is written in Unicode).
    inline bool NormalizeName(const char* raw, char (&out)[kMaxName])
    {
        if (!raw) return false;
        size_t length = 0;
        for (; raw[length]; ++length)
        {
            if (length >= kMaxName - 1) return false;
            const char c = Lower(raw[length]);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return false;
            out[length] = c;
        }
        if (length && out[length - 1] == '.') --length;
        if (!length) return false;
        out[length] = '\0';
        return true;
    }

    /// Dotted digits: an IPv4 literal (or a bare number, which resolvers also read as an address). IPv6 literals never
    /// get this far - ':' is not a name character. Literals are not names, and the rules are names.
    inline bool IsAddressLiteral(const char* name)
    {
        for (const char* c = name; *c; ++c)
            if (!((*c >= '0' && *c <= '9') || *c == '.')) return false;
        return true;
    }

    inline bool EndsWithLabel(const char* name, size_t nameLength, const char* suffix, size_t suffixLength)
    {
        return nameLength > suffixLength && name[nameLength - suffixLength - 1] == '.' &&
               std::memcmp(name + nameLength - suffixLength, suffix, suffixLength) == 0;
    }

    /// A rule's or an option's pattern against a normalised name.
    inline bool PatternMatches(const char* pattern, bool subdomains, const char* name)
    {
        const size_t p = std::strlen(pattern), n = std::strlen(name);
        if (p == n && std::memcmp(pattern, name, n) == 0) return true;
        return subdomains && EndsWithLabel(name, n, pattern, p);
    }

    /// "localhost" and every name under it: RFC 6761 reserves them for this machine, where the launcher and Stoker's
    /// local services listen.
    inline bool IsLoopbackName(const char* name) { return PatternMatches("localhost", true, name); }

    /// Host patterns from an option or the environment, held in fixed storage. A pattern is a name, or "*." and a name.
    class HostList
    {
    public:
        static constexpr size_t kCapacity = 64;
        static constexpr size_t kStorage = 4096;

        /// Adds one pattern; false (and nothing added) when it is not a host pattern or the list is full.
        bool Add(const char* text, size_t length)
        {
            bool subdomains = false;
            if (length >= 2 && text[0] == '*' && text[1] == '.') { subdomains = true; text += 2; length -= 2; }
            if (!length || length >= kMaxName || count_ == kCapacity) return false;
            char raw[kMaxName];
            std::memcpy(raw, text, length);
            raw[length] = '\0';
            char name[kMaxName];
            if (!NormalizeName(raw, name)) return false;
            const size_t size = std::strlen(name) + 1;
            if (used_ + size > kStorage) return false;
            std::memcpy(storage_ + used_, name, size);
            entries_[count_++] = {storage_ + used_, subdomains};
            used_ += size;
            return true;
        }

        /// Patterns separated by line breaks, commas or spaces; a '#' starts a comment to the end of its line.
        /// Returns how many could not be read as host patterns (and were left out).
        int AddLines(const char* text)
        {
            int rejected = 0;
            while (text && *text)
            {
                if (*text == '#') { while (*text && *text != '\n') ++text; continue; }
                if (*text == '\n' || *text == '\r' || *text == ',' || *text == ' ' || *text == '\t') { ++text; continue; }
                const char* start = text;
                while (*text && *text != '\n' && *text != '\r' && *text != ',' && *text != ' ' && *text != '\t' && *text != '#') ++text;
                if (!Add(start, static_cast<size_t>(text - start))) ++rejected;
            }
            return rejected;
        }

        /// The host of a URL ("scheme://[user@]host[:port][/...]", or "[v6]" as host), added as an exact name.
        /// False when there is no host name in it; an address literal is not added, as literals are never blocked.
        bool AddUrlHost(const char* url)
        {
            const char* scheme = url ? std::strstr(url, "://") : nullptr;
            if (!scheme) return false;
            const char* host = scheme + 3;
            const char* end = host;
            while (*end && *end != '/' && *end != '?' && *end != '#') ++end;
            for (const char* at = host; at < end; ++at)
                if (*at == '@') host = at + 1;
            if (host < end && *host == '[') return false;
            const char* colon = host;
            while (colon < end && *colon != ':') ++colon;
            return Add(host, static_cast<size_t>(colon - host));
        }

        bool Matches(const char* name) const
        {
            for (size_t i = 0; i < count_; ++i)
                if (PatternMatches(entries_[i].name, entries_[i].subdomains, name)) return true;
            return false;
        }

        size_t Count() const { return count_; }

    private:
        struct Entry { const char* name; bool subdomains; };
        char storage_[kStorage] = {};
        Entry entries_[kCapacity] = {};
        size_t used_ = 0, count_ = 0;
    };

    enum class Mode { Block, Observe };
    enum class LogLevel { None, Blocked, All };

    enum class Verdict
    {
        NotAName,    // nothing a rule could match: no name, an address literal, characters no host name has
        Protected,   // loopback, or a host Stoker itself needs - never blocked, whatever the options say
        Allowed,     // in allowHosts
        Pass,        // no rule matches
        Block,       // a rule of a switched-on category, or extraHosts, matches
    };

    struct Decision
    {
        Verdict verdict = Verdict::NotAName;
        Category category = Category::Extra;
        const char* vendor = nullptr;
        char name[kMaxName] = {};
    };

    /// What the plugin was configured to do, filled once at init and only read afterwards.
    struct Policy
    {
        Mode mode = Mode::Block;
        LogLevel log = LogLevel::Blocked;
        bool categories[4] = {true, true, true, true};   // Analytics, Attribution, Crash, Engine
        HostList allow, extra, protect;

        bool CategoryOn(Category category) const
        {
            return category == Category::Extra || categories[static_cast<int>(category)];
        }

        /// What happens to `raw`. The order is the guarantee: what Stoker needs comes first, then the operator's
        /// allowHosts, then the rules.
        Decision Decide(const char* raw) const
        {
            Decision decision;
            if (!NormalizeName(raw, decision.name) || IsAddressLiteral(decision.name)) return decision;
            if (IsLoopbackName(decision.name) || protect.Matches(decision.name)) { decision.verdict = Verdict::Protected; return decision; }
            if (allow.Matches(decision.name)) { decision.verdict = Verdict::Allowed; return decision; }
            for (const Rule& rule : generated::kRules)
            {
                if (!CategoryOn(rule.category) || !PatternMatches(rule.name, rule.subdomains, decision.name)) continue;
                decision.verdict = Verdict::Block;
                decision.category = rule.category;
                decision.vendor = rule.vendor;
                return decision;
            }
            if (extra.Matches(decision.name))
            {
                decision.verdict = Verdict::Block;
                decision.vendor = "extraHosts";
                return decision;
            }
            decision.verdict = Verdict::Pass;
            return decision;
        }

        /// Whether the hook answers "not found" for this decision.
        bool Refuses(const Decision& decision) const { return mode == Mode::Block && decision.verdict == Verdict::Block; }

        /// Whether a decision is worth a log line (the first time its name is seen).
        bool Logs(const Decision& decision) const
        {
            if (decision.verdict == Verdict::NotAName) return false;
            if (mode == Mode::Observe || log == LogLevel::All) return true;
            return log == LogLevel::Blocked && decision.verdict == Verdict::Block;
        }
    };

    /// Names already logged, so each is logged once per process however often the game asks. Lock-free open
    /// addressing over 64-bit hashes; when it is full, nothing more is logged (Insert returns false), which costs
    /// lines, never a call.
    class OnceSet
    {
    public:
        static constexpr size_t kSlots = 2048;

        static uint64_t Hash(const char* text)
        {
            uint64_t hash = 1469598103934665603ull;
            for (; *text; ++text) { hash ^= static_cast<unsigned char>(*text); hash *= 1099511628211ull; }
            return hash ? hash : 1;   // 0 marks an empty slot
        }

        /// True the first time `text` is inserted.
        bool Insert(const char* text)
        {
            const uint64_t hash = Hash(text);
            for (size_t probe = 0; probe < kSlots; ++probe)
            {
                auto& slot = slots_[(hash + probe) % kSlots];
                uint64_t current = slot.load(std::memory_order_acquire);
                if (current == hash) return false;
                if (current == 0)
                {
                    if (slot.compare_exchange_strong(current, hash, std::memory_order_acq_rel)) return true;
                    if (current == hash) return false;
                }
            }
            return false;
        }

    private:
        std::atomic<uint64_t> slots_[kSlots] = {};
    };

    /// The line a logged decision gets: "<verb> <name> (<api>, from <module>)[: <category>, <vendor>]".
    inline void Describe(const Policy& policy, const Decision& decision, const char* api, const char* module, char* out, size_t capacity)
    {
        const char* verb = "resolved";
        switch (decision.verdict)
        {
        case Verdict::Block: verb = policy.mode == Mode::Block ? "blocked" : "would block"; break;
        case Verdict::Protected: verb = "protected"; break;
        case Verdict::Allowed: verb = "allowed"; break;
        default: break;
        }
        size_t used = 0;
        auto append = [&](const char* text) {
            for (; text && *text && used + 1 < capacity; ++text) out[used++] = *text;
        };
        append(verb); append(" "); append(decision.name); append(" ("); append(api); append(", from ");
        append(module && *module ? module : "?"); append(")");
        if (decision.verdict == Verdict::Block) { append(": "); append(CategoryName(decision.category)); append(", "); append(decision.vendor); }
        if (capacity) out[used < capacity ? used : capacity - 1] = '\0';
    }
}
