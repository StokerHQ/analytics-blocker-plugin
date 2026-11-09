// What a rule is. The table itself is generated from rules/hosts.yaml (src/generated/rules.h).
#pragma once

namespace analytics_blocker
{
    /// Each category is switched by the option of the same name. Extra is the operator's own extraHosts.
    enum class Category : unsigned char { Analytics, Attribution, Crash, Engine, Extra };

    /// A host the plugin blocks: `name` exactly, or with `subdomains` also every name ending in "." + name.
    /// `name` is lower-case ASCII without a trailing dot, as the generator checks.
    struct Rule
    {
        const char* name;
        bool subdomains;
        Category category;
        const char* vendor;
    };

    constexpr const char* CategoryName(Category category)
    {
        switch (category)
        {
        case Category::Analytics: return "analytics";
        case Category::Attribution: return "attribution";
        case Category::Crash: return "crash";
        case Category::Engine: return "engine";
        case Category::Extra: return "extra";
        }
        return "unknown";
    }
}
