// Bazarish project (c) 2026
#include "GrantStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::service;

int main()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-grants-" + toHex(randomBytes(8)));
    const std::string user = Identity::generate().fingerprint();

    {
        GrantStore grants(root);
        CHECK(!grants.peekSubscription(user).has_value());

        grants.grantSubscription(user, 5ULL * 1024 * 1024 * 1024, 30 * 24 * 3600, 1000);
        const std::optional<GrantStore::SubscriptionGrant> peeked = grants.peekSubscription(user);
        CHECK(peeked.has_value());
        CHECK(peeked->quotaBytes == 5ULL * 1024 * 1024 * 1024);
        CHECK(peeked->termSeconds == 30 * 24 * 3600);
        CHECK(peeked->grantedAt == 1000);
    }
    {
        // Persistence across reopen, then a one-shot take.
        GrantStore grants(root);
        const std::optional<GrantStore::SubscriptionGrant> taken = grants.takeSubscription(user);
        CHECK(taken.has_value());
        CHECK(taken->quotaBytes == 5ULL * 1024 * 1024 * 1024);
        CHECK(!grants.peekSubscription(user).has_value());     // consumed
        CHECK(!grants.takeSubscription(user).has_value());     // nothing left
    }

    fs::remove_all(root);
    std::printf("TestGrantStore: all checks passed\n");
    return 0;
}
