// Bazarish project (c) 2026
#include "FederationPool.hpp"

#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish::server;

int main()
{
    // Deterministic: the same fingerprint maps to the same pool entry every time
    // (so a user keeps the same destination across restarts).
    CHECK(poolIndexFor("alicefingerprint", 10) == poolIndexFor("alicefingerprint", 10));

    // Always in range, for a few pool sizes.
    for (int i = 0; i < 200; ++i) {
        const std::string fp = "user-" + std::to_string(i);
        CHECK(poolIndexFor(fp, 10) < 10);
        CHECK(poolIndexFor(fp, 3) < 3);
    }

    // A single-entry pool always maps to 0; an empty pool returns 0 (no modulo by 0).
    CHECK(poolIndexFor("anyone", 1) == 0);
    CHECK(poolIndexFor("anyone", 0) == 0);

    // Spreads users across the pool rather than piling them on one entry.
    std::set<std::size_t> buckets;
    for (int i = 0; i < 200; ++i) {
        buckets.insert(poolIndexFor("user-" + std::to_string(i), 10));
    }
    CHECK(buckets.size() >= 8);  // 200 users over 10 entries should touch most

    // Distinct fingerprints are not all forced to the same entry.
    CHECK(poolIndexFor("alpha", 10) != poolIndexFor("alpha", 10) + 1);  // sanity: stable
    bool anyDiffer = false;
    for (int i = 1; i < 20 && !anyDiffer; ++i) {
        anyDiffer = poolIndexFor("alpha", 10) != poolIndexFor("user-" + std::to_string(i), 10);
    }
    CHECK(anyDiffer);

    std::printf("TestFederationPool OK\n");
    return 0;
}
