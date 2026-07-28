// Bazarish project (c) 2026
#include "FederationRateLimiter.hpp"

#include <cstdio>
#include <cstdlib>
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
    // At most 3 inbound deliveries per 60s window, counted per peer destination.
    FederationRateLimiter limiter(3, 60);

    const std::string alice = "alice.b32.i2p";
    const std::string bob = "bob.b32.i2p";

    // An empty peer destination (e.g. a non-I2P transport) is never limited.
    for (int i = 0; i < 100; ++i) {
        CHECK(limiter.allow("", 1000));
    }

    // The first three from one peer in a window pass; further ones are dropped,
    // including a later attempt still inside the same 60s window.
    CHECK(limiter.allow(alice, 1000));
    CHECK(limiter.allow(alice, 1000));
    CHECK(limiter.allow(alice, 1000));
    CHECK(!limiter.allow(alice, 1000));
    CHECK(!limiter.allow(alice, 1059));

    // A different peer has an independent budget within the same window.
    CHECK(limiter.allow(bob, 1000));
    CHECK(limiter.allow(bob, 1030));
    CHECK(limiter.allow(bob, 1059));
    CHECK(!limiter.allow(bob, 1059));

    // Once the window fully elapses (now - start >= 60), the budget resets.
    CHECK(limiter.allow(alice, 1060));
    CHECK(limiter.allow(alice, 1060));
    CHECK(limiter.allow(alice, 1060));
    CHECK(!limiter.allow(alice, 1060));

    // A zero budget rejects every named peer but still passes empty destinations.
    FederationRateLimiter closed(0, 60);
    CHECK(!closed.allow(alice, 0));
    CHECK(closed.allow("", 0));

    std::printf("TestFederationRateLimiter OK\n");
    return 0;
}
