// Bazarish project (c) 2026
#include "RateLimiter.hpp"

#include <cstdio>
#include <cstdlib>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace bazarish;

int main()
{
    RateLimiter limiter(3, 60);

    const std::string alice = "alice.b32.i2p";
    const std::string bob = "bob.b32.i2p";

    CHECK(limiter.allow(alice, 1000));
    CHECK(limiter.allow(alice, 1000));
    CHECK(limiter.allow(alice, 1000));
    CHECK(!limiter.allow(alice, 1000));
    CHECK(!limiter.allow(alice, 1059));

    CHECK(limiter.allow(bob, 1000));
    CHECK(limiter.allow(bob, 1030));
    CHECK(limiter.allow(bob, 1059));
    CHECK(!limiter.allow(bob, 1059));

    CHECK(limiter.allow(alice, 1060));
    CHECK(limiter.allow(alice, 1060));
    CHECK(limiter.allow(alice, 1060));
    CHECK(!limiter.allow(alice, 1060));

    RateLimiter closed(0, 60);
    CHECK(!closed.allow(alice, 0));

    std::printf("TestRateLimiter OK\n");
    return 0;
}
