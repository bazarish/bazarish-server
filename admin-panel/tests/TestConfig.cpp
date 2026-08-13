// Bazarish project (c) 2026
#include "Config.hpp"

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#define CHECK_THROWS(expression)                                                      \
    do {                                                                             \
        bool thrown = false;                                                         \
        try {                                                                        \
            (void)(expression);                                                      \
        } catch (const std::exception&) {                                            \
            thrown = true;                                                           \
        }                                                                            \
        if (!thrown) {                                                               \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d: %s did not throw\n", \
                __FILE__, __LINE__, #expression);                                    \
            std::exit(1);                                                            \
        }                                                                            \
    } while (false)

using namespace bazarish::admin;

int main()
{
    const std::string text = R"({
        "admin": "abcd1234",
        "listen": {"host": "0.0.0.0", "port": 9000},
        "services": [
            {"name": "core", "kind": "server-core", "url": "http://127.0.0.1:8420"},
            {"name": "facade", "kind": "facade", "url": "http://127.0.0.1:8429"}
        ]
    })";
    const Config config = Config::fromJson(text);
    CHECK(config.admin == "abcd1234");
    CHECK(config.listenHost == "0.0.0.0");
    CHECK(config.listenPort == 9000);
    CHECK(config.services.size() == 2);
    CHECK(config.services[0].name == "core");
    CHECK(config.services[0].kind == "server-core");
    CHECK(config.services[0].url == "http://127.0.0.1:8420");
    CHECK(config.services[1].kind == "facade");

    // Defaults applied when optional fields are omitted.
    const Config minimal = Config::fromJson(R"({"admin": "fp"})");
    CHECK(minimal.audience == "bazarish-admin-panel");
    CHECK(minimal.listenHost == "127.0.0.1");
    CHECK(minimal.listenPort == 8460);
    CHECK(minimal.services.empty());

    // A missing or empty admin fingerprint is rejected.
    CHECK_THROWS(Config::fromJson(R"({"services": []})"));
    CHECK_THROWS(Config::fromJson(R"({"admin": ""})"));

    // An unknown service kind is rejected (catches config typos).
    CHECK_THROWS(Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "x", "kind": "nope", "url": "http://x"}]})"));

    // A service entry missing a required field (url) is rejected.
    CHECK_THROWS(Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "x", "kind": "server-core"}]})"));

    std::printf("TestConfig: all checks passed\n");
    return 0;
}
