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
    CHECK(config.admins.size() == 1);
    CHECK(config.admins.front() == "abcd1234");
    CHECK(config.listenHost == "0.0.0.0");
    CHECK(config.listenPort == 9000);
    CHECK(config.fleets.size() == 1);
    CHECK(config.fleets[0].services.size() == 2);
    CHECK(config.fleets[0].services[0].name == "core");
    CHECK(config.fleets[0].services[0].kind == "server-core");
    CHECK(config.fleets[0].services[0].url == "http://127.0.0.1:8420");
    CHECK(config.fleets[0].services[1].kind == "facade");

    const Config minimal = Config::fromJson(R"({"admin": "fp"})");
    CHECK(minimal.consumer.name == "Bazarish admin panel");
    CHECK(minimal.listenHost == "127.0.0.1");
    CHECK(minimal.listenPort == 8460);
    CHECK(minimal.consumer.place == "http://127.0.0.1:8460");
    CHECK(minimal.consumer.role == "Administrator");
    CHECK(minimal.fleets.empty());

    const Config shared = Config::fromJson(R"({"admin": ["one", "two"]})");
    CHECK(shared.admins.size() == 2);
    CHECK(shared.admins.at(1) == "two");
    CHECK(Config::fromJson(R"({"admin": []})").admins.empty());
    CHECK(Config::fromJson(R"({"services": []})").admins.empty());
    CHECK_THROWS(Config::fromJson(R"({"admin": ["one", ""]})"));
    CHECK_THROWS(Config::fromJson(R"({"admin": ""})"));

    const Config many = Config::fromJson(R"({"admin": "fp", "fleets": [
        {"name": "berlin", "services": [
            {"name": "core", "kind": "server-core", "url": "http://10.0.0.1:8420"},
            {"name": "node", "kind": "service-node", "url": "http://10.0.0.1:8421"}]},
        {"name": "riga", "services": [
            {"name": "core", "kind": "server-core", "url": "http://10.0.0.2:8420"}]}
    ]})");
    CHECK(many.fleets.size() == 2);
    CHECK(many.fleets[0].name == "berlin");
    CHECK(many.fleets[0].services.size() == 2);
    CHECK(many.fleets[1].name == "riga");

    CHECK_THROWS(Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "alias", "kind": "alias-resolver", "url": "http://127.0.0.1:8432"}]})"));

    CHECK_THROWS(Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "x", "kind": "nope", "url": "http://x"}]})"));

    CHECK_THROWS(Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "x", "kind": "server-core"}]})"));

    const Config pasted = Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "gate", "kind": "gateway",
         "url": "https://gate.example/f3a9c2e1#a-long-token"}]})");
    CHECK(pasted.fleets.at(0).services.at(0).url == "https://gate.example/f3a9c2e1");
    CHECK(pasted.fleets.at(0).services.at(0).token == "a-long-token");

    const Config named = Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "gate", "kind": "gateway",
         "url": "http://192.168.0.70:8440/f3a9c2e1", "token": "a-long-token"}]})");
    CHECK(named.fleets.at(0).services.at(0).url == "http://192.168.0.70:8440/f3a9c2e1");
    CHECK(named.fleets.at(0).services.at(0).token == "a-long-token");

    std::printf("TestConfig: all checks passed\n");
    return 0;
}
