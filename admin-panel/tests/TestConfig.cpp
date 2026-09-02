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
    // A plain list of services is one deployment, which is what a single server
    // looks like.
    CHECK(config.fleets.size() == 1);
    CHECK(config.fleets[0].services.size() == 2);
    CHECK(config.fleets[0].services[0].name == "core");
    CHECK(config.fleets[0].services[0].kind == "server-core");
    CHECK(config.fleets[0].services[0].url == "http://127.0.0.1:8420");
    CHECK(config.fleets[0].services[1].kind == "facade");

    // Defaults applied when optional fields are omitted.
    const Config minimal = Config::fromJson(R"({"admin": "fp"})");
    CHECK(minimal.consumer.name == "Bazarish admin panel");
    CHECK(minimal.listenHost == "127.0.0.1");
    CHECK(minimal.listenPort == 8460);
    // Where it listens is where the operator opens it, so that is what the panel
    // says it is until an operator fronts it and says otherwise.
    CHECK(minimal.consumer.place == "http://127.0.0.1:8460");
    CHECK(minimal.consumer.role == "Administrator");
    CHECK(minimal.fleets.empty());

    // Several operators, each with their own key.
    const Config shared = Config::fromJson(R"({"admin": ["one", "two"]})");
    CHECK(shared.admins.size() == 2);
    CHECK(shared.admins.at(1) == "two");
    // No administrator is not an error: it is a fresh install, and the setup
    // wizard is what that state exists for. An empty fingerprint still is one -
    // it names nobody while pretending to name somebody.
    CHECK(Config::fromJson(R"({"admin": []})").admins.empty());
    CHECK(Config::fromJson(R"({"services": []})").admins.empty());
    CHECK_THROWS(Config::fromJson(R"({"admin": ["one", ""]})"));
    CHECK_THROWS(Config::fromJson(R"({"admin": ""})"));

    // Several deployments, each with its own services: that is the unit that
    // scales, because a subscription names one messaging server.
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

    // The alias service is central, not part of anyone's deployment.
    CHECK_THROWS(Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "alias", "kind": "alias-resolver", "url": "http://127.0.0.1:8432"}]})"));

    // An unknown service kind is rejected (catches config typos).
    CHECK_THROWS(Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "x", "kind": "nope", "url": "http://x"}]})"));

    // A service entry missing a required field (url) is rejected.
    CHECK_THROWS(Config::fromJson(R"({"admin": "fp", "services": [
        {"name": "x", "kind": "server-core"}]})"));

    std::printf("TestConfig: all checks passed\n");
    return 0;
}
