// Bazarish project (c) 2026
#include "Config.hpp"
#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

using namespace bazarish::admin;

int main()
{
    const std::string text = R"({
        "admin": ["abcd1234"],
        "listen": {"host": "0.0.0.0", "port": 9000},
        "services": [
            {"name": "core", "kind": "server-core", "url": "https://127.0.0.1:8420", "pin": "a-pin"},
            {"name": "facade", "kind": "facade", "url": "https://127.0.0.1:8429", "pin": "a-pin"}
        ]
    })";
    const Config config = Config::fromJson(text);
    CHECK(config.admins.size() == 1);
    CHECK(config.admins.front() == "abcd1234");
    CHECK(config.listenHost == "0.0.0.0");
    CHECK(config.listenPort == 9000);
    CHECK(config.services.size() == 2);
    CHECK(config.services[0].name == "core");
    CHECK(config.services[0].kind == "server-core");
    CHECK(config.services[0].url == "https://127.0.0.1:8420");
    CHECK(config.services[0].pin == "a-pin");
    CHECK(config.services[1].kind == "facade");

    const Config minimal = Config::fromJson(R"({"admin": ["fp"]})");
    CHECK(minimal.consumer.name == "Bazarish admin panel");
    CHECK(minimal.listenHost == "127.0.0.1");
    CHECK(minimal.listenPort == 8460);
    CHECK(minimal.consumer.place.size() == 1);
    CHECK(minimal.consumer.place.front() == "http://127.0.0.1:8460");
    CHECK(minimal.consumer.role == "Administrator");
    CHECK(minimal.services.empty());

    const Config shared = Config::fromJson(R"({"admin": ["one", "two"]})");
    CHECK(shared.admins.size() == 2);
    CHECK(shared.admins.at(1) == "two");
    CHECK(Config::fromJson(R"({"admin": []})").admins.empty());
    CHECK(Config::fromJson(R"({"services": []})").admins.empty());
    CHECK_THROWS(Config::fromJson(R"({"admin": ["one", ""]})"));

    try {
        Config::fromJson(R"({"admin": ["fp"], "fleets": [{"name": "home", "services": [
            {"name": "core", "kind": "server-core", "url": "https://10.0.0.1:8428", "pin": "a-pin"}]}]})");
        CHECK(false);
    } catch (const std::runtime_error& error) {
        CHECK(std::string(error.what()).find("\"fleets\"") != std::string::npos);
    }
    CHECK_THROWS(Config::fromJson(R"({"admin": ["fp"], "title": "home"})"));
    CHECK_THROWS(Config::fromJson(R"(["fp"])"));

    CHECK_THROWS(Config::fromJson(R"({"admin": ["fp"], "services": [
        {"name": "alias", "kind": "alias-resolver", "url": "https://127.0.0.1:8432", "pin": "a-pin"}]})"));

    CHECK_THROWS(Config::fromJson(R"({"admin": ["fp"], "services": [
        {"name": "x", "kind": "nope", "url": "https://x", "pin": "a-pin"}]})"));

    CHECK_THROWS(Config::fromJson(R"({"admin": ["fp"], "services": [
        {"name": "x", "kind": "server-core"}]})"));

    const Config spread = Config::fromJson(R"({"admin": ["fp"], "services": [
            {"name": "core", "kind": "server-core", "url": "https://10.0.0.1:8428", "pin": "a-pin"},
            {"name": "node", "kind": "service-node", "url": "https://10.0.0.1:8427", "pin": "a-pin"},
            {"name": "facade-a", "kind": "facade", "url": "https://10.0.0.1:8429", "pin": "a-pin"},
            {"name": "facade-b", "kind": "facade", "url": "https://10.0.0.3:8429", "pin": "a-pin"},
            {"name": "gw-a", "kind": "gateway", "url": "https://10.0.0.4:8439", "pin": "a-pin"},
            {"name": "gw-b", "kind": "gateway", "url": "https://10.0.0.5:8439", "pin": "a-pin"}]})");
    CHECK(spread.services.size() == 6);

    CHECK_THROWS(Config::fromJson(R"({"admin": ["fp"], "services": [
        {"name": "edge", "kind": "facade", "url": "https://10.0.0.1:8429", "pin": "a-pin"},
        {"name": "edge", "kind": "gateway", "url": "https://10.0.0.4:8439", "pin": "a-pin"}]})"));
    CHECK_THROWS(Config::fromJson(R"({"admin": ["fp"], "services": [
        {"name": "core", "kind": "server-core", "url": "https://10.0.0.1:8428", "pin": "a-pin"},
        {"name": "core-2", "kind": "server-core", "url": "https://10.0.0.2:8428", "pin": "a-pin"}]})"));
    CHECK_THROWS(Config::fromJson(R"({"admin": ["fp"], "services": [
        {"name": "node", "kind": "service-node", "url": "https://10.0.0.1:8427", "pin": "a-pin"},
        {"name": "node-2", "kind": "service-node", "url": "https://10.0.0.2:8427", "pin": "a-pin"}]})"));

    std::printf("TestConfig: all checks passed\n");
    return 0;
}
