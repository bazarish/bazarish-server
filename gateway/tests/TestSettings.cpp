// Bazarish project (c) 2026
#include "Settings.hpp"

#include "TestUtil.hpp"

#include <bazarish/ConfigFile.hpp>

#include <cstdio>
#include <optional>
#include <string>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

ConfigView document(const std::string& text)
{
    return ConfigView(nlohmann::json::parse(text));
}

bool refusedNaming(const std::string& text, const std::string& key)
{
    try {
        static_cast<void>(Settings::from(document(text)));
    } catch (const std::exception& error) {
        std::printf("refused: %s\n", error.what());
        return std::string(error.what()).find("\"" + key + "\"") != std::string::npos;
    }
    return false;
}

std::string withBase(const std::string& rest)
{
    return R"({"basePath": "/s", "state": "/t", )" + rest + "}";
}

const char* kWhole = R"({
    "listen": { "host": "0.0.0.0", "port": 8431 },
    "basePath": "/f3a9c2e1b7d4",
    "state": "/var/lib/bazarish-gateway",
    "reseed": ["https://reseed.example/i2pseeds.su3"],
    "decoy": {
        "page": { "maxBytes": 65536, "parts": [
            { "weight": 3, "medianBytes": 20000, "sigma": 0.8 },
            { "weight": 1, "medianBytes": 50000, "sigma": 0.4 } ] },
        "resource": { "maxBytes": 8192, "parts": [ { "weight": 1, "medianBytes": 2000, "sigma": 1.2 } ] }
    },
    "serverName": "caddy",
    "notFound": "",
    "publicAddress": "https://gate.example",
    "sessionTtlSeconds": 120,
    "i2p": { "privacy": "max", "logLevel": "warn" },
    "logLevel": "debug",
    "pools": { "stream": 0, "call": 7, "watch": 3 },
    "operators": ["sr4mtrnzkspfagb6"],
    "opsListen": { "host": "127.0.0.1", "port": 8439 },
    "opsClients": ["4e7d4e99"],
    "direct": [{"dest": "alpha.b32.i2p", "host": "10.0.0.2", "port": 8418, "pin": "ab12"}],
    "server": {"host": "127.0.0.1", "port": 8424, "pin": "cd34"}
})";

}  // namespace

int main()
{
    const Settings whole = Settings::from(document(kWhole));
    CHECK(whole.listenHost == "0.0.0.0");
    CHECK(whole.listenPort == 8431);
    CHECK(whole.basePath == "/f3a9c2e1b7d4");
    CHECK(whole.reseedUrls.size() == 1);
    CHECK(whole.decoyPage.max == 65536);
    CHECK(whole.decoyPage.parts.size() == 2);
    CHECK(whole.decoyPage.parts.front().weight == 3);
    CHECK(whole.decoyPage.parts.back().median == 50000);
    CHECK(whole.decoyResource.max == 8192);
    CHECK(whole.decoyResource.parts.front().sigma == 1.2);
    CHECK(whole.serverName == "caddy");
    CHECK(whole.sessionTtlSeconds == 120);
    CHECK(whole.tunnelPrivacy == i2p::Privacy::eMax);
    CHECK(whole.streamPool == 0);
    CHECK(whole.callPool == 7);
    CHECK(whole.watchPool == 3);
    CHECK(whole.logLevel == log::Level::eDebug);
    CHECK(whole.i2pLogLevel == i2p::I2pLogLevel::eWarn);
    CHECK(whole.operators.size() == 1);
    CHECK(whole.opsPort == 8439);
    CHECK(whole.opsClients.size() == 1);
    CHECK(whole.direct.size() == 1);
    CHECK(whole.server.has_value());

    const Settings example = Settings::from(ConfigView(ConfigFile(BAZARISH_GATEWAY_EXAMPLE).read()));
    CHECK(example.basePath.front() == '/');

    CHECK(refusedNaming(R"({"basePath": "/s", "state": "/t", "token": "x"})", "token"));
    CHECK(refusedNaming(withBase(R"("decoy": {"minBytes": 1024})"),
        "decoy.minBytes"));
    CHECK(refusedNaming(withBase(R"("i2p": {"privacy": "minimal", "tunnelQuantity": 3})"),
        "i2p.tunnelQuantity"));
    CHECK(refusedNaming(withBase(R"("listen": {"host": "h", "port": 1, "tls": true})"),
        "listen.tls"));
    CHECK(refusedNaming(withBase(R"("opsListen": {"host": "h", "port": 1, "pin": "p"})"),
        "opsListen.pin"));
    CHECK(refusedNaming(withBase(R"("pools": {"stream": 1, "dial": 2})"), "pools.dial"));
    CHECK(refusedNaming(withBase(R"("decoy": {"page": {"maxBytes": 4096, "minBytes": 1,)"
        R"( "parts": [{"weight": 1, "medianBytes": 9, "sigma": 1}]}})"), "decoy.page.minBytes"));
    CHECK(refusedNaming(withBase(R"("decoy": {"resource": {"maxBytes": 4096,)"
        R"( "parts": [{"weight": 1, "medianBytes": 9, "sigma": 1, "min": 2}]}})"),
        "decoy.resource.parts.min"));
    CHECK(refusedNaming(withBase(R"("direct": [{"dest": "a.b32.i2p", "host": "h", "port": 1,)"
        R"( "pin": "p", "tls": false}])"), "direct.tls"));
    CHECK(refusedNaming(withBase(R"("server": {"host": "h", "port": 1, "pin": "p", "token": "t"})"),
        "server.token"));
    CHECK(refusedNaming(withBase(R"("i2p": "max")"), "i2p"));
    CHECK(refusedNaming(withBase(R"("direct": {"dest": "a.b32.i2p"})"), "direct"));
    CHECK(Settings::from(document(withBase(R"("server": null)"))).server == std::nullopt);

    const Settings bare = Settings::from(document(R"({
        "basePath": "/secret", "state": "/tmp/s"
    })"));
    CHECK(bare.listenHost == "127.0.0.1");
    CHECK(bare.decoyPage.parts.size() == 1);
    CHECK(bare.decoyPage.parts.front().median == kDecoyPageMedianBytes);
    CHECK(bare.decoyPage.parts.front().sigma == kDecoyPageSigma);
    CHECK(bare.decoyPage.max == kDecoyMaxBytes);
    CHECK(bare.decoyResource.parts.front().median == kDecoyResourceMedianBytes);
    CHECK(bare.decoyResource.parts.front().sigma == kDecoyResourceSigma);
    CHECK(bare.sessionTtlSeconds == kSessionTtl.count());
    CHECK(bare.serverName == "nginx");
    CHECK(bare.tunnelPrivacy == i2p::Privacy::eMinimal);
    CHECK(bare.streamPool == kDefaultStreamPool);
    CHECK(bare.callPool == kDefaultCallPool);
    CHECK(bare.watchPool == kDefaultWatchPool);
    CHECK(bare.notFoundBody.find("404 Not Found") != std::string::npos);

    CHECK_THROWS(Settings::from(document(R"({"state": "/tmp/s"})")));
    CHECK(Settings::from(document(R"({"basePath": "/p", "state": "/tmp/s",
        "publicAddress": "https://gate.example:8443"})")).publicAddress
        == "https://gate.example:8443");
    CHECK(Settings::from(document(R"({"basePath": "/p", "state": "/tmp/s",
        "publicAddress": "http://[2001:db8::5]:8080"})")).publicAddress
        == "http://[2001:db8::5]:8080");
    for (const char* const wrong : {"gate.example", "https://", "https://gate.example/",
             "https://gate.example/p", "https://gate.example?x", "ftp://gate.example"}) {
        CHECK_THROWS(Settings::from(document(
            std::string(R"({"basePath": "/p", "state": "/tmp/s", "publicAddress": ")")
            + wrong + "\"}")));
    }
    CHECK_THROWS(
        Settings::from(document(R"({"basePath": "", "state": "/tmp/s"})")));
    CHECK_THROWS(
        Settings::from(document(R"({"basePath": "secret", "state": "/tmp/s"})")));
    CHECK_THROWS(Settings::from(document(
        R"({"basePath": "/s", "state": "/t", "reseed": ["http://seed.example/"]})")));
    CHECK_THROWS(Settings::from(document(R"({"basePath": "/s"})")));

    for (const char* const wrong : {
             R"({"page": {"maxBytes": 1024, "parts": [{"weight": 1, "medianBytes": 4096, "sigma": 1}]}})",
             R"({"page": {"maxBytes": 1024, "parts": []}})",
             R"({"resource": {"maxBytes": 0, "parts": [{"weight": 1, "medianBytes": 1, "sigma": 1}]}})",
             R"({"resource": {"maxBytes": 4096, "parts": [{"weight": 0, "medianBytes": 9, "sigma": 1}]}})",
             R"({"resource": {"maxBytes": 4096, "parts": [{"weight": 1, "medianBytes": 9, "sigma": 0}]}})",
             R"({"resource": {"parts": [{"weight": 1, "medianBytes": 9, "sigma": 1}]}})"}) {
        CHECK_THROWS(Settings::from(document(
            std::string(R"({"basePath": "/s", "state": "/t", "decoy": )") + wrong + "}")));
    }
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "state": "/t", "sessionTtlSeconds": 0
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "state": "/t", "i2p": { "privacy": "short" }
    })")));

    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "state": "/t", "notFound": "/no/such/page.html"
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "state": "/t", "pools": { "stream": -1 }
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "state": "/t", "pools": { "call": 17 }
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "state": "/t", "pools": { "watch": 17 }
    })")));

    const Settings routed = Settings::from(document(R"({
        "basePath": "/s", "state": "/t",
        "direct": [{"dest": "alpha.b32.i2p", "host": "10.0.0.2", "port": 8418, "pin": "ab12"}]
    })"));
    CHECK(routed.direct.size() == 1);
    CHECK(routed.direct.front().dest == "alpha.b32.i2p");
    CHECK(routed.direct.front().host == "10.0.0.2");
    CHECK(routed.direct.front().port == 8418);
    CHECK(routed.direct.front().pin == "ab12");

    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "state": "/t",
        "direct": [{"dest": "alpha.b32.i2p", "host": "10.0.0.2", "port": 8418}]
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "state": "/t",
        "direct": [{"host": "10.0.0.2", "port": 8418, "pin": "ab12"}]
    })")));

    std::printf("TestSettings ok\n");
    return 0;
}
