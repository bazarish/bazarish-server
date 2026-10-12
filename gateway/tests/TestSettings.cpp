// Bazarish project (c) 2026
#include "Settings.hpp"

#include "TestUtil.hpp"

#include <string>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

ConfigView document(const std::string& text)
{
    return ConfigView(nlohmann::json::parse(text));
}

const char* kWhole = R"({
    "listen": { "host": "0.0.0.0", "port": 8431 },
    "basePath": "/f3a9c2e1b7d4",
    "token": "a-long-random-string",
    "state": "/var/lib/bazarish-gateway",
    "reseed": ["https://reseed.example/i2pseeds.su3"],
    "decoy": { "minBytes": 2048, "maxBytes": 4096 },
    "serverName": "caddy",
    "sessionTtlSeconds": 120,
    "i2p": { "privacy": "max", "tunnelQuantity": 5 },
    "pools": { "stream": 0, "call": 7 }
})";

}  // namespace

int main()
{
    const Settings whole = Settings::from(document(kWhole));
    CHECK(whole.listenHost == "0.0.0.0");
    CHECK(whole.listenPort == 8431);
    CHECK(whole.basePath == "/f3a9c2e1b7d4");
    CHECK(whole.token == "a-long-random-string");
    CHECK(whole.reseedUrls.size() == 1);
    CHECK(whole.decoyMinBytes == 2048);
    CHECK(whole.decoyMaxBytes == 4096);
    CHECK(whole.serverName == "caddy");
    CHECK(whole.sessionTtlSeconds == 120);
    CHECK(whole.tunnelPrivacy == i2p::Privacy::eMax);
    CHECK(whole.tunnelQuantity == 5);
    CHECK(whole.streamPool == 0);
    CHECK(whole.callPool == 7);

    const Settings bare = Settings::from(document(R"({
        "basePath": "/secret", "token": "t", "state": "/tmp/s"
    })"));
    CHECK(bare.listenHost == "127.0.0.1");
    CHECK(bare.decoyMinBytes == kDecoyMinBytes);
    CHECK(bare.decoyMaxBytes == kDecoyMaxBytes);
    CHECK(bare.sessionTtlSeconds == kSessionTtl.count());
    CHECK(bare.serverName == "nginx");
    CHECK(bare.tunnelPrivacy == i2p::Privacy::eMinimal);
    CHECK(bare.tunnelQuantity == i2p::kDefaultTunnelQuantity);
    CHECK(bare.streamPool == kDefaultStreamPool);
    CHECK(bare.callPool == kDefaultCallPool);
    CHECK(bare.notFoundBody.find("404 Not Found") != std::string::npos);

    CHECK_THROWS(Settings::from(document(R"({"token": "t", "state": "/tmp/s"})")));
    CHECK_THROWS(
        Settings::from(document(R"({"basePath": "", "token": "t", "state": "/tmp/s"})")));
    CHECK_THROWS(
        Settings::from(document(R"({"basePath": "secret", "token": "t", "state": "/tmp/s"})")));
    CHECK_THROWS(Settings::from(document(R"({"basePath": "/s", "state": "/tmp/s"})")));
    CHECK_THROWS(Settings::from(document(R"({"basePath": "/s", "token": "", "state": "/t"})")));
    CHECK_THROWS(Settings::from(document(
        R"({"basePath": "/s", "token": "t", "state": "/t", "reseed": ["http://seed.example/"]})")));
    CHECK_THROWS(Settings::from(document(R"({"basePath": "/s", "token": "t"})")));

    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t",
        "decoy": { "minBytes": 4096, "maxBytes": 1024 }
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t", "decoy": { "minBytes": 0 }
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t", "sessionTtlSeconds": 0
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t", "i2p": { "privacy": "short" }
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t", "i2p": { "tunnelQuantity": 0 }
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t", "i2p": { "tunnelQuantity": 17 }
    })")));

    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t", "notFound": "/no/such/page.html"
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t", "pools": { "stream": -1 }
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t", "pools": { "call": 17 }
    })")));

    const Settings routed = Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t",
        "direct": [{"dest": "alpha.b32.i2p", "host": "10.0.0.2", "port": 8418, "pin": "ab12"}]
    })"));
    CHECK(routed.direct.size() == 1);
    CHECK(routed.direct.front().dest == "alpha.b32.i2p");
    CHECK(routed.direct.front().host == "10.0.0.2");
    CHECK(routed.direct.front().port == 8418);
    CHECK(routed.direct.front().pin == "ab12");

    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t",
        "direct": [{"dest": "alpha.b32.i2p", "host": "10.0.0.2", "port": 8418}]
    })")));
    CHECK_THROWS(Settings::from(document(R"({
        "basePath": "/s", "token": "t", "state": "/t",
        "direct": [{"host": "10.0.0.2", "port": 8418, "pin": "ab12"}]
    })")));

    std::printf("TestSettings ok\n");
    return 0;
}
