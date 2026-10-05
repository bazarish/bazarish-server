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
    "sessionTtlSeconds": 120
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

    const Settings bare = Settings::from(document(R"({
        "basePath": "/secret", "token": "t", "state": "/tmp/s"
    })"));
    CHECK(bare.listenHost == "127.0.0.1");
    CHECK(bare.decoyMinBytes == kDecoyMinBytes);
    CHECK(bare.decoyMaxBytes == kDecoyMaxBytes);
    CHECK(bare.sessionTtlSeconds == kSessionTtl.count());
    CHECK(bare.serverName == "nginx");
    CHECK(bare.notFoundBody.find("404 Not Found") != std::string::npos);

    CHECK_THROWS(Settings::from(document(R"({"token": "t", "state": "/tmp/s"})")));
    CHECK_THROWS(
        Settings::from(document(R"({"basePath": "", "token": "t", "state": "/tmp/s"})")));
    CHECK_THROWS(
        Settings::from(document(R"({"basePath": "secret", "token": "t", "state": "/tmp/s"})")));
    CHECK_THROWS(Settings::from(document(R"({"basePath": "/s", "state": "/tmp/s"})")));
    CHECK_THROWS(Settings::from(document(R"({"basePath": "/s", "token": "", "state": "/t"})")));
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
        "basePath": "/s", "token": "t", "state": "/t", "notFound": "/no/such/page.html"
    })")));

    std::printf("TestSettings ok\n");
    return 0;
}
