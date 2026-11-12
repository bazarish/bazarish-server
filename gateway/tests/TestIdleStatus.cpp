// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/5d0e7b3a91c8";
constexpr std::chrono::seconds kDialFor{20};
// Many status periods: a status the gateway meant to send has long arrived by then.
constexpr std::chrono::seconds kSettle{3};

std::optional<i2p::LocalDestination> find(const i2p::Router& router, const std::string& host)
{
    for (const i2p::LocalDestination& destination : router.localDestinations()) {
        if (destination.host == host) {
            return destination;
        }
    }
    return std::nullopt;
}

bool routedLocally(const i2p::Router& router, const std::string& host)
{
    const std::optional<i2p::LocalDestination> found = find(router, host);
    return found.has_value() && found->localRoute;
}

}  // namespace

int main()
{
    const std::filesystem::path root = testutil::freshDir("gateway-idle-status-test");
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));
    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayFingerprint = gateway.fingerprint();
    config.gatewayTls = false;
    i2p::Router client(config);
    client.start();

    i2p::EndpointConfig serving;
    serving.privacy = i2p::Privacy::eMinimal;
    serving.published = true;
    const std::shared_ptr<i2p::Endpoint> hers = client.createEndpoint(serving);
    i2p::EndpointConfig dialling;
    dialling.privacy = i2p::Privacy::eMinimal;
    dialling.published = false;
    const std::shared_ptr<i2p::Endpoint> his = client.createEndpoint(dialling);

    const std::unique_ptr<i2p::Stream> out = his->connect(hers->routingHost(), kDialFor);
    CHECK(out != nullptr);
    std::this_thread::sleep_for(kSettle);
    CHECK(!routedLocally(client, his->routingHost()));

    i2p::windowActive(true);
    i2p::userActed();
    CHECK(testutil::waitFor([&]() { return routedLocally(client, his->routingHost()); }));

    out->close();
    his->stop();
    hers->stop();
    client.stop();
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestIdleStatus ok\n");
    return 0;
}
