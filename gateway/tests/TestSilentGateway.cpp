// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "Relay.hpp"
#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/5d0c2e81b7a3";
constexpr const char* kToken = "a-silent-gateway-token";
constexpr std::chrono::seconds kDialSeconds{1};

i2p::RouterConfig borrowedFrom(const int port)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayToken = kToken;
    config.gatewayTls = false;
    config.gatewayControlMinLife = std::chrono::seconds(600);
    config.gatewayControlMaxLife = std::chrono::seconds(600);
    config.gatewayDecoyMin = std::chrono::milliseconds(600000);
    config.gatewayDecoyMax = std::chrono::milliseconds(600000);
    return config;
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-silent-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.token = kToken;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));
    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    Relay relay(port);
    i2p::Router serving(borrowedFrom(port));
    i2p::Router dialling(borrowedFrom(relay.port()));
    serving.start();
    dialling.start();

    i2p::EndpointConfig published;
    published.privacy = i2p::Privacy::eMinimal;
    published.published = true;
    const std::shared_ptr<i2p::Endpoint> theirs = serving.createEndpoint(published);

    i2p::EndpointConfig hidden;
    hidden.privacy = i2p::Privacy::eMinimal;
    hidden.published = false;
    const std::shared_ptr<i2p::Endpoint> mine = dialling.createEndpoint(hidden);

    relay.stall(true);
    const std::unique_ptr<i2p::Stream> unanswered = mine->connect(theirs->routingHost(), kDialSeconds);
    CHECK(unanswered == nullptr);
    relay.stall(false);

    std::filesystem::remove_all(root);
    return 0;
}
