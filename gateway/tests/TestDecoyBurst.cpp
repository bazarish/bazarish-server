// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "Relay.hpp"
#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>
#include <bazarish/TrafficShape.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <thread>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/3e8a51c09d27";
constexpr std::chrono::seconds kIdleSpell{4};
constexpr std::chrono::seconds kActiveSpell{12};
constexpr std::chrono::seconds kBurstDrains{4};
constexpr std::chrono::milliseconds kWaitBursts{20000};
constexpr std::size_t kLeastDecoys = 8;
// Short read pauses so a test sees many bursts; the shape is the browsing one otherwise.
constexpr shape::Pareto kQuickReading{shape::kReadAlpha, 0.5, 1.0};

}  // namespace

int main()
{
    const std::filesystem::path root = testutil::freshDir("gateway-decoy-burst-test");
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
    Relay relay(port);

    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = relay.port();
    config.gatewayPath = kPath;
    config.gatewayFingerprint = gateway.fingerprint();
    config.gatewayTls = false;
    config.gatewayReadPause = kQuickReading;
    i2p::Router client(config);
    client.start();

    std::this_thread::sleep_for(kIdleSpell);
    CHECK(gateway.decoys() == 0);
    CHECK(gateway.rejoins() == 0);
    CHECK(relay.connections() == 1);

    i2p::windowActive(true);
    i2p::userActed();
    CHECK(testutil::waitFor([&gateway]() { return gateway.decoys() >= kLeastDecoys; }, kWaitBursts));
    std::this_thread::sleep_for(kActiveSpell);
    i2p::windowActive(false);
    std::this_thread::sleep_for(kBurstDrains);

    const std::size_t decoys = gateway.decoys();
    const std::size_t rejoins = gateway.rejoins();
    const std::size_t sockets = 1 + rejoins;
    const std::size_t connections = relay.connections();
    CHECK(connections > sockets);
    const std::size_t decoyConnections = connections - sockets;
    std::printf("%zu decoys over %zu connections; %zu control sockets replaced at a burst\n",
        decoys, decoyConnections, rejoins);
    CHECK(rejoins >= 1);
    CHECK(decoys > decoyConnections);
    CHECK(decoyConnections <= decoys);

    std::this_thread::sleep_for(kIdleSpell);
    CHECK(gateway.decoys() == decoys);
    CHECK(gateway.rejoins() == rejoins);
    CHECK(relay.connections() == connections);

    client.stop();
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestDecoyBurst ok\n");
    return 0;
}
