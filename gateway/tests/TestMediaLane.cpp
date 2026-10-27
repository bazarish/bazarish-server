// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "Relay.hpp"
#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/5c3f9a12e8d7";
constexpr const char* kToken = "a-fifth-static-token";
constexpr int kWaitSeconds = 30;
constexpr std::size_t kOversizeBytes = 20000;
constexpr std::chrono::milliseconds kNothingArrives{1500};

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

bool waitFor(const std::function<bool()>& done)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kWaitSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return done();
}

bool routedLocally(const i2p::Router& router, const std::string& host)
{
    for (const i2p::LocalDestination& destination : router.localDestinations()) {
        if (destination.host == host) {
            return destination.localRoute;
        }
    }
    return false;
}

std::shared_ptr<i2p::Endpoint> mediaOn(i2p::Router& router)
{
    i2p::EndpointConfig config;
    config.privacy = i2p::Privacy::eMinimal;
    config.published = true;
    config.traffic = i2p::Traffic::eRaw;
    config.realtime = true;
    config.label = "Call media";
    return router.createEndpoint(config);
}

bool mediaFlows(i2p::Endpoint& from, i2p::Endpoint& to)
{
    const std::string payload = "audio";
    from.sendRawDatagram(to.routingHost(), payload.data(), payload.size());
    const std::vector<std::uint8_t> got
        = to.receiveRawDatagram(std::chrono::milliseconds(3000));
    return got.size() == payload.size();
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-media-lane-test";
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
    i2p::Router alice(borrowedFrom(relay.port()));
    i2p::Router bob(borrowedFrom(port));
    alice.start();
    bob.start();

    const std::shared_ptr<i2p::Endpoint> hers = mediaOn(alice);
    const std::shared_ptr<i2p::Endpoint> his = mediaOn(bob);
    CHECK(waitFor([&]() { return gateway.sockets() == 4; }));
    CHECK(waitFor([&]() { return relay.connections() == 2; }));

    CHECK(!routedLocally(bob, his->routingHost()));
    CHECK(mediaFlows(*his, *hers));
    CHECK(mediaFlows(*hers, *his));
    CHECK(waitFor([&]() {
        return routedLocally(bob, his->routingHost()) && routedLocally(alice, hers->routingHost());
    }));

    CHECK_THROWS(his->connect(hers->routingHost(), std::chrono::seconds(1)));
    std::string nobody;
    CHECK_THROWS(his->accept(nobody, std::chrono::seconds(1)));

    const std::vector<std::uint8_t> oversize(kOversizeBytes, 'x');
    his->sendRawDatagram(hers->routingHost(), oversize.data(), oversize.size());
    CHECK(hers->receiveRawDatagram(std::chrono::milliseconds(500)).empty());
    CHECK(gateway.sockets() == 4);
    CHECK(mediaFlows(*his, *hers));

    relay.cut(1);

    CHECK(waitFor([&]() { return relay.connections() >= 3; }));
    CHECK(waitFor([&]() { return gateway.sockets() == 4; }));
    CHECK(alice.running());
    CHECK(!hers->lost());
    CHECK(mediaFlows(*his, *hers));
    CHECK(mediaFlows(*hers, *his));

    i2p::EndpointConfig quiet;
    quiet.privacy = i2p::Privacy::eMinimal;
    quiet.published = true;
    quiet.traffic = i2p::Traffic::eRaw;
    quiet.realtime = false;
    const std::shared_ptr<i2p::Endpoint> aside = bob.createEndpoint(quiet);
    CHECK(mediaFlows(*aside, *hers));
    aside->stop();

    const i2p::Keys own = i2p::Keys::generate();
    i2p::EndpointConfig guarded;
    guarded.published = true;
    guarded.traffic = i2p::Traffic::eRaw;
    guarded.keys = own;
    guarded.leaseSetReaders = {Key::generateX25519().rawPublic()};
    const std::shared_ptr<i2p::Endpoint> presence = alice.createEndpoint(guarded);
    CHECK(presence->routingHost() == i2p::routingHost(own.publicBase64()));
    const std::string knock = "here";
    his->sendRawDatagram(presence->routingHost(), knock.data(), knock.size());
    CHECK(presence->receiveRawDatagram(kNothingArrives).empty());
    CHECK(!routedLocally(alice, presence->routingHost()));
    presence->stop();

    i2p::EndpointConfig watching;
    watching.published = true;
    watching.traffic = i2p::Traffic::eRaw;
    watching.leaseSetReaderKey = Key::generateX25519().rawPrivate();
    const std::shared_ptr<i2p::Endpoint> watcher = bob.createEndpoint(watching);
    CHECK(mediaFlows(*watcher, *hers));
    watcher->stop();

    CHECK(gateway.refusals() == 0);

    bob.stop();
    CHECK(waitFor([&]() { return engine.localDestinations().size() == 1 + gateway.pooled(); }));

    gateway.stop();
    CHECK(waitFor([&]() { return engine.localDestinations().empty(); }));

    alice.stop();
    std::filesystem::remove_all(root);
    std::printf("TestMediaLane ok\n");
    return 0;
}
