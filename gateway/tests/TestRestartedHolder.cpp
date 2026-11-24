// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/5d0c9e2a71b3";
constexpr std::chrono::milliseconds kKnockAnswer{500};
constexpr std::int64_t kShortSessionSeconds = 1;

i2p::RouterConfig borrowedFrom(const int port, const std::string& fingerprint)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayFingerprint = fingerprint;
    config.gatewayTls = false;
    return config;
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

}  // namespace

int main()
try {
    i2p::windowActive(true);
    i2p::userActed();
    const testutil::ScratchDir scratch("gateway-restarted-holder-test");
    const std::filesystem::path& root = scratch.path();
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";
    settings.sessionTtlSeconds = kShortSessionSeconds;

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));
    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    const i2p::Keys own = i2p::Keys::generate();
    const Key reader = Key::generateX25519();
    i2p::EndpointConfig presence;
    presence.published = true;
    presence.traffic = i2p::Traffic::eRaw;
    presence.keys = own;
    presence.leaseSetReaders = {reader.rawPublic()};

    auto before = std::make_unique<i2p::Router>(borrowedFrom(port, gateway.fingerprint()));
    before->start();
    const std::shared_ptr<i2p::Endpoint> old = before->createEndpoint(presence);
    const std::string host = old->routingHost();

    i2p::Router after(borrowedFrom(port, gateway.fingerprint()));
    after.start();
    const std::shared_ptr<i2p::Endpoint> holder = after.createEndpoint(presence);
    CHECK(holder->routingHost() == host);

    old->stop();
    before->stop();
    before.reset();
    std::this_thread::sleep_for(std::chrono::seconds(2 * kShortSessionSeconds));

    i2p::Router bob(borrowedFrom(port, gateway.fingerprint()));
    bob.start();
    i2p::EndpointConfig watching;
    watching.published = true;
    watching.traffic = i2p::Traffic::eRaw;
    watching.leaseSetReaderKey = reader.rawPrivate();
    const std::shared_ptr<i2p::Endpoint> watcher = bob.createEndpoint(watching);
    const std::string knock = "still here?";
    CHECK(testutil::waitFor([&]() {
        watcher->sendRawDatagram(host, bazarish::viewOf(knock));
        return !holder->receiveRawDatagram(kKnockAnswer).empty();
    }));
    CHECK(testutil::waitFor([&]() { return routedLocally(after, host); }));

    watcher->stop();
    holder->stop();
    bob.stop();
    after.stop();
    gateway.stop();
    std::printf("TestRestartedHolder ok\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
