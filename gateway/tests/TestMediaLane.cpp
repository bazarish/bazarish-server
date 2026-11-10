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
constexpr std::size_t kOversizeBytes = 20000;
constexpr std::chrono::milliseconds kNothingArrives{1500};
constexpr std::int64_t kAskedBeforeEnd = 300;
constexpr std::int64_t kPastLapse = 30;
constexpr std::chrono::milliseconds kRenewalRoundTrip{1000};
constexpr std::chrono::milliseconds kMediaWithin{3000};
constexpr std::chrono::milliseconds kMediaProbeEvery{200};
constexpr std::chrono::milliseconds kOversizeDropped{500};

i2p::RouterConfig borrowedFrom(const int port, const std::string& fingerprint)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayFingerprint = fingerprint;
    config.gatewayTls = false;
    config.gatewayControlMinLife = std::chrono::seconds(600);
    config.gatewayControlMaxLife = std::chrono::seconds(600);
    config.gatewayDecoyMin = std::chrono::milliseconds(600000);
    config.gatewayDecoyMax = std::chrono::milliseconds(600000);
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

// Datagrams may be lost, the first ones after a socket comes back above all: the lane flows when one gets through.
bool mediaFlows(i2p::Endpoint& from, i2p::Endpoint& to)
{
    const std::string payload = "audio";
    const auto until = std::chrono::steady_clock::now() + kMediaWithin;
    while (std::chrono::steady_clock::now() < until) {
        from.sendRawDatagram(to.routingHost(), bazarish::viewOf(payload));
        if (to.receiveRawDatagram(kMediaProbeEvery).size() == payload.size()) {
            return true;
        }
    }
    return false;
}

// A probe left over from an earlier check may still arrive: only the size that must not come counts.
bool noneOfSizeWithin(i2p::Endpoint& to, const std::size_t size, const std::chrono::milliseconds window)
{
    const auto until = std::chrono::steady_clock::now() + window;
    while (std::chrono::steady_clock::now() < until) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            until - std::chrono::steady_clock::now());
        const std::vector<std::uint8_t> got = to.receiveRawDatagram(left);
        if (got.size() == size) {
            return false;
        }
    }
    return true;
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = testutil::freshDir("gateway-media-lane-test");
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
    i2p::Router alice(borrowedFrom(relay.port(), gateway.fingerprint()));
    i2p::Router bob(borrowedFrom(port, gateway.fingerprint()));
    alice.start();
    bob.start();

    const std::shared_ptr<i2p::Endpoint> hers = mediaOn(alice);
    const std::shared_ptr<i2p::Endpoint> his = mediaOn(bob);
    CHECK(testutil::waitFor([&]() { return gateway.sockets() == 4; }));
    CHECK(testutil::waitFor([&]() { return relay.connections() == 2; }));

    CHECK(!routedLocally(bob, his->routingHost()));
    CHECK(mediaFlows(*his, *hers));
    CHECK(mediaFlows(*hers, *his));
    CHECK(testutil::waitFor([&]() {
        return routedLocally(bob, his->routingHost()) && routedLocally(alice, hers->routingHost());
    }));

    CHECK_THROWS(his->connect(hers->routingHost(), std::chrono::seconds(1)));
    std::string nobody;
    CHECK_THROWS(his->accept(nobody, std::chrono::seconds(1)));

    const std::vector<std::uint8_t> oversize(kOversizeBytes, 'x');
    his->sendRawDatagram(hers->routingHost(), oversize);
    CHECK(noneOfSizeWithin(*hers, kOversizeBytes, kOversizeDropped));
    CHECK(gateway.sockets() == 4);
    CHECK(mediaFlows(*his, *hers));

    relay.cut(1);

    CHECK(testutil::waitFor([&]() { return relay.connections() >= 3; }));
    CHECK(testutil::waitFor([&]() { return gateway.sockets() == 4; }));
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
    const Key reader = Key::generateX25519();
    i2p::EndpointConfig guarded;
    guarded.published = true;
    guarded.traffic = i2p::Traffic::eRaw;
    guarded.keys = own;
    guarded.leaseSetReaders = {reader.rawPublic()};
    const std::shared_ptr<i2p::Endpoint> presence = alice.createEndpoint(guarded);
    CHECK(presence->routingHost() == i2p::routingHost(own.publicBase64()));
    const std::string knock = "here";
    his->sendRawDatagram(presence->routingHost(), bazarish::viewOf(knock));
    CHECK(presence->receiveRawDatagram(kNothingArrives).empty());
    CHECK(!routedLocally(alice, presence->routingHost()));
    const auto watcherWith = [&bob](const Bytes& secret) {
        i2p::EndpointConfig config;
        config.published = true;
        config.traffic = i2p::Traffic::eRaw;
        config.leaseSetReaderKey = secret;
        return bob.createEndpoint(config);
    };
    const std::shared_ptr<i2p::Endpoint> reading = watcherWith(reader.rawPrivate());
    CHECK(mediaFlows(*reading, *presence));
    CHECK(testutil::waitFor([&]() { return routedLocally(alice, presence->routingHost()); }));
    CHECK(mediaFlows(*presence, *reading));
    const std::shared_ptr<i2p::Endpoint> stranger = watcherWith(Key::generateX25519().rawPrivate());
    stranger->sendRawDatagram(presence->routingHost(), bazarish::viewOf(knock));
    CHECK(noneOfSizeWithin(*presence, knock.size(), kNothingArrives));
    reading->stop();
    stranger->stop();
    const std::int64_t endOfToday = own.issueTransient(1).transientExpires();
    gateway.lapseDelegations(endOfToday - kAskedBeforeEnd);
    std::this_thread::sleep_for(kRenewalRoundTrip);
    gateway.lapseDelegations(endOfToday - kPastLapse);
    std::this_thread::sleep_for(kRenewalRoundTrip);
    CHECK(!presence->lost());
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
    CHECK(testutil::waitFor([&]() { return engine.localDestinations().size() == 1 + gateway.pooled(); }));

    gateway.stop();
    CHECK(testutil::waitFor([&]() { return engine.localDestinations().empty(); }));

    alice.stop();
    std::filesystem::remove_all(root);
    std::printf("TestMediaLane ok\n");
    return 0;
}
