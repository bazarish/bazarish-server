// Bazarish project (c) 2026
#include "Gateway.hpp"

#include <GatewayLink.hpp>
#include <TlsPipe.hpp>

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Tls.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;
namespace fs = std::filesystem;

namespace {

constexpr const char* kPath = "/5d1c0e93b2a7";
constexpr const char* kToken = "a-server-link-token";
constexpr int kWaitSeconds = 20;
constexpr std::chrono::seconds kShortWait{1};
constexpr std::chrono::milliseconds kPoll{20};
constexpr int kRandomNameBytes = 8;
constexpr std::size_t kEchoBytes = 256;
constexpr const char* kUserDest = "ykmtx5g3h4var6o4n4tw6k2fqsmszqwzkj2abdmax7avtiqyeskwb2zi.b32.i2p";
constexpr const char* kOtherDest = "r4obpwh2bvnmfiaks7oramvjbpv4ldf6ezxmbl3xiqhrmjcjqj6tapv2.b32.i2p";

i2p::RouterConfig borrowedFrom(const int port)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayToken = kToken;
    config.gatewayTls = false;
    return config;
}

bool waitFor(const std::function<bool()>& done)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kWaitSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(kPoll);
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

std::shared_ptr<i2p::Endpoint> leaseFor(i2p::Router& router, const std::string& target)
{
    i2p::EndpointConfig config;
    config.privacy = i2p::Privacy::eMinimal;
    config.published = false;
    config.target = target;
    return router.createEndpoint(config);
}

std::string echoed(i2p::Stream& stream, const std::string& said)
{
    stream.writeAll(said.data(), said.size());
    std::string heard;
    std::vector<char> buffer(kEchoBytes);
    while (heard.size() < said.size()) {
        const std::size_t got = stream.readSome(buffer.data(), buffer.size());
        if (got == 0) {
            break;
        }
        heard.append(buffer.data(), got);
    }
    return heard;
}

}  // namespace

int main()
{
    const fs::path root = fs::temp_directory_path()
        / ("bazarish-gateway-server-link-" + toHex(randomBytes(kRandomNameBytes)));
    fs::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.token = kToken;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";

    const tls::Credential gatewayKey = tls::selfSigned(settings.stateDir);
    const tls::Credential serverKey = tls::selfSigned(root / "server");

    std::mutex mutex;
    std::vector<std::string> served{kUserDest};
    std::string lastFrom;
    server::GatewayLink link(
        serverKey, {gatewayKey.pin},
        [&]() {
            const std::lock_guard<std::mutex> lock(mutex);
            return served;
        },
        [&](const std::string&, const std::string& from, server::TlsPipe& pipe) {
            {
                const std::lock_guard<std::mutex> lock(mutex);
                lastFrom = from;
            }
            std::vector<char> buffer(kEchoBytes);
            for (;;) {
                const std::size_t got = pipe.readSome(buffer.data(), buffer.size());
                if (got == 0) {
                    return true;
                }
                pipe.writeAll(buffer.data(), got);
            }
        });
    const int linkPort = link.start("127.0.0.1", 0);
    CHECK(linkPort > 0);
    const auto serve = [&](std::vector<std::string> dests) {
        {
            const std::lock_guard<std::mutex> lock(mutex);
            served = std::move(dests);
        }
        link.servedChanged();
    };

    settings.server = ServerLink{"127.0.0.1", linkPort, serverKey.pin};
    i2p::Router engine(i2p::offlineRouter(root / "i2p"));
    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);
    i2p::Router alice(borrowedFrom(port));
    alice.start();

    std::shared_ptr<i2p::Endpoint> lease;
    CHECK(waitFor([&]() {
        std::shared_ptr<i2p::Endpoint> made = leaseFor(alice, kUserDest);
        if (made->waitReady(kShortWait) && routedLocally(alice, made->routingHost())) {
            lease = made;
            return true;
        }
        made->stop();
        return false;
    }));

    const std::unique_ptr<i2p::Stream> stream
        = lease->connect(kUserDest, std::chrono::seconds(kWaitSeconds));
    CHECK(stream != nullptr);
    CHECK(echoed(*stream, "a letter for a user of this server") == "a letter for a user of this server");
    {
        const std::lock_guard<std::mutex> lock(mutex);
        CHECK(!lastFrom.empty());
        CHECK(i2p::routingHost(lastFrom) == lease->routingHost());
    }
    stream->close();

    CHECK(lease->connect(kOtherDest, kShortWait) == nullptr);

    serve({kOtherDest});
    CHECK(waitFor([&]() { return lease->lost(); }));
    const std::shared_ptr<i2p::Endpoint> built = leaseFor(alice, kUserDest);
    CHECK(!built->waitReady(kShortWait));
    CHECK(!routedLocally(alice, built->routingHost()));
    built->stop();

    i2p::EndpointConfig plain;
    plain.privacy = i2p::Privacy::eMinimal;
    plain.published = false;
    const std::shared_ptr<i2p::Endpoint> shared = alice.createEndpoint(plain);
    const std::unique_ptr<i2p::Stream> direct
        = shared->connect(kOtherDest, std::chrono::seconds(kWaitSeconds));
    CHECK(direct != nullptr);
    CHECK(echoed(*direct, "carried without a tunnel") == "carried without a tunnel");
    CHECK(waitFor([&]() { return routedLocally(alice, shared->routingHost()); }));
    direct->close();
    shared->stop();

    std::shared_ptr<i2p::Endpoint> second;
    CHECK(waitFor([&]() {
        second = leaseFor(alice, kOtherDest);
        if (second->waitReady(kShortWait) && routedLocally(alice, second->routingHost())) {
            return true;
        }
        second->stop();
        return false;
    }));
    link.setGateways({});
    CHECK(waitFor([&]() { return second->lost(); }));
    const std::shared_ptr<i2p::Endpoint> unlinked = leaseFor(alice, kOtherDest);
    CHECK(!unlinked->waitReady(kShortWait));
    CHECK(!routedLocally(alice, unlinked->routingHost()));
    unlinked->stop();

    alice.stop();
    gateway.stop();
    link.stop();
    fs::remove_all(root);
    std::printf("TestServerLink ok\n");
    return 0;
}
