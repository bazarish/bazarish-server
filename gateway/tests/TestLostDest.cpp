// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/4f7a0c93e6b1";
constexpr int kWaitSeconds = 20;

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

}  // namespace

int main()
{
    const std::filesystem::path root
        = testutil::freshDir("gateway-lost-dest-test");
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));

    std::unique_ptr<Gateway> first = std::make_unique<Gateway>(settings, engine);
    const int port = first->start();
    CHECK(port > 0);

    i2p::Router client(borrowedFrom(port, first->fingerprint()));
    client.start();

    i2p::EndpointConfig wanted;
    wanted.privacy = i2p::Privacy::eMinimal;
    wanted.published = false;
    const std::shared_ptr<i2p::Endpoint> before = client.createEndpoint(wanted);
    CHECK(testutil::waitFor([&]() { return first->sockets() >= 1; }));

    first.reset();
    settings.listenPort = port;
    Gateway second(settings, engine);
    CHECK(second.start() == port);
    CHECK(testutil::waitFor([&]() { return second.sockets() >= 1; }));

    CHECK(testutil::waitFor([&]() { return before->lost(); }));
    CHECK(!before->ready());
    CHECK(before->connect(
        "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p", std::chrono::seconds(1))
        == nullptr);

    const auto asked = std::chrono::steady_clock::now();
    CHECK(!before->waitReady(std::chrono::seconds(kWaitSeconds)));
    CHECK(std::chrono::steady_clock::now() - asked < std::chrono::seconds(1));

    CHECK(second.refusals() == 0);

    i2p::EndpointConfig serving;
    serving.privacy = i2p::Privacy::eMinimal;
    serving.published = true;
    const std::shared_ptr<i2p::Endpoint> hers = client.createEndpoint(serving);
    const std::string host = hers->routingHost();
    CHECK(host.find(".b32.i2p") != std::string::npos);

    const std::shared_ptr<i2p::Endpoint> after = client.createEndpoint(wanted);
    const std::unique_ptr<i2p::Stream> out
        = after->connect(host, std::chrono::seconds(kWaitSeconds));
    CHECK(out != nullptr);
    std::string caller;
    const std::unique_ptr<i2p::Stream> in
        = hers->accept(caller, std::chrono::seconds(kWaitSeconds));
    CHECK(in != nullptr);
    CHECK(second.refusals() == 0);

    out->close();
    in->close();
    after->stop();
    hers->stop();
    before->stop();
    client.stop();
    second.stop();
    std::filesystem::remove_all(root);
    std::printf("TestLostDest ok\n");
    return 0;
}
