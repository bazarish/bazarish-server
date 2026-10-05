// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "Relay.hpp"
#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/8a1d6f04c9b2";
constexpr const char* kToken = "a-sixth-static-token";
constexpr int kWaitSeconds = 30;
constexpr std::size_t kWindows = 3;
constexpr std::size_t kTotalBytes = kWindows * kStreamWindowBytes;
constexpr std::size_t kReadChunk = 16 * 1024;
constexpr std::chrono::milliseconds kSettled{500};
constexpr std::chrono::milliseconds kLook{20};

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
        std::this_thread::sleep_for(kLook);
    }
    return done();
}

void settle(const std::function<std::size_t()>& read)
{
    std::size_t last = read();
    auto since = std::chrono::steady_clock::now();
    const auto deadline = since + std::chrono::seconds(kWaitSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(kLook);
        const std::size_t now = read();
        if (now != last) {
            last = now;
            since = std::chrono::steady_clock::now();
            continue;
        }
        if (std::chrono::steady_clock::now() - since >= kSettled) {
            return;
        }
    }
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-lost-credit-test";
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
    i2p::Router sender(borrowedFrom(relay.port()));
    i2p::Router receiver(borrowedFrom(port));
    sender.start();
    receiver.start();

    i2p::EndpointConfig serving;
    serving.privacy = i2p::Privacy::eMinimal;
    serving.published = true;
    const std::shared_ptr<i2p::Endpoint> theirs = receiver.createEndpoint(serving);

    i2p::EndpointConfig dialling;
    dialling.privacy = i2p::Privacy::eMinimal;
    dialling.published = false;
    const std::shared_ptr<i2p::Endpoint> mine = sender.createEndpoint(dialling);

    const std::unique_ptr<i2p::Stream> out
        = mine->connect(theirs->routingHost(), std::chrono::seconds(kWaitSeconds));
    CHECK(out != nullptr);
    std::string peer;
    const std::unique_ptr<i2p::Stream> in
        = theirs->accept(peer, std::chrono::seconds(kWaitSeconds));
    CHECK(in != nullptr);

    std::string payload;
    while (payload.size() < kTotalBytes) {
        payload += static_cast<char>('a' + payload.size() % 26);
    }
    out->writeAll(payload.data(), payload.size());
    settle([&]() { return out->pendingBytes(); });
    CHECK(out->pendingBytes() >= kStreamWindowBytes);

    relay.hold(true);
    relay.cut(0);
    CHECK(waitFor([&]() { return gateway.sockets() == 1; }));

    std::atomic<std::size_t> received{0};
    std::atomic<bool> ended{false};
    in->setReadTimeout(std::chrono::seconds(kWaitSeconds));
    std::thread reader([&]() {
        std::vector<char> buffer(kReadChunk);
        try {
            while (received.load() < kTotalBytes) {
                const std::size_t got = in->readSome(buffer.data(), buffer.size());
                if (got == 0) {
                    break;
                }
                received.fetch_add(got);
            }
        } catch (const std::exception&) {
        }
        ended.store(true);
    });
    settle([&]() { return received.load(); });
    CHECK(received.load() >= kStreamWindowBytes);
    CHECK(received.load() < kTotalBytes);

    relay.hold(false);
    CHECK(waitFor([&]() { return gateway.sockets() == 2; }));

    CHECK(waitFor([&]() { return received.load() == kTotalBytes; }));
    reader.join();
    CHECK(ended.load());
    CHECK(gateway.refusals() == 0);

    out->close();
    in->close();
    mine->stop();
    theirs->stop();
    sender.stop();
    receiver.stop();
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestLostCredit ok\n");
    return 0;
}
