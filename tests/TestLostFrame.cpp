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

constexpr const char* kPath = "/0e5b73c1a9f4";
constexpr const char* kToken = "a-seventh-static-token";
constexpr int kWaitSeconds = 30;
// One window, so everything sent is retained for a replay and the arithmetic of
// the loss is the whole of the test.
constexpr std::size_t kTotalBytes = kStreamWindowBytes;
constexpr std::size_t kReadChunk = 8 * 1024;
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
    // The only socket that goes is the one this test takes away.
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

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-lost-frame-test";
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

    // The reader is behind the relay: it is the socket that has to swallow a
    // write and then die with it.
    Relay relay(port);
    i2p::Router reader(borrowedFrom(relay.port()));
    i2p::Router writer(borrowedFrom(port));
    reader.start();
    writer.start();

    i2p::EndpointConfig serving;
    serving.privacy = i2p::Privacy::eMinimal;
    serving.published = true;
    const std::shared_ptr<i2p::Endpoint> theirs = reader.createEndpoint(serving);

    i2p::EndpointConfig dialling;
    dialling.privacy = i2p::Privacy::eMinimal;
    dialling.published = false;
    const std::shared_ptr<i2p::Endpoint> mine = writer.createEndpoint(dialling);

    const std::unique_ptr<i2p::Stream> out
        = mine->connect(theirs->routingHost(), std::chrono::seconds(kWaitSeconds));
    CHECK(out != nullptr);
    std::string peer;
    const std::unique_ptr<i2p::Stream> in
        = theirs->accept(peer, std::chrono::seconds(kWaitSeconds));
    CHECK(in != nullptr);

    std::atomic<std::size_t> received{0};
    in->setReadTimeout(std::chrono::seconds(kWaitSeconds));
    std::thread taking([&]() {
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
            // Gave up: something was lost and never came again.
        }
    });

    // From here the relay takes what the gateway writes for the reader and holds
    // it. The gateway's writes succeed, so it credits the writer and counts the
    // bytes delivered - and the reader has not seen them.
    relay.stall(true);
    std::string payload;
    while (payload.size() < kTotalBytes) {
        payload += static_cast<char>('a' + payload.size() % 26);
    }
    out->writeAll(payload.data(), payload.size());
    CHECK(waitFor([&]() { return out->pendingBytes() == 0; }));
    CHECK(received.load() < kTotalBytes);

    // And now the socket dies with them in it. Nothing else will ever ask for
    // those bytes: the writer has been credited, the gateway has counted them
    // out, and only the reader's own count says otherwise.
    relay.cut(0);
    relay.stall(false);
    CHECK(waitFor([&]() { return gateway.rejoins() >= 1; }));

    // The resume names what the reader actually received, and what is above it
    // goes out again - on the socket that has just been handed over, which is
    // the one thing the replay must not be held back from.
    CHECK(waitFor([&]() { return received.load() == kTotalBytes; }));
    taking.join();
    CHECK(gateway.refusals() == 0);

    out->close();
    in->close();
    mine->stop();
    theirs->stop();
    writer.stop();
    reader.stop();
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestLostFrame ok\n");
    return 0;
}
