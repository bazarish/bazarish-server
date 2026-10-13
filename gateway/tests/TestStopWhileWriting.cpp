// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/5d0c94e1b7a3";
constexpr const char* kToken = "a-fourth-static-token";
constexpr int kWaitSeconds = 20;
constexpr int kRounds = 40;
constexpr std::size_t kChunkBytes = 64 * 1024;
constexpr int kStopWithinSeconds = 10;
constexpr int kLongestHeadStartMs = 30;

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

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-stop-test";
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

    i2p::Router alice(borrowedFrom(port));
    i2p::Router bob(borrowedFrom(port));
    alice.start();
    bob.start();

    i2p::EndpointConfig serving;
    serving.privacy = i2p::Privacy::eMinimal;
    serving.published = true;
    const std::shared_ptr<i2p::Endpoint> hers = alice.createEndpoint(serving);
    const std::string host = hers->routingHost();

    const std::vector<char> chunk(kChunkBytes, 'x');
    for (int round = 0; round < kRounds; ++round) {
        i2p::EndpointConfig dialling;
        dialling.privacy = i2p::Privacy::eMinimal;
        dialling.published = false;
        const std::shared_ptr<i2p::Endpoint> his = bob.createEndpoint(dialling);
        const std::unique_ptr<i2p::Stream> out
            = his->connect(host, std::chrono::seconds(kWaitSeconds));
        CHECK(out != nullptr);
        std::string caller;
        const std::unique_ptr<i2p::Stream> in
            = hers->accept(caller, std::chrono::seconds(kWaitSeconds));
        CHECK(in != nullptr);

        std::thread reader([&]() {
            std::vector<char> buffer(kChunkBytes);
            try {
                while (in->readSome(buffer.data(), buffer.size()) > 0) {
                }
            } catch (const std::exception&) {
            }
        });
        std::thread writer([&]() {
            try {
                for (;;) {
                    out->writeAll(chunk.data(), chunk.size());
                }
            } catch (const std::exception&) {
            }
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(round % kLongestHeadStartMs));
        std::atomic<bool> stopped{false};
        std::thread watchdog([&]() {
            const auto deadline
                = std::chrono::steady_clock::now() + std::chrono::seconds(kStopWithinSeconds);
            while (!stopped.load()) {
                if (std::chrono::steady_clock::now() > deadline) {
                    std::fprintf(stderr, "round %d: stopping a destination with a stream"
                        " being written never returned\n", round);
                    std::_Exit(1);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        });
        his->stop();
        stopped.store(true);
        watchdog.join();
        writer.join();
        in->close();
        reader.join();
    }

    hers->stop();
    bob.stop();
    alice.stop();
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestStopWhileWriting ok\n");
    return 0;
}
