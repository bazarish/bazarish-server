// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/7c1e93b52fa8";
constexpr const char* kToken = "a-fourth-static-token";
constexpr int kWaitSeconds = 60;
constexpr std::size_t kPieceBytes = 32 * 1024;
constexpr int kRounds = 8;

i2p::RouterConfig borrowedFrom(const int port)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayToken = kToken;
    config.gatewayTls = false;
    config.gatewayDecoyMin = std::chrono::milliseconds(300);
    config.gatewayDecoyMax = std::chrono::milliseconds(600);
    config.gatewayControlMinLife = std::chrono::seconds(1);
    config.gatewayControlMaxLife = std::chrono::seconds(2);
    config.gatewayControlMaxGap = std::chrono::seconds(1);
    return config;
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-churn-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.token = kToken;
    settings.stateDir = root / "state";
    settings.decoyMinBytes = 512;
    settings.decoyMaxBytes = 2048;
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

    i2p::EndpointConfig dialling;
    dialling.privacy = i2p::Privacy::eMinimal;
    dialling.published = false;
    const std::shared_ptr<i2p::Endpoint> his = bob.createEndpoint(dialling);

    const std::unique_ptr<i2p::Stream> out
        = his->connect(hers->routingHost(), std::chrono::seconds(kWaitSeconds));
    CHECK(out != nullptr);
    std::string caller;
    const std::unique_ptr<i2p::Stream> in
        = hers->accept(caller, std::chrono::seconds(kWaitSeconds));
    CHECK(in != nullptr);

    std::string sent;
    for (int round = 0; round < kRounds; ++round) {
        std::string piece;
        while (piece.size() < kPieceBytes) {
            piece += static_cast<char>('a' + (round % 26));
        }
        out->writeAll(piece.data(), piece.size());
        sent += piece;
        std::this_thread::sleep_for(std::chrono::milliseconds(1400));
    }

    std::string got;
    std::vector<char> buffer(4096);
    in->setReadTimeout(std::chrono::seconds(kWaitSeconds));
    try {
        while (got.size() < sent.size()) {
            const std::size_t read = in->readSome(buffer.data(), buffer.size());
            if (read == 0) {
                break;
            }
            got.append(buffer.data(), read);
        }
    } catch (const std::exception& error) {
        std::printf("stalled: %s\n  got %zu of %zu, sender holds %zu, rejoins %zu,"
                    " refusals %zu, sockets %zu\n",
            error.what(), got.size(), sent.size(), out->pendingBytes(), gateway.rejoins(),
            gateway.refusals(), gateway.sockets());
        std::fflush(stdout);
    }
    CHECK(got.size() == sent.size());
    CHECK(got == sent);

    CHECK(gateway.rejoins() >= 2);

    CHECK(gateway.refusals() == 0);

    out->close();
    in->close();
    his->stop();
    hers->stop();
    bob.stop();
    alice.stop();
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestControlChurn ok (%zu rejoins)\n", gateway.rejoins());
    return 0;
}
