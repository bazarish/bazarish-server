// Bazarish project (c) 2026
#include "Gateway.hpp"

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
// Enough to span several replacements, read in pieces with a pause between so
// the socket is quiet when the draw comes up. A socket carrying something is
// never dropped, so a test that never pauses would never see a churn.
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
    // Seconds instead of minutes, so what a day of running does shows up in
    // ten seconds of testing.
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

    i2p::RouterConfig routerConfig;
    routerConfig.dataDir = root / "i2p";
    // Never started: two clients of one gateway meet inside it.
    i2p::Router engine(routerConfig);

    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    i2p::Router alice(borrowedFrom(port));
    i2p::Router bob(borrowedFrom(port));
    alice.start();
    bob.start();

    // Neither destination is raised for a transfer, so the stream rides the
    // control socket - which is the one being replaced underneath it.
    i2p::EndpointConfig serving{alice.generateKeys()};
    serving.privacy = i2p::Privacy::eMinimal;
    serving.published = true;
    const std::shared_ptr<i2p::Endpoint> hers = alice.createEndpoint(serving);

    i2p::EndpointConfig dialling{bob.generateKeys()};
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
        // A write queues and returns, so this does not wait on the far side.
        out->writeAll(piece.data(), piece.size());
        sent += piece;
        // Long enough for the socket to fall quiet and be replaced.
        std::this_thread::sleep_for(std::chrono::milliseconds(1400));
    }

    // Every byte, in order, across however many sockets carried them.
    std::string got;
    std::vector<char> buffer(4096);
    in->setReadTimeout(std::chrono::seconds(kWaitSeconds));
    while (got.size() < sent.size()) {
        const std::size_t read = in->readSome(buffer.data(), buffer.size());
        if (read == 0) {
            break;
        }
        got.append(buffer.data(), read);
    }
    CHECK(got.size() == sent.size());
    CHECK(got == sent);

    // And the sockets really were replaced: without that this would be a plain
    // transfer wearing a test's name.
    CHECK(gateway.rejoins() >= 2);

    // Nothing was refused along the way. A test that passes while the gateway
    // is turning frames away is a test that proves less than it looks.
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
