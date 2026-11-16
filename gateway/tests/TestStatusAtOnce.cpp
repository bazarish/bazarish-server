// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "RawClient.hpp"
#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Tls.hpp>

#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

namespace asio = boost::asio;
using namespace bazarish;
using namespace bazarish::gateway;
using namespace bazarish::gateway::raw;

namespace {

constexpr const char* kPath = "/7c1e4b09d2a6";
constexpr const char* kFacadeDest = "fkc4nkqn6k2bwrqsgbabnkyx4g5s2cp3nvnrdnkqxz4bzcbzrfaa.b32.i2p";
constexpr int kFacadePort = 9;
constexpr std::uint32_t kHelloRef = 2;
constexpr std::uint32_t kFirstEndpointRef = 4;
constexpr std::uint32_t kRefStep = 2;
constexpr int kEndpoints = 9;
constexpr int kStatusPeriodShare = 5;

std::chrono::steady_clock::duration untilReady(Dialled& client, const std::uint32_t ref)
{
    const auto asked = std::chrono::steady_clock::now();
    send(client,
        encodeJson(FrameType::eEndpointCreate, ref,
            {{"kind", "stream"}, {"published", false}, {"target", kFacadeDest}}));
    for (;;) {
        const Frame frame = receive(client);
        if (frame.ref == ref && frame.type == FrameType::eEndpointStatus
            && bodyJson(frame).value("ready", false)) {
            return std::chrono::steady_clock::now() - asked;
        }
    }
}

}  // namespace

int main()
{
    const std::filesystem::path root = testutil::freshDir("gateway-status-at-once-test");
    std::filesystem::create_directories(root);
    const tls::Credential facade = tls::selfSigned(root / "facade");

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";
    settings.direct = {DirectRoute{kFacadeDest, "127.0.0.1", kFacadePort, facade.pin}};

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));
    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    asio::io_context io;
    Seat seat;
    Dialled client = dial(io, port, kPath, gateway.fingerprint(), seat, false);
    CHECK(client.socket != nullptr);
    send(client, encodeJson(FrameType::eHello, kHelloRef, {{"version", kProtocolVersion}}));
    CHECK(receive(client).type == FrameType::eReady);

    std::vector<std::chrono::steady_clock::duration> waited;
    for (int made = 0; made < kEndpoints; ++made) {
        waited.push_back(untilReady(client, kFirstEndpointRef + kRefStep * made));
    }
    std::sort(waited.begin(), waited.end());
    CHECK(waited[waited.size() / 2] < kStatusPeriod / kStatusPeriodShare);

    boost::system::error_code ignored;
    client.socket->next_layer().close(ignored);
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestStatusAtOnce ok\n");
    return 0;
}
