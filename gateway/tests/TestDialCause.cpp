// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "RawClient.hpp"
#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>
#include <bazarish/Tls.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>

namespace asio = boost::asio;
using asio::ip::tcp;
using namespace bazarish;
using namespace bazarish::gateway;
using namespace bazarish::gateway::raw;

namespace {

constexpr const char* kPath = "/2a6f0d93c7e1";
constexpr const char* kClosedDest = "fkc4nkqn6k2bwrqsgbabnkyx4g5s2cp3nvnrdnkqxz4bzcbzrfaa.b32.i2p";
constexpr int kDialDeadlineSeconds = 30;
constexpr std::uint32_t kHelloRef = 2;
constexpr std::uint32_t kEndpointRef = 4;
constexpr std::uint32_t kStreamRef = 6;
// Far inside the deadline: a refused connection is not retried until the deadline runs out.
constexpr std::chrono::seconds kRefusedWithin{5};

Frame about(Dialled& dialled, const std::uint32_t ref)
{
    for (;;) {
        const Frame frame = receive(dialled);
        if (frame.ref == ref && frame.type != FrameType::eEndpointStatus) {
            return frame;
        }
    }
}

int closedPort()
{
    asio::io_context io;
    const tcp::acceptor door(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    return door.local_endpoint().port();
}

}  // namespace

int main()
{
    const std::filesystem::path root = testutil::freshDir("gateway-dial-cause-test");
    std::filesystem::create_directories(root);
    const tls::Credential nobody = tls::selfSigned(root / "nobody");

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";
    settings.direct = {DirectRoute{kClosedDest, "127.0.0.1", closedPort(), nobody.pin}};

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));
    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    asio::io_context io;
    Seat seat;
    Dialled client = dial(io, port, kPath, gateway.fingerprint(), seat, false);
    CHECK(client.socket != nullptr);
    send(client, encodeJson(FrameType::eHello, kHelloRef, {{"version", kProtocolVersion}}));
    CHECK(about(client, kHelloRef).type == FrameType::eReady);
    send(client,
        encodeJson(FrameType::eEndpointCreate, kEndpointRef,
            {{"kind", "stream"}, {"published", false}}));
    CHECK(about(client, kEndpointRef).type == FrameType::eOk);

    const auto asked = std::chrono::steady_clock::now();
    send(client,
        encodeJson(FrameType::eStreamOpen, kStreamRef,
            {{"endpoint", kEndpointRef}, {"host", kClosedDest},
                {"deadline", kDialDeadlineSeconds}}));
    const Frame answer = about(client, kStreamRef);
    const auto answered = std::chrono::steady_clock::now() - asked;
    CHECK(answer.type == FrameType::eStreamReset);
    CHECK(answered < kRefusedWithin);
    const nlohmann::json body = bodyJson(answer);
    CHECK(body.value("code", std::string()) == faultName(Fault::eUnreachable));
    CHECK(body.value("message", std::string()).find("refused") != std::string::npos);

    boost::system::error_code ignored;
    client.socket->next_layer().close(ignored);
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestDialCause ok\n");
    return 0;
}
