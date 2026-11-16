// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "RawClient.hpp"
#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::gateway;
using namespace bazarish::gateway::raw;

namespace {

constexpr const char* kPath = "/c4e82a17f05b";
constexpr int kWaitSeconds = 20;
constexpr std::uint32_t kHelloRef = 2;
constexpr std::uint32_t kEndpointRef = 4;
constexpr std::uint32_t kStreamRef = 6;
constexpr std::uint32_t kRejoinHelloRef = 8;
constexpr std::uint32_t kResumeRef = 10;
// Longer than the five seconds the gateway once held a rejoined stream by the clock.
constexpr std::chrono::seconds kResumeLate{6};
constexpr std::chrono::milliseconds kNewBytesLand{500};

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

Frame answerTo(Dialled& dialled, const std::uint32_t ref)
{
    for (;;) {
        const Frame frame = receive(dialled);
        if (frame.ref == ref
            && (frame.type == FrameType::eOk || frame.type == FrameType::eReady
                || frame.type == FrameType::eStreamOpened || frame.type == FrameType::eError
                || frame.type == FrameType::eStreamReset)) {
            return frame;
        }
    }
}

}  // namespace

int main()
{
    const std::filesystem::path root = testutil::freshDir("gateway-late-resume-test");
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
    const std::string fingerprint = gateway.fingerprint();

    i2p::Router alice(borrowedFrom(port, fingerprint));
    alice.start();
    i2p::EndpointConfig serving;
    serving.privacy = i2p::Privacy::eMinimal;
    serving.published = true;
    const std::shared_ptr<i2p::Endpoint> hers = alice.createEndpoint(serving);

    asio::io_context io;
    Seat seat;
    Dialled first = dial(io, port, kPath, fingerprint, seat, false);
    CHECK(first.socket != nullptr);
    send(first, encodeJson(FrameType::eHello, kHelloRef, {{"version", kProtocolVersion}}));
    CHECK(answerTo(first, kHelloRef).type == FrameType::eReady);
    send(first,
        encodeJson(FrameType::eEndpointCreate, kEndpointRef,
            {{"kind", "stream"}, {"published", false}}));
    CHECK(answerTo(first, kEndpointRef).type == FrameType::eOk);
    send(first,
        encodeJson(FrameType::eStreamOpen, kStreamRef,
            {{"endpoint", kEndpointRef}, {"host", hers->routingHost()},
                {"deadline", kWaitSeconds}}));
    CHECK(answerTo(first, kStreamRef).type == FrameType::eStreamOpened);
    std::string caller;
    const std::unique_ptr<i2p::Stream> theirs
        = hers->accept(caller, std::chrono::seconds(kWaitSeconds));
    CHECK(theirs != nullptr);

    const std::string before = "said before the socket died;";
    theirs->writeAll(viewOf(before));
    std::string heardFirst;
    while (heardFirst.size() < before.size()) {
        const Frame frame = receive(first);
        if (frame.type == FrameType::eStreamData && frame.ref == kStreamRef) {
            heardFirst.append(frame.body.begin(), frame.body.end());
        }
    }
    CHECK(heardFirst == before);
    boost::system::error_code ignored;
    first.socket->next_layer().close(ignored);

    Dialled again = dial(io, port, kPath, fingerprint, seat, true);
    CHECK(again.socket != nullptr);
    send(again, encodeJson(FrameType::eHello, kRejoinHelloRef, {{"version", kProtocolVersion}}));
    const Frame ready = answerTo(again, kRejoinHelloRef);
    CHECK(ready.type == FrameType::eReady);
    CHECK(bodyJson(ready).value("resumed", false));

    std::this_thread::sleep_for(kResumeLate);
    const std::string after = "said after the rejoin";
    theirs->writeAll(viewOf(after));
    std::this_thread::sleep_for(kNewBytesLand);
    send(again,
        encodeJson(FrameType::eResume, kResumeRef,
            {{"streams", nlohmann::json::array({{{"id", kStreamRef}, {"received", 0}}})}}));

    const std::string expected = before + after;
    std::string heard;
    while (heard.size() < expected.size()) {
        const Frame frame = receive(again);
        if (frame.type == FrameType::eStreamData && frame.ref == kStreamRef) {
            heard.append(frame.body.begin(), frame.body.end());
        }
    }
    CHECK(heard == expected);

    again.socket->next_layer().close(ignored);
    theirs->close();
    hers->stop();
    alice.stop();
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestLateResume ok\n");
    return 0;
}
