// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/GatewayChannel.hpp>
#include <bazarish/WebSocketClient.hpp>

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/9d1c4b7e2f60";

struct Heard {
    std::mutex mutex;
    std::condition_variable changed;
    std::vector<Frame> frames;
    bool gone = false;

    void note(const Frame& frame)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex);
            frames.push_back(frame);
        }
        changed.notify_all();
    }

    bool waitForCount(const std::size_t count)
    {
        std::unique_lock<std::mutex> lock(mutex);
        return changed.wait_for(
            lock, std::chrono::seconds(10), [&]() { return frames.size() >= count; });
    }
};

http::SocketDial dialFor(const int port)
{
    http::SocketDial dial;
    dial.host = "127.0.0.1";
    dial.port = port;
    dial.path = kPath;
    dial.tls = false;
    dial.maxMessageBytes = kMaxRecordBytes;
    return dial;
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = testutil::freshDir("gateway-client-test");
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.stateDir = root / "state";
    settings.decoyMinBytes = 512;
    settings.decoyMaxBytes = 1024;
    settings.notFoundBody = "<html>nothing</html>";

    i2p::Router router(i2p::offlineRouter(root / "i2p"));

    Gateway gateway(settings, router);
    const int port = gateway.start();
    CHECK(port > 0);

    const http::Probe reached = http::probeHost(dialFor(port), std::string("noise"));
    CHECK(reached.reached);
    CHECK(reached.status == 200);

    http::SocketDial elsewhere = dialFor(port);
    elsewhere.path = std::string(kPath) + "/elsewhere";
    const http::Probe refused = http::probeHost(elsewhere, std::string("noise"));
    CHECK(refused.reached);
    CHECK(refused.status == 404);

    const ChannelOpened wrongKey = openChannel(dialFor(port), Identity::generate().fingerprint(),
        std::nullopt, [](const http::SocketPtr&, const std::vector<unsigned char>&) {},
        [](const http::SocketPtr&) {});
    CHECK(wrongKey.socket == nullptr);
    CHECK(wrongKey.wrongGateway);

    Heard heard;
    const ChannelOpened opened = openChannel(
        dialFor(port), gateway.fingerprint(), std::nullopt,
        [&heard](const http::SocketPtr&, const std::vector<unsigned char>& message) {
            heard.note(decode(message));
        },
        [&heard](const http::SocketPtr&) {
            const std::lock_guard<std::mutex> lock(heard.mutex);
            heard.gone = true;
        });
    CHECK(opened.error.empty());
    CHECK(opened.socket != nullptr);
    CHECK(opened.welcome.has_value());

    opened.socket->send(encodeJson(FrameType::eHello, 2, {{"version", kProtocolVersion}}));
    CHECK(heard.waitForCount(1));
    const Frame ready = heard.frames.front();
    CHECK(ready.type == FrameType::eReady);
    CHECK(ready.ref == 2);
    const nlohmann::json body = bodyJson(ready);
    CHECK(body["version"] == kProtocolVersion);
    CHECK(body["resumed"] == false);

    opened.socket->close();
    Heard second;
    const ChannelOpened again = openChannel(dialFor(port), gateway.fingerprint(),
        ChannelJoin{opened.welcome->sessionKey, opened.welcome->tickets.front()},
        [&second](const http::SocketPtr&, const std::vector<unsigned char>& message) {
            const Frame frame = decode(message);
            if (frame.type != FrameType::eTickets) {
                second.note(frame);
            }
        },
        [](const http::SocketPtr&) {});
    CHECK(again.error.empty());
    CHECK(again.socket != nullptr);
    CHECK(!again.welcome.has_value());
    again.socket->send(encodeJson(FrameType::eHello, 2, {{"version", kProtocolVersion}}));
    CHECK(second.waitForCount(1));
    const nlohmann::json rejoined = bodyJson(second.frames.front());
    CHECK(rejoined["resumed"] == true);
    again.socket->close();

    i2p::RouterConfig gatewayConfig;
    gatewayConfig.backend = i2p::Backend::eGateway;
    gatewayConfig.gatewayHost = "127.0.0.1";
    gatewayConfig.gatewayPort = port;
    gatewayConfig.gatewayPath = kPath;
    gatewayConfig.gatewayFingerprint = gateway.fingerprint();
    gatewayConfig.gatewayTls = false;
    i2p::Router borrowed(gatewayConfig);

    const i2p::Capabilities what = borrowed.capabilities();
    CHECK(!what.routerCounters);
    CHECK(what.destinationCounters);
    CHECK(!what.netDbSample);
    CHECK(!what.proxy);
    CHECK(!what.offlineKeys);

    borrowed.start();
    CHECK(borrowed.running());

    i2p::EndpointConfig wanted;
    wanted.privacy = i2p::Privacy::eMinimal;
    wanted.tunnelQuantity = 2;
    wanted.published = false;
    wanted.label = "Test";
    wanted.accountLabel = "an account";
    const std::shared_ptr<i2p::Endpoint> mine = borrowed.createEndpoint(wanted);
    CHECK(mine != nullptr);
    const std::string host = mine->routingHost();
    CHECK(host.size() > 50);
    CHECK(host.find(".b32.i2p") != std::string::npos);

    i2p::EndpointConfig ofMyOwn;
    ofMyOwn.keys = i2p::Keys::generate();
    CHECK_THROWS(borrowed.createEndpoint(ofMyOwn));

    bool refusedProxy = false;
    try {
        borrowed.setSocksProxy("127.0.0.1", 9050);
    } catch (const std::exception&) {
        refusedProxy = true;
    }
    CHECK(refusedProxy);

    CHECK(borrowed.running());
    CHECK(borrowed.knownRouters() == 0);
    CHECK(borrowed.transportPeers().empty());
    if (what.proxy) {
        (void)borrowed.proxyState();
    }
    bool proxyRefused = false;
    try {
        (void)borrowed.proxyState();
    } catch (const std::exception&) {
        proxyRefused = true;
    }
    CHECK(proxyRefused);

    const std::vector<i2p::LocalDestination> seen = borrowed.localDestinations();
    CHECK(seen.size() == 1);
    CHECK(seen.front().host == host);
    CHECK(seen.front().label == "Test");
    CHECK(seen.front().accountLabel == "an account");

    mine->stop();
    borrowed.stop();
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestGatewayClient ok\n");
    return 0;
}
