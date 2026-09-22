// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestUtil.hpp"

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
constexpr const char* kToken = "another-static-token";

// What the client heard, so the test waits for it rather than sleeping.
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

http::SocketDial dialFor(const int port, const std::string& cookie)
{
    http::SocketDial dial;
    dial.host = "127.0.0.1";
    dial.port = port;
    dial.path = kPath;
    dial.tls = false;
    dial.subprotocol = kSubprotocol;
    dial.maxMessageBytes = kMaxFrameBytes;
    dial.headers[kTokenHeader] = kToken;
    if (!cookie.empty()) {
        dial.headers[kSessionHeader] = cookie;
    }
    return dial;
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-client-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.token = kToken;
    settings.stateDir = root / "state";
    settings.decoyMinBytes = 512;
    settings.decoyMaxBytes = 1024;
    settings.notFoundBody = "<html>nothing</html>";

    i2p::RouterConfig routerConfig;
    routerConfig.dataDir = root / "i2p";
    i2p::Router router(routerConfig);

    Gateway gateway(settings, router);
    const int port = gateway.start();
    CHECK(port > 0);

    // A probe is what a client does to find out whether an address is a gateway
    // at all: a decoy request, and the answer that comes back.
    const http::Probe reached = http::probeHost(dialFor(port, {}), std::string("noise"));
    CHECK(reached.reached);
    CHECK(reached.status == 200);

    // Without the token it is the same 404 as any other address on the host.
    http::SocketDial wrong = dialFor(port, {});
    wrong.headers[kTokenHeader] = "not-the-token";
    const http::Probe refused = http::probeHost(wrong, std::string("noise"));
    CHECK(refused.reached);
    CHECK(refused.status == 404);

    // And the socket opens, says hello, and is answered.
    Heard heard;
    const http::SocketDialResult opened = http::openSocket(
        dialFor(port, {}),
        [&heard](const http::SocketPtr&, const std::vector<unsigned char>& message) {
            heard.note(decode(message.data(), message.size()));
        },
        [&heard](const http::SocketPtr&) {
            const std::lock_guard<std::mutex> lock(heard.mutex);
            heard.gone = true;
        });
    CHECK(opened.error.empty());
    CHECK(opened.socket != nullptr);

    opened.socket->send(encodeJson(FrameType::eHello, 2, {{"version", kProtocolVersion}}));
    CHECK(heard.waitForCount(1));
    const Frame ready = heard.frames.front();
    CHECK(ready.type == FrameType::eReady);
    CHECK(ready.ref == 2);
    const nlohmann::json body = bodyJson(ready);
    CHECK(body["version"] == kProtocolVersion);
    CHECK(body["resumed"] == false);
    const std::string cookie = body["session"];
    CHECK(!cookie.empty());

    // The same session, rejoined by its cookie after the socket went away on
    // purpose - which is what the client does to keep a watcher from seeing one
    // connection that lives for hours.
    opened.socket->close();
    Heard second;
    const http::SocketDialResult again = http::openSocket(
        dialFor(port, cookie),
        [&second](const http::SocketPtr&, const std::vector<unsigned char>& message) {
            second.note(decode(message.data(), message.size()));
        },
        nullptr);
    CHECK(again.error.empty());
    CHECK(again.socket != nullptr);
    again.socket->send(encodeJson(FrameType::eHello, 2, {{"version", kProtocolVersion}}));
    CHECK(second.waitForCount(1));
    const nlohmann::json rejoined = bodyJson(second.frames.front());
    CHECK(rejoined["resumed"] == true);
    CHECK(rejoined["session"] == cookie);
    again.socket->close();

    // And the transport itself: a router whose engine is somebody else's. The
    // engine behind the gateway is never started: minting a destination and
    // naming it needs keys, not tunnels, and a test that waited for tunnels
    // would be a test of the network.
    i2p::RouterConfig gatewayConfig;
    gatewayConfig.backend = i2p::Backend::eGateway;
    gatewayConfig.gatewayHost = "127.0.0.1";
    gatewayConfig.gatewayPort = port;
    gatewayConfig.gatewayPath = kPath;
    gatewayConfig.gatewayToken = kToken;
    gatewayConfig.gatewayTls = false;
    i2p::Router borrowed(gatewayConfig);

    const i2p::Capabilities what = borrowed.capabilities();
    CHECK(what.routerCounters);
    CHECK(what.destinationCounters);
    CHECK(!what.netDbSample);
    CHECK(!what.proxy);
    CHECK(!what.offlineKeys);

    borrowed.start();
    CHECK(borrowed.running());

    // The gateway mints the destination: the client sends no key and gets back
    // an address.
    const std::shared_ptr<i2p::Endpoint> mine = borrowed.createEndpoint(
        i2p::EndpointConfig{borrowed.generateKeys(), i2p::Privacy::eMinimal, 2,
            /*published=*/false, "Test", {}});
    CHECK(mine != nullptr);
    const std::string host = mine->routingHost();
    CHECK(host.size() > 50);
    CHECK(host.find(".b32.i2p") != std::string::npos);

    // What the gateway holds it does not hand over, and asking says so rather
    // than answering with something empty.
    bool refusedKey = false;
    try {
        (void)mine->privateBlob();
    } catch (const std::exception&) {
        refusedKey = true;
    }
    CHECK(refusedKey);
    bool refusedProxy = false;
    try {
        borrowed.setSocksProxy("127.0.0.1", 9050);
    } catch (const std::exception&) {
        refusedProxy = true;
    }
    CHECK(refusedProxy);

    // The status view sees this session's destinations and nothing else.
    const std::vector<i2p::LocalDestination> seen = borrowed.localDestinations();
    CHECK(seen.size() == 1);
    CHECK(seen.front().host == host);

    mine->stop();
    borrowed.stop();
    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestGatewayClient ok\n");
    return 0;
}
