// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>
#include <bazarish/Tls.hpp>
#include <bazarish/TlsContext.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
using asio::ip::tcp;
using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/7b31e0c9d2a6";
constexpr const char* kStalledDest = "fkc4nkqn6k2bwrqsgbabnkyx4g5s2cp3nvnrdnkqxz4bzcbzrfaa.b32.i2p";
constexpr int kWaitSeconds = 20;
constexpr int kStalledBufferBytes = 4096;
// Far past what the kernel buffers towards a peer that reads nothing.
constexpr std::size_t kFloodBytes = 16 * 1024 * 1024;
constexpr std::size_t kFloodChunk = 64 * 1024;
constexpr std::chrono::milliseconds kFloodHeadStart{500};
constexpr std::chrono::seconds kOtherStreamWithin{10};

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

class StalledPeer {
public:
    explicit StalledPeer(const tls::Credential& served)
        : door_(io_)
        , context_(tls::serverContext(served.certificate.string(), served.key.string()))
    {
        door_.open(tcp::v4());
        door_.set_option(asio::socket_base::receive_buffer_size(kStalledBufferBytes));
        door_.bind(tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
        door_.listen();
        holder_ = std::thread([this]() { hold(); });
    }

    ~StalledPeer()
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            released_ = true;
        }
        letGo_.notify_all();
        boost::system::error_code ignored;
        door_.close(ignored);
        holder_.join();
    }

    int port() const { return door_.local_endpoint().port(); }
    bool shookHands() const { return shook_.load(); }

private:
    void hold()
    {
        try {
            tcp::socket socket = door_.accept();
            asio::ssl::stream<tcp::socket&> stream(socket, context_);
            stream.handshake(asio::ssl::stream_base::server);
            shook_.store(true);
            std::unique_lock<std::mutex> lock(mutex_);
            letGo_.wait(lock, [this]() { return released_; });
        } catch (const std::exception& error) {
            std::fprintf(stderr, "the stalled peer ended: %s\n", error.what());
        }
    }

    asio::io_context io_;
    tcp::acceptor door_;
    asio::ssl::context context_;
    std::mutex mutex_;
    std::condition_variable letGo_;
    bool released_ = false;
    std::atomic<bool> shook_{false};
    std::thread holder_;
};

}  // namespace

int main()
try {
    const testutil::ScratchDir scratch("gateway-stalled-peer-test");
    const std::filesystem::path& root = scratch.path();
    std::filesystem::create_directories(root);
    const tls::Credential served = tls::selfSigned(root / "stalled");
    StalledPeer stalled(served);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";
    settings.direct = {DirectRoute{kStalledDest, "127.0.0.1", stalled.port(), served.pin}};

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));
    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    i2p::Router alice(borrowedFrom(port, gateway.fingerprint()));
    i2p::Router bob(borrowedFrom(port, gateway.fingerprint()));
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

    const std::unique_ptr<i2p::Stream> slow
        = his->connect(kStalledDest, std::chrono::seconds(kWaitSeconds));
    CHECK(slow != nullptr);
    CHECK(testutil::waitFor([&]() { return stalled.shookHands(); }));
    const std::unique_ptr<i2p::Stream> quick
        = his->connect(hers->routingHost(), std::chrono::seconds(kWaitSeconds));
    CHECK(quick != nullptr);
    std::string caller;
    const std::unique_ptr<i2p::Stream> taken
        = hers->accept(caller, std::chrono::seconds(kWaitSeconds));
    CHECK(taken != nullptr);

    std::thread flooding([&]() {
        const std::vector<unsigned char> chunk(kFloodChunk, 'f');
        try {
            for (std::size_t sent = 0; sent < kFloodBytes; sent += chunk.size()) {
                slow->writeAll(chunk);
            }
        } catch (const std::exception&) {
        }
    });
    std::this_thread::sleep_for(kFloodHeadStart);

    const std::string ping = "past the stalled stream";
    quick->writeAll(viewOf(ping));
    taken->setReadTimeout(kOtherStreamWithin);
    std::string heard;
    std::string buffer(ping.size(), '\0');
    try {
        while (heard.size() < ping.size()) {
            const std::size_t got = taken->readSome(bufferOf(buffer));
            if (got == 0) {
                break;
            }
            heard.append(buffer, 0, got);
        }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "the other stream read nothing: %s\n", error.what());
    }
    CHECK(heard == ping);

    slow->close();
    quick->close();
    taken->close();
    his->stop();
    hers->stop();
    bob.stop();
    alice.stop();
    gateway.stop();
    flooding.join();
    std::printf("TestStalledPeer ok\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
