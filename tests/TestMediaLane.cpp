// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/5c3f9a12e8d7";
constexpr const char* kToken = "a-fifth-static-token";
constexpr int kWaitSeconds = 30;
// One datagram larger than a frame can carry, which is what an I2P raw datagram
// is allowed to be: the router takes up to 32 KiB.
constexpr std::size_t kOversizeBytes = 20000;
constexpr std::size_t kRelayBufferBytes = 16384;
constexpr int kBacklog = 16;

// A plain TCP relay in front of the gateway, so one connection can be cut the
// way a phone changing network cuts one, leaving the others alone.
class Relay {
public:
    explicit Relay(const int to)
        : to_(to)
    {
        listen_ = ::socket(AF_INET, SOCK_STREAM, 0);
        CHECK(listen_ >= 0);
        const int one = 1;
        const int reusable
            = ::setsockopt(listen_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = ::inet_addr("127.0.0.1");
        const int bound = ::bind(listen_, reinterpret_cast<sockaddr*>(&address), sizeof address);
        socklen_t length = sizeof address;
        const int named = ::getsockname(listen_, reinterpret_cast<sockaddr*>(&address), &length);
        const int listening = ::listen(listen_, kBacklog);
        CHECK(reusable == 0);
        CHECK(bound == 0);
        CHECK(named == 0);
        CHECK(listening == 0);
        port_ = ntohs(address.sin_port);
        accepter_ = std::thread([this]() { accepting(); });
    }

    ~Relay()
    {
        running_.store(false);
        ::shutdown(listen_, SHUT_RDWR);
        ::close(listen_);
        if (accepter_.joinable()) {
            accepter_.join();
        }
        cutAll();
        for (std::thread& pump : pumps_) {
            if (pump.joinable()) {
                pump.join();
            }
        }
    }

    Relay(const Relay&) = delete;
    Relay& operator=(const Relay&) = delete;

    int port() const { return port_; }

    // How many connections have been made through it, which is how a socket
    // taken again is told from one that never came back.
    std::size_t connections() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return pairs_.size();
    }

    // Cuts the nth connection this relay took, counting from zero.
    void cut(const std::size_t which)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        CHECK(which < pairs_.size());
        ::shutdown(pairs_[which].first, SHUT_RDWR);
        ::shutdown(pairs_[which].second, SHUT_RDWR);
    }

private:
    void cutAll()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [in, out] : pairs_) {
            ::shutdown(in, SHUT_RDWR);
            ::shutdown(out, SHUT_RDWR);
        }
    }

    void accepting()
    {
        while (running_.load()) {
            const int in = ::accept(listen_, nullptr, nullptr);
            if (in < 0) {
                return;
            }
            const int out = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = ::inet_addr("127.0.0.1");
            address.sin_port = htons(static_cast<std::uint16_t>(to_));
            if (out < 0
                || ::connect(out, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0) {
                ::close(in);
                ::close(out);
                continue;
            }
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                pairs_.emplace_back(in, out);
            }
            pumps_.emplace_back([in, out]() { pump(in, out); });
            pumps_.emplace_back([in, out]() { pump(out, in); });
        }
    }

    static void pump(const int from, const int to)
    {
        std::vector<char> buffer(kRelayBufferBytes);
        for (;;) {
            const ssize_t got = ::recv(from, buffer.data(), buffer.size(), 0);
            if (got <= 0) {
                ::shutdown(to, SHUT_RDWR);
                return;
            }
            ssize_t sent = 0;
            while (sent < got) {
                const ssize_t wrote = ::send(to, buffer.data() + sent,
                    static_cast<std::size_t>(got - sent), MSG_NOSIGNAL);
                if (wrote <= 0) {
                    ::shutdown(from, SHUT_RDWR);
                    return;
                }
                sent += wrote;
            }
        }
    }

    int to_;
    int listen_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread accepter_;
    std::vector<std::thread> pumps_;
    mutable std::mutex mutex_;
    std::vector<std::pair<int, int>> pairs_;
};

i2p::RouterConfig borrowedFrom(const int port)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayToken = kToken;
    config.gatewayTls = false;
    // The control socket stays put and the decoys stay away: what this test
    // watches is one lane dying, not the churn that has a test of its own.
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
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return done();
}

std::shared_ptr<i2p::Endpoint> mediaOn(i2p::Router& router)
{
    i2p::EndpointConfig config{router.generateKeys()};
    config.privacy = i2p::Privacy::eMinimal;
    config.published = true;
    config.realtime = true;
    config.label = "Call media";
    return router.createEndpoint(config);
}

// One datagram each way, which is what a call is made of.
bool mediaFlows(i2p::Endpoint& from, i2p::Endpoint& to)
{
    const std::string payload = "audio";
    from.sendRawDatagram(to.routingHost(), payload.data(), payload.size());
    const std::vector<std::uint8_t> got
        = to.receiveRawDatagram(std::chrono::milliseconds(3000));
    return got.size() == payload.size();
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-media-lane-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.token = kToken;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";

    // Two clients of one gateway meet inside it, so nothing here needs a router
    // that is on the network - and one kept off it is the plainest proof that
    // no datagram went over I2P.
    i2p::Router engine(i2p::offlineRouter(root / "i2p"));

    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    // Alice reaches the gateway through a relay that can be cut; Bob talks to
    // it straight.
    Relay relay(port);
    i2p::Router alice(borrowedFrom(relay.port()));
    i2p::Router bob(borrowedFrom(port));
    alice.start();
    bob.start();

    const std::shared_ptr<i2p::Endpoint> hers = mediaOn(alice);
    const std::shared_ptr<i2p::Endpoint> his = mediaOn(bob);
    // Two control sockets and a lane for each call, because media takes one at
    // creation.
    CHECK(waitFor([&]() { return gateway.sockets() == 4; }));
    CHECK(waitFor([&]() { return relay.connections() == 2; }));

    CHECK(mediaFlows(*his, *hers));
    CHECK(mediaFlows(*hers, *his));

    // A payload no frame can carry is dropped where it is written. The router
    // drops one it cannot carry and says nothing; a send that threw would take
    // the caller's thread with it, and one written onto the lane would take the
    // lane.
    const std::vector<std::uint8_t> oversize(kOversizeBytes, 'x');
    his->sendRawDatagram(hers->routingHost(), oversize.data(), oversize.size());
    CHECK(hers->receiveRawDatagram(std::chrono::milliseconds(500)).empty());
    CHECK(gateway.sockets() == 4);
    CHECK(mediaFlows(*his, *hers));

    // The lane dies the way a network blip kills it, leaving the control socket
    // and the session alone.
    relay.cut(1);

    // It is taken again, and the call is a call once more. Without this the
    // datagrams are dropped at both ends for the rest of the call, which is
    // silence nobody is told about. A connection where the cut one was is what
    // proves it: the count only ever grows, so watching for it cannot miss the
    // moment the way a socket count that dips and recovers can.
    CHECK(waitFor([&]() { return relay.connections() >= 3; }));
    CHECK(waitFor([&]() { return gateway.sockets() == 4; }));
    // The session is not what died: the destination is still hers.
    CHECK(alice.running());
    CHECK(!hers->lost());
    CHECK(mediaFlows(*his, *hers));
    CHECK(mediaFlows(*hers, *his));

    // Nothing was refused along the way. A test that passes while the gateway
    // turns frames away proves less than it looks.
    CHECK(gateway.refusals() == 0);

    // A borrowed router takes its destinations down with it. Turning I2P off is
    // not a request to leave your address published and reachable for the rest
    // of a session's term.
    bob.stop();
    CHECK(waitFor([&]() { return engine.localDestinations().size() == 1; }));

    // A daemon on its way out stops what its sessions hold, rather than leaving
    // threads running against the lock it is about to take away.
    gateway.stop();
    // Waited for, not read at once: the engine lets a destination go when the
    // last handler holding it has returned, which is a moment after the session
    // that held it was stopped.
    CHECK(waitFor([&]() { return engine.localDestinations().empty(); }));

    alice.stop();
    std::filesystem::remove_all(root);
    std::printf("TestMediaLane ok\n");
    return 0;
}
