// Bazarish project (c) 2026
#include "I2pFront.hpp"
#include "Relay.hpp"

#include <bazarish/Log.hpp>

#include <stdexcept>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <iterator>
#include <utility>

namespace bazarish::facade {

namespace {

constexpr int kAcceptTimeoutSeconds = 30;
constexpr int kReadyWaitSeconds = 300;
constexpr int kReadyPollSeconds = 1;
constexpr std::size_t kMaxRelaysInFlight = 256;

int connectLocal(const std::string& host, const int port)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1
        || ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

I2pFront::I2pFront(Options options, bazarish::i2p::Keys keys)
    : options_(std::move(options))
    , keys_(std::move(keys))
{
}

I2pFront::~I2pFront()
{
    stop();
}

void I2pFront::start()
{
    running_ = true;
    bazarish::i2p::RouterConfig routerConfig;
    routerConfig.dataDir = options_.stateDir / "i2p";
    routerConfig.role = bazarish::i2p::Role::eServer;
    router_ = std::make_unique<bazarish::i2p::Router>(routerConfig);

    endpoint_ = router_->createEndpoint(
        bazarish::i2p::EndpointConfig{keys_, options_.privacy, options_.tunnelQuantity, true});
    const std::string host = endpoint_->routingHost();
    readyThread_ = std::thread([this, host]() {
        for (int waited = 0; waited < kReadyWaitSeconds; waited += kReadyPollSeconds) {
            if (endpoint_->waitReady(std::chrono::seconds(kReadyPollSeconds))) {
                bazarish::log::info("i2p facade ready: {}", host);
                return;
            }
            if (!running_) {
                return;
            }
        }
        bazarish::log::warn("i2p facade not ready after {}s: {}", kReadyWaitSeconds, host);
    });
    acceptThread_ = std::thread([this]() { acceptLoop(); });
}

void I2pFront::stop()
{
    running_ = false;
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }
    if (readyThread_.joinable()) {
        readyThread_.join();
    }
    (void)reapRelays(true);
    endpoint_.reset();
    router_.reset();
}

std::size_t I2pFront::reapRelays(const bool all)
{
    std::list<Relay> done;
    std::size_t left = 0;
    {
        const std::lock_guard<std::mutex> lock(relaysMutex_);
        for (auto it = relays_.begin(); it != relays_.end();) {
            if (all || it->finished->load()) {
                done.splice(done.end(), relays_, it++);
            } else {
                ++it;
            }
        }
        left = relays_.size();
    }
    for (Relay& gone : done) {
        if (!gone.finished->load()) {
            gone.stream->close();
            (void)::shutdown(gone.fd, SHUT_RDWR);
        }
        gone.thread.join();
        if (::close(gone.fd) != 0) {
            bazarish::log::warn("i2p front: closing a relay's socket failed");
        }
    }
    return left;
}

void I2pFront::acceptLoop()
{
    while (running_) {
        std::string peer;
        std::unique_ptr<bazarish::i2p::Stream> stream;
        try {
            stream = endpoint_->accept(peer, std::chrono::seconds(kAcceptTimeoutSeconds));
        } catch (const std::exception& error) {
            bazarish::log::warn("i2p accept failed: {}", error.what());
            continue;
        }
        if (!stream) {
            continue;
        }
        const int fd = connectLocal(options_.localHost, options_.localPort);
        if (fd < 0) {
            bazarish::log::warn("i2p front: own listener {}:{} refused the relay",
                options_.localHost, options_.localPort);
            continue;
        }
        // A thread of its own: one slow client must not hold up the accept loop.
        if (reapRelays(false) >= kMaxRelaysInFlight) {
            bazarish::log::warn("i2p front: {} relays already in flight; refusing one",
                kMaxRelaysInFlight);
            ::close(fd);
            stream->close();
            continue;
        }
        const std::shared_ptr<bazarish::i2p::Stream> held = std::move(stream);
        const std::shared_ptr<std::atomic<bool>> finished
            = std::make_shared<std::atomic<bool>>(false);
        const std::lock_guard<std::mutex> lock(relaysMutex_);
        relays_.push_back(Relay{std::thread([held, fd, finished]() {
                                    relay(*held, fd);
                                    finished->store(true);
                                }),
            held, fd, finished});
    }
}

}  // namespace bazarish::facade
