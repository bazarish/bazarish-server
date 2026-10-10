// Bazarish project (c) 2026
#include "I2pFront.hpp"

#include <bazarish/Log.hpp>

#include <stdexcept>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <exception>
#include <iterator>
#include <utility>

namespace bazarish::facade {

namespace {

constexpr int kAcceptTimeoutSeconds = 30;
constexpr std::size_t kPumpBufferBytes = 32 * 1024;
constexpr int kReadyWaitSeconds = 300;
constexpr int kReadyPollSeconds = 1;
constexpr int kDrainMillis = 60000;
constexpr int kDrainPollMillis = 50;
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

void relay(std::unique_ptr<bazarish::i2p::Stream> stream, const int fd)
{
    std::size_t fromClient = 0;
    std::size_t toClient = 0;
    std::atomic<bool> clientClosed{false};
    std::thread inbound([&stream, fd, &fromClient, &clientClosed]() {
        std::array<char, kPumpBufferBytes> buffer{};
        while (true) {
            const std::size_t read = stream->readSome(buffer.data(), buffer.size());
            if (read == 0) {
                break;
            }
            fromClient += read;
            std::size_t written = 0;
            while (written < read) {
                const ssize_t n = ::write(fd, buffer.data() + written, read - written);
                if (n <= 0) {
                    ::shutdown(fd, SHUT_WR);
                    return;
                }
                written += static_cast<std::size_t>(n);
            }
        }
        clientClosed = true;
        ::shutdown(fd, SHUT_WR);
    });

    std::array<char, kPumpBufferBytes> buffer{};
    while (true) {
        const ssize_t n = ::read(fd, buffer.data(), buffer.size());
        if (n <= 0) {
            break;
        }
        try {
            stream->writeAll(buffer.data(), static_cast<std::size_t>(n));
            toClient += static_cast<std::size_t>(n);
        } catch (const std::exception& error) {
            bazarish::log::debug("i2p relay: write to client failed: {}", error.what());
            break;
        }
    }
    for (int waited = 0; !clientClosed && waited < kDrainMillis; waited += kDrainPollMillis) {
        std::this_thread::sleep_for(std::chrono::milliseconds(kDrainPollMillis));
    }
    stream->close();
    ::shutdown(fd, SHUT_RD);
    inbound.join();
    ::close(fd);
    bazarish::log::debug("i2p relay done: {} bytes in, {} bytes out", fromClient, toClient);
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
    endpoint_.reset();
    router_.reset();
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
        // Detached: one slow client must not hold up the accept loop.
        if (relays_.load() >= kMaxRelaysInFlight) {
            bazarish::log::warn("i2p front: {} relays already in flight; refusing one",
                kMaxRelaysInFlight);
            ::close(fd);
            stream->close();
            continue;
        }
        relays_.fetch_add(1);
        std::thread([this, held = std::move(stream), fd]() mutable {
            relay(std::move(held), fd);
            relays_.fetch_sub(1);
        }).detach();
    }
}

}  // namespace bazarish::facade
