// Bazarish project (c) 2026
#include "I2pFront.hpp"

#include <bazarish/Bytes.hpp>
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
#include <fstream>
#include <iterator>
#include <system_error>
#include <utility>

namespace bazarish::facade {

namespace {

// How long an accept waits before looping to re-check the stop flag.
constexpr int kAcceptTimeoutSeconds = 30;
// Pump buffer. Requests are small; a response may be a large streamed body.
constexpr std::size_t kPumpBufferBytes = 32 * 1024;
// How long to wait for a destination's leaseset to publish before saying so.
constexpr int kReadyWaitSeconds = 300;
// How long a finished reply may wait for the client to read it before the stream
// is torn down anyway, and how often that is checked.
constexpr int kDrainMillis = 60000;
constexpr int kDrainPollMillis = 50;

std::string readFileText(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void writePrivateFile(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    out.close();
    if (!out) {
        // This is the destination's private key: a half-written one costs the
        // address on the next start, so it is a hard failure, not a warning.
        throw std::runtime_error("cannot write " + path.string());
    }
    std::error_code ec;
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
    if (ec) {
        // Refusing to run is better than serving from a key file others can read.
        throw std::runtime_error(
            "cannot restrict permissions on " + path.string() + ": " + ec.message());
    }
}

// A connected socket to the facade's own listener, or -1.
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

// Pumps one accepted stream against the local listener until either side ends.
// The response direction runs here and the request direction on a helper thread,
// so a streamed response is relayed as it arrives rather than after the request.
// How many relays this facade carries at once. Each is one thread and one
// socket to the local listener; the ceiling is what keeps a burst of clients
// from becoming a burst of threads.
constexpr std::size_t kMaxRelaysInFlight = 256;

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
        // The client is done asking: tell the listener so it can answer and close.
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
            if (toClient == 0) {
                // The first bytes back are the status line: log them so a framing
                // complaint from the client can be checked against what was sent.
                const std::size_t head = std::min<std::size_t>(static_cast<std::size_t>(n), 48);
                std::string preview(buffer.data(), head);
                for (char& c : preview) {
                    if (c == '\r' || c == '\n') { c = '|'; }
                }
                bazarish::log::debug("i2p relay: first reply bytes: {}", preview);
            }
            stream->writeAll(buffer.data(), static_cast<std::size_t>(n));
            toClient += static_cast<std::size_t>(n);
        } catch (const std::exception& error) {
            bazarish::log::debug("i2p relay: write to client failed: {}", error.what());
            break;
        }
    }
    // The backend is done, but the reply may still be queued in the stream. Give
    // the client its chance to read it: wait until it closes its side (which it
    // does right after reading a Connection: close reply), and only then tear the
    // stream down. Closing straight after the last write truncates the reply -
    // the client then sees an empty stream and calls the response malformed.
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

I2pFront::I2pFront(Options options)
    : options_(std::move(options))
{
}

I2pFront::~I2pFront()
{
    stop();
}

std::vector<std::string> I2pFront::start()
{
    std::error_code ec;
    std::filesystem::create_directories(options_.stateDir, ec);
    router_ = std::make_unique<bazarish::i2p::Router>(
        bazarish::i2p::RouterConfig{options_.stateDir / "i2p", bazarish::i2p::Role::eServer});

    std::vector<std::string> hosts;
    for (std::size_t i = 0; i < options_.destinations; ++i) {
        const std::filesystem::path keyPath
            = options_.stateDir / ("facade-dest-" + std::to_string(i) + ".key");
        const std::string raw = std::filesystem::exists(keyPath) ? readFileText(keyPath) : "";
        const bazarish::i2p::Keys keys = raw.empty()
            ? bazarish::i2p::Keys::generate()
            : bazarish::i2p::Keys::fromBlob(bazarish::Bytes(raw.begin(), raw.end()));
        // Encrypted LeaseSet2: the address clients dial is the blinded b33.
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint
            = router_->createEndpoint(bazarish::i2p::EndpointConfig{keys,
                bazarish::i2p::LeaseSetKind::eEncrypted, options_.privacy,
                options_.tunnelQuantity, true});
        if (raw.empty()) {
            const bazarish::Bytes blob = endpoint->privateBlob();
            writePrivateFile(keyPath, std::string(blob.begin(), blob.end()));
        }
        hosts.push_back(endpoint->routingHost());
        // Publishing the leaseset takes a while after the address is known, and
        // until it does a client's dial simply fails. Say when each one is
        // actually reachable rather than leaving the log claiming it is up.
        const std::string host = endpoint->routingHost();
        std::thread([endpoint, host]() {
            if (endpoint->waitReady(std::chrono::seconds(kReadyWaitSeconds))) {
                bazarish::log::info("i2p facade ready: {}", host);
            } else {
                bazarish::log::warn("i2p facade not ready after {}s: {}", kReadyWaitSeconds, host);
            }
        }).detach();
        endpoints_.push_back(std::move(endpoint));
    }

    running_ = true;
    for (const std::shared_ptr<bazarish::i2p::Endpoint>& endpoint : endpoints_) {
        acceptThreads_.emplace_back([this, endpoint]() { acceptLoop(endpoint); });
    }
    return hosts;
}

void I2pFront::stop()
{
    running_ = false;
    for (std::thread& thread : acceptThreads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    acceptThreads_.clear();
    endpoints_.clear();
    router_.reset();
}

void I2pFront::acceptLoop(const std::shared_ptr<bazarish::i2p::Endpoint>& endpoint)
{
    while (running_) {
        std::string peer;
        std::unique_ptr<bazarish::i2p::Stream> stream;
        try {
            stream = endpoint->accept(peer, std::chrono::seconds(kAcceptTimeoutSeconds));
        } catch (const std::exception& error) {
            bazarish::log::warn("i2p accept failed: {}", error.what());
            continue;
        }
        if (!stream) {
            continue;  // accept timeout: re-check the stop flag
        }
        const int fd = connectLocal(options_.localHost, options_.localPort);
        if (fd < 0) {
            bazarish::log::warn("i2p front: own listener {}:{} refused the relay",
                options_.localHost, options_.localPort);
            continue;
        }
        // Detached: one slow client must not hold up the accept loop. The
        // caller's destination is deliberately not logged - the facade logs
        // nothing that identifies a client.
        //
        // Bounded, though: a relay is a thread held for the life of a client's
        // connection, and without a ceiling a burst of them is a burst of
        // threads. Past it the stream is closed rather than queued - a client
        // retries, a facade that cannot make a thread does not.
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
