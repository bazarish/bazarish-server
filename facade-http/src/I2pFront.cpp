// Bazarish project (c) 2026
#include "I2pFront.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Log.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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
    std::error_code ec;
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
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
void relay(std::unique_ptr<bazarish::i2p::Stream> stream, const int fd)
{
    std::thread inbound([&stream, fd]() {
        std::array<char, kPumpBufferBytes> buffer{};
        while (true) {
            const std::size_t read = stream->readSome(buffer.data(), buffer.size());
            if (read == 0) {
                break;
            }
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
        } catch (const std::exception&) {
            break;  // peer gone
        }
    }
    stream->close();
    ::shutdown(fd, SHUT_RD);
    inbound.join();
    ::close(fd);
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
        std::thread(relay, std::move(stream), fd).detach();
    }
}

}  // namespace bazarish::facade
