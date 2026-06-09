// Bazarish project (c) 2026
#include "TcpFederation.hpp"

#include "Federation.hpp"

#include <bazarish/Sam.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <stdexcept>

namespace bazarish::server {

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

// Splits "host:port" on the last colon.
bool parseHostPort(const std::string& endpoint, std::string& host, int& port)
{
    const std::string::size_type colon = endpoint.rfind(':');
    if (colon == std::string::npos) {
        return false;
    }
    host = endpoint.substr(0, colon);
    port = std::atoi(endpoint.substr(colon + 1).c_str());
    return port > 0;
}

int connectTo(const std::string& host, const int port)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0
        || ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

TcpFederation::TcpFederation(DeliveryEngine& engine, Resolver resolve)
    : engine_(engine)
    , resolve_(std::move(resolve))
    , running_(false)
    , listenFd_(-1)
{
}

TcpFederation::~TcpFederation()
{
    stop();
    if (listenFd_ >= 0) {
        ::close(listenFd_);
        listenFd_ = -1;
    }
}

int TcpFederation::bindAndListen(const std::string& host, const int port)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    const int yes = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0
        || ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0
        || ::listen(fd, 16) < 0) {
        ::close(fd);
        return -1;
    }
    listenFd_ = fd;

    sockaddr_in bound;
    std::memset(&bound, 0, sizeof(bound));
    socklen_t length = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &length) < 0) {
        return -1;
    }
    return ntohs(bound.sin_port);
}

void TcpFederation::start()
{
    running_ = true;
    acceptThread_ = std::thread([this]() { acceptLoop(); });
}

void TcpFederation::acceptLoop()
{
    while (running_) {
        const int conn = ::accept(listenFd_, nullptr, nullptr);
        if (conn < 0) {
            if (!running_) {
                break;
            }
            continue;
        }
        try {
            // SamStream takes ownership of the connection fd.
            SamStream stream(conn);
            federationServeOnce(stream, engine_, nowSeconds());
        } catch (const std::exception&) {
            // Any framing or delivery error just drops this connection; an
            // unreachable peer is the caller's concern, not ours.
        }
    }
}

void TcpFederation::stop()
{
    if (!running_.exchange(false)) {
        return;
    }
    // Waking the blocking accept(): shut the socket down so it returns.
    if (listenFd_ >= 0) {
        ::shutdown(listenFd_, SHUT_RDWR);
    }
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }
    if (listenFd_ >= 0) {
        ::close(listenFd_);
        listenFd_ = -1;
    }
}

RemoteDeliveryResult TcpFederation::deliver(
    const std::string& toServer, const Bytes& sealed, const Bytes& payload)
{
    RemoteDeliveryResult result;
    const std::optional<std::string> endpoint = resolve_(toServer);
    if (!endpoint.has_value()) {
        return result;  // reachable stays false: no route to this server
    }
    std::string host;
    int port = 0;
    if (!parseHostPort(endpoint.value(), host, port)) {
        return result;
    }
    const int fd = connectTo(host, port);
    if (fd < 0) {
        return result;
    }
    try {
        SamStream stream(fd);
        const FederationDeliverResult remote
            = federationSendDeliver(stream, sealed, payload);
        result.reachable = true;
        result.delivered = remote.delivered;
        result.errorCode = remote.errorCode;
        result.errorMessage = remote.errorMessage;
    } catch (const std::exception&) {
        // Connected but the exchange broke: treat as unreachable so the
        // sender retries (no outbound state is kept).
        result.reachable = false;
    }
    return result;
}

RemoteDeliverFn TcpFederation::asRemoteDeliverFn()
{
    return [this](const std::string& toServer, const Bytes& sealed, const Bytes& payload) {
        return deliver(toServer, sealed, payload);
    };
}

}  // namespace bazarish::server
