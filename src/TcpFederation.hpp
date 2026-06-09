// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "HttpApi.hpp"

#include <atomic>
#include <functional>
#include <optional>
#include <string>
#include <thread>

namespace bazarish::server {

// A federation transport over plain TCP, reusing the same wire framing as
// the I2P transport (the framing works over any byte stream). Intended for
// an operator-controlled private channel (localhost, a VPN) and for local
// multi-server testing — not a hidden network. Server fingerprints resolve
// to "host:port" via the injected resolver (fed from peers configuration).
class TcpFederation {
public:
    using Resolver = std::function<std::optional<std::string>(const std::string& serverFp)>;

    TcpFederation(DeliveryEngine& engine, Resolver resolve);
    ~TcpFederation();

    TcpFederation(const TcpFederation&) = delete;
    TcpFederation& operator=(const TcpFederation&) = delete;

    // Binds and listens; returns the bound port (useful when port is 0) or
    // -1 on failure.
    int bindAndListen(const std::string& host, int port);
    // Starts the inbound accept loop on a background thread.
    void start();
    // Stops the accept loop and closes the listening socket.
    void stop();

    // Relays a sealed envelope to toServer; the HttpApi RemoteDeliverFn.
    RemoteDeliveryResult deliver(
        const std::string& toServer, const Bytes& sealed, const Bytes& payload);
    RemoteDeliverFn asRemoteDeliverFn();

private:
    void acceptLoop();

    DeliveryEngine& engine_;
    Resolver resolve_;
    std::atomic<bool> running_;
    int listenFd_;
    std::thread acceptThread_;
};

}  // namespace bazarish::server
