// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "HttpApi.hpp"

#include <bazarish/Sam.hpp>

#include <atomic>
#include <functional>
#include <optional>
#include <string>
#include <thread>

namespace bazarish::server {

class FederationRateLimiter;

// The I2P federation node: an inbound accept loop that serves incoming
// deliveries into the local DeliveryEngine, plus an outbound relay used as
// the HttpApi RemoteDeliverFn. Server fingerprints are resolved to I2P
// destinations by the injected resolver (fed from verified server cards).
class I2pFederation {
public:
    using Resolver = std::function<std::optional<std::string>(const std::string& serverFp)>;

    I2pFederation(SamSession& session, DeliveryEngine& engine, Resolver resolve,
        FederationRateLimiter* limiter = nullptr);
    ~I2pFederation();

    I2pFederation(const I2pFederation&) = delete;
    I2pFederation& operator=(const I2pFederation&) = delete;

    // Starts the inbound accept loop on a background thread.
    void start();
    // Signals the loop to stop. A blocking accept only returns on the next
    // inbound connection or the SAM socket timeout, so shutdown is not
    // instantaneous — acceptable for a long-running daemon.
    void stop();

    // Relays a sealed envelope to toServer; the HttpApi RemoteDeliverFn.
    RemoteDeliveryResult deliver(
        const std::string& toServer, const Bytes& sealed, const Bytes& payload);
    RemoteDeliverFn asRemoteDeliverFn();

private:
    void acceptLoop();

    SamSession& session_;
    DeliveryEngine& engine_;
    Resolver resolve_;
    FederationRateLimiter* limiter_;
    std::atomic<bool> running_;
    std::thread acceptThread_;
};

}  // namespace bazarish::server
