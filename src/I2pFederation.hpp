// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "Federation.hpp"
#include "HttpApi.hpp"

#include <bazarish/Sam.hpp>

#include <atomic>
#include <string>
#include <thread>

namespace bazarish::server {

class FederationRateLimiter;

// The I2P federation node: an inbound accept loop that serves incoming
// deliveries into the local DeliveryEngine, plus an outbound relay used as the
// HttpApi RemoteDeliverFn. Routing is by destination — the outbound relay dials
// the recipient's I2P destination directly (see docs-main api/InviteAnonymity.md).
class I2pFederation {
public:
    I2pFederation(
        SamSession& session, DeliveryEngine& engine, FederationRateLimiter* limiter = nullptr);
    ~I2pFederation();

    I2pFederation(const I2pFederation&) = delete;
    I2pFederation& operator=(const I2pFederation&) = delete;

    // Starts the inbound accept loop on a background thread.
    void start();
    // Signals the loop to stop. A blocking accept only returns on the next
    // inbound connection or the SAM socket timeout, so shutdown is not
    // instantaneous — acceptable for a long-running daemon.
    void stop();

    // Relays a sealed envelope to the recipient's I2P destination toDest; the
    // HttpApi RemoteDeliverFn.
    RemoteDeliveryResult deliver(
        const std::string& toDest, const Bytes& sealed, const Bytes& payload);
    RemoteDeliverFn asRemoteDeliverFn();

    // Wires the contact-card lookup served on the inbound (home) accept loop for
    // op "card". Set before start(). Unset means CARD_UNKNOWN.
    void setGetCard(GetCardFn getCard);

    // Relays a sealed fetch (op "card" or "resolve") to a destination over I2P;
    // the HttpApi RemoteFetchFn (the proxy fallback for a no-SAM client).
    RemoteFetchResult fetchOverI2p(
        const std::string& toDest, const std::string& op, const Bytes& sealed);
    RemoteFetchFn asRemoteFetchFn();

private:
    void acceptLoop();

    SamSession& session_;
    DeliveryEngine& engine_;
    FederationRateLimiter* limiter_;
    GetCardFn getCard_;
    std::atomic<bool> running_;
    std::thread acceptThread_;
};

}  // namespace bazarish::server
