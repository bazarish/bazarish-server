// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "Federation.hpp"
#include "HttpApi.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>

#include <atomic>
#include <string>
#include <thread>

namespace bazarish::server {

class FederationRateLimiter;
class WarmDestPool;

// Sends a signed delivered-ack for messageId to the sending server at toDest,
// dialled FROM the given serving endpoint (the one that received the delivery) -
// never a shared address. The ack is signed with that destination's own
// per-destination signing key (bound to the destination, never the server root
// identity), so two users one server hosts on different destinations share no
// signer. Wired once and shared by every serving accept loop, which each pass
// their own destination's key.
using AckSenderFn = std::function<void(bazarish::i2p::Endpoint& from, const std::string& toDest,
    const std::string& messageId, const Key& signingKey)>;

// Relays a sealed envelope to toDest dialled from the given serving endpoint
// (the sender's own destination). The recipient acks back to from's address.
// onPhase (when set) is called with the live phase ("dialing", "connected",
// "sending", "awaiting-ack") so the caller can surface real delivery progress.
RemoteDeliveryResult federationDeliver(bazarish::i2p::Endpoint& from, const std::string& toDest,
    const Bytes& sealed, const Bytes& payload, const FederationPhaseFn& onPhase = {});

// Sends an already-signed delivered-ack from the given serving endpoint to toDest
// (one-way: write the line, drain until the receiver closes, so it flushes).
void federationSendAck(bazarish::i2p::Endpoint& from, const std::string& toDest,
    const std::string& messageId, const Bytes& signerPublicDer, const Bytes& signature);

// The I2P federation node: an inbound accept loop that serves incoming
// deliveries into the local DeliveryEngine, plus an outbound relay used as the
// HttpApi RemoteDeliverFn. Routing is by destination - the outbound relay dials
// the recipient's I2P destination directly (see docs-main api/InviteAnonymity.md).
class I2pFederation {
public:
    I2pFederation(bazarish::i2p::Endpoint& endpoint, DeliveryEngine& engine,
        FederationRateLimiter* limiter = nullptr);
    ~I2pFederation();

    I2pFederation(const I2pFederation&) = delete;
    I2pFederation& operator=(const I2pFederation&) = delete;

    // Starts the inbound accept loop on a background thread.
    void start();
    // Signals the loop to stop. A blocking accept only returns on the next
    // inbound connection or the accept timeout, so shutdown is not
    // instantaneous - acceptable for a long-running daemon.
    void stop();

    // Wires the contact-card lookup served on the inbound (home) accept loop for
    // op "card" - the only thing the home dest serves. Set before start(). Unset
    // means CARD_UNKNOWN.
    void setGetCard(GetCardFn getCard);

    // Wires a pool of warm single-use transient destinations to dial outbound
    // fetches FROM (instead of the home dest), so a card/resolve lookup is both
    // anonymous (a fresh one-time dest per lookup, never reused) and fast (the
    // tunnels are pre-built). Optional: when unset, or when the pool is momentarily
    // empty, fetches fall back to the home endpoint. Set before use.
    void setWarmPool(WarmDestPool* pool);

    // Relays a sealed fetch (op "card" or "resolve") to a destination over I2P;
    // the HttpApi RemoteFetchFn (the proxy fallback for a client with no I2P transport).
    RemoteFetchResult fetchOverI2p(
        const std::string& toDest, const std::string& op, const Bytes& sealed);
    RemoteFetchFn asRemoteFetchFn();

private:
    void acceptLoop();

    bazarish::i2p::Endpoint& endpoint_;
    DeliveryEngine& engine_;
    FederationRateLimiter* limiter_;
    GetCardFn getCard_;
    WarmDestPool* warmPool_ = nullptr;
    std::atomic<bool> running_;
    std::thread acceptThread_;
};

}  // namespace bazarish::server
