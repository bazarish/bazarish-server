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

// Sends a signed delivered-ack for deliveryId to the sending server at toDest,
// dialled FROM the given serving endpoint (the one that received the delivery) -
// never a shared address. The ack is signed with that destination's own
// per-destination signing key (bound to the destination, never the server root
// identity), so two users one server hosts on different destinations share no
// signer. Wired once and shared by every serving accept loop, which each pass
// their own destination's key.
using AckSenderFn = std::function<void(bazarish::i2p::Endpoint& from, const std::string& toDest,
    const std::string& deliveryId, const Key& signingKey)>;

// Relays a sealed envelope to toDest dialled from the given serving endpoint
// (the sender's own destination). The recipient acks back to from's address.
// onPhase (when set) is called with the live phase ("dialing", "connected",
// "sending", "awaiting-ack") so the caller can surface real delivery progress.
RemoteDeliveryResult federationDeliver(bazarish::i2p::Endpoint& from, const std::string& toDest,
    const Bytes& sealed, const Bytes& payload, const FederationPhaseFn& onPhase = {});

// Sends an already-signed delivered-ack from the given serving endpoint to toDest
// (one-way: write the line, drain until the receiver closes, so it flushes).
void federationSendAck(bazarish::i2p::Endpoint& from, const std::string& toDest,
    const std::string& deliveryId, const Bytes& signerPublicDer, const Bytes& signature);

// Outbound discovery over I2P. A server has no federation address of its own -
// user-to-user delivery runs on the users' own destinations, and its only public
// I2P addresses are the facade's, for clients. So a card/resolve lookup dials
// from a warm SINGLE-USE transient destination: fresh per lookup, never reused,
// dropped right after, and unattributable to the server or to any of its users.
class I2pFetch {
public:
    // The pool is optional: without one (or when it is momentarily empty) a
    // one-time destination is built on demand, which only costs the cold tunnel
    // build the pool exists to hide.
    I2pFetch(bazarish::i2p::Router& router, WarmDestPool* pool = nullptr);

    I2pFetch(const I2pFetch&) = delete;
    I2pFetch& operator=(const I2pFetch&) = delete;

    // Relays a sealed fetch (op "card" or "resolve") to a destination over I2P;
    // the HttpApi RemoteFetchFn (the proxy fallback for a client with no I2P
    // transport of its own).
    RemoteFetchResult fetchOverI2p(
        const std::string& toDest, const std::string& op, const Bytes& sealed);
    RemoteFetchFn asRemoteFetchFn();

private:
    bazarish::i2p::Router& router_;
    WarmDestPool* warmPool_;
};

}  // namespace bazarish::server
