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

// Signs a delivered confirmation for the reply that is already open, with the
// signing key of the destination that received the delivery - bound to that
// destination, never the server root identity, so two users one server hosts on
// different destinations share no signer.

// Relays a sealed envelope to toDest, dialled from the given endpoint - a warm
// one-time destination leased for this sender and this recipient (see
// OutboundLeases), never the sender's own address. The recipient's signed
// confirmation comes back on the same stream, since nothing can dial a one-time
// destination back.
// onPhase (when set) is called with the live phase ("dialing", "connected",
// "sending", "awaiting-ack") so the caller can surface real delivery progress.
RemoteDeliveryResult federationDeliver(bazarish::i2p::Endpoint& from, const std::string& toDest,
    const Bytes& sealed, const Bytes& payload, const FederationPhaseFn& onPhase = {});

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
