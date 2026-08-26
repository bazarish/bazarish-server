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
