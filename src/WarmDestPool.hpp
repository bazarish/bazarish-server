// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace bazarish::server {

// A pool of pre-built, SINGLE-USE transient outbound I2P destinations kept warm
// (their tunnels already built) so an operation that wants a one-time dest - a
// contact-add card fetch / federated resolve - grabs a ready one instead of paying
// the cold tunnel-build latency (seconds). Each acquired dest is used exactly once
// and then dropped, never reused: two one-time lookups are therefore never linkable
// to the same destination (the anonymity invariant the one-time dest exists for).
//
// The pool is best-effort: a slow or failing build (e.g. a firewalled router that
// cannot build tunnels) backs off and never blocks acquire(), which simply returns
// nullptr so the caller falls back to its standing endpoint. The target size adapts
// between minSize (idle) and maxSize (busy) from observed demand.
class WarmDestPool {
public:
    struct Options {
        std::size_t minSize = 2;
        std::size_t maxSize = 10;
        bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
        int tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity;
        // How long a freshly created dest is given to warm before it is abandoned.
        std::chrono::seconds buildTimeout{120};
        // Idle gap after which the target size decays one step toward minSize.
        std::chrono::seconds idleDecay{45};
    };

    WarmDestPool(bazarish::i2p::Router& router, Options options);
    ~WarmDestPool();

    void start();
    void stop();

    // A warm, single-use endpoint, or nullptr when none is ready (the caller then
    // dials from its standing endpoint). Records demand so the pool grows under load
    // and wakes the warmer to refill. The returned endpoint must be used once and
    // dropped - never returned to the pool.
    std::shared_ptr<bazarish::i2p::Endpoint> acquire();

    struct Stats {
        std::size_t ready = 0;
        std::size_t building = 0;
        std::size_t target = 0;
        std::uint64_t hits = 0;
        std::uint64_t misses = 0;
    };
    Stats stats() const;

private:
    void warmerLoop();
    // A destination still warming (its tunnels building), with the time it started so
    // a never-ready build can be abandoned.
    struct Building {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        std::chrono::steady_clock::time_point startedAt;
    };

    bazarish::i2p::Router& router_;
    const Options options_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::shared_ptr<bazarish::i2p::Endpoint>> ready_;  // warm, unused
    std::size_t target_;
    std::chrono::steady_clock::time_point lastAcquire_;
    bool sawMiss_ = false;  // an acquire found the pool empty since the last tick
    std::uint64_t hits_ = 0;
    std::uint64_t misses_ = 0;
    std::atomic<bool> running_{false};
    std::thread warmer_;
};

}  // namespace bazarish::server
