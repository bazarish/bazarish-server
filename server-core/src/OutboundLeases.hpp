// Bazarish project (c) 2026
#pragma once

#include "WarmDestPool.hpp"

#include <bazarish/I2p.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace bazarish::server {

// Which destination a user's outbound deliveries leave from.
//
// Delivering from the user's own serving destination hands the recipient's server
// a stable name for the sender: one address, every message, every recipient - a
// social graph readable by whoever operates the far end. Deliveries go out from a
// warm one-time destination instead, held for one term and then destroyed, so what
// the far end can group together is one term's worth of traffic and no more.
//
// One term, one destination, one CORRESPONDENT. Holding a destination per user
// would let a server that hosts several of A's contacts see one address writing
// into several of its mailboxes and read off who A talks to there; the pair is
// what keeps each conversation to its own address.
//
// A term rather than a destination per message: at a hundred users a fresh dest
// per message is a hundred tunnel builds a minute for no further gain - inside one
// term the same messages are grouped by timing anyway.
class OutboundLeases {
public:
    struct Options {
        // How long one destination serves one user. A tunnel's own lifetime: past it
        // the destination would be rebuilding its tunnels regardless.
        std::chrono::seconds term{600};
    };

    OutboundLeases(WarmDestPool& pool, Options options);
    ~OutboundLeases();

    void start();
    void stop();

    // The destination this user's deliveries to THIS recipient go out from now,
    // taking a fresh one when the last term is over. Nullptr when the pool has
    // nothing warm - the caller leaves the send in its spool rather than falling
    // back to the user's own address, which is the very thing this avoids.
    std::shared_ptr<bazarish::i2p::Endpoint> forPair(
        const std::string& user, const std::string& toDest);

    struct Stats {
        std::size_t live = 0;
    };
    Stats stats() const;

private:
    void sweeperLoop();
    // Drops every term that has run out. Called with the lock held.
    void dropExpired(std::chrono::steady_clock::time_point now);

    struct Lease {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        std::chrono::steady_clock::time_point expiresAt;
    };

    WarmDestPool& pool_;
    const Options options_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::map<std::string, Lease> leases_;
    std::atomic<bool> running_{false};
    std::thread sweeper_;
};

}  // namespace bazarish::server
