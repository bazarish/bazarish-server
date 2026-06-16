// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::server {

// Rate-limits inbound federation by the connecting peer's I2P destination, so a
// single peer cannot flood a server (accountability is per-connecting-dest, not a
// root-chained signature). A fixed window per peer: at most maxPerWindow inbound
// deliveries per windowSeconds. Thread-safe — shared across every accept loop
// (home destination, address pool, per-user destinations).
class FederationRateLimiter {
public:
    FederationRateLimiter(std::size_t maxPerWindow, std::int64_t windowSeconds);

    // Records an inbound attempt from peerDest at now and returns whether it is
    // within the limit (false → the caller should drop without serving). An empty
    // peerDest (e.g. a non-I2P transport) is always allowed.
    bool allow(const std::string& peerDest, std::int64_t now);

private:
    struct Window {
        std::int64_t start = 0;
        std::size_t count = 0;
    };

    const std::size_t maxPerWindow_;
    const std::int64_t windowSeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, Window> windows_;
};

}  // namespace bazarish::server
