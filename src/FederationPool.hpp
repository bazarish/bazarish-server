// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"

#include <bazarish/Sam.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {

// Deterministic, restart- and platform-stable index of the pool destination
// assigned to a user fingerprint. Returns 0 when poolSize is 0.
std::size_t poolIndexFor(const std::string& userFp, std::size_t poolSize);

// A free-tier address pool: N server-owned federation destinations, each a
// persisted encrypted LeaseSet2 (b33) SAM session with its own inbound accept
// loop feeding the shared DeliveryEngine. Free users are spread deterministically
// across the pool (k-anonymity: a floodfill that sees a pool destination cannot
// tell which of the users behind it a message is for). Keys persist so a pool
// destination keeps its address across restarts. Building the sessions blocks
// while their tunnels build, exactly like the home federation destination.
class FederationPool {
public:
    FederationPool(std::string samHost, std::uint16_t samPort, DeliveryEngine& engine,
        std::filesystem::path stateDir, std::string sessionIdPrefix, I2pPrivacy privacy,
        std::size_t size);
    ~FederationPool();

    FederationPool(const FederationPool&) = delete;
    FederationPool& operator=(const FederationPool&) = delete;

    // Brings up every pool destination (reusing persisted keys) and starts their
    // accept loops. Blocks while the tunnels build.
    void start();
    void stop();

    // The shareable destination of the pool entry assigned to a user.
    // Deterministic by fingerprint, so a user keeps the same pool destination
    // across restarts. Empty when the pool is empty.
    std::string destinationFor(const std::string& userFp) const;
    // Every pool destination (for the server card / diagnostics).
    const std::vector<std::string>& destinations() const;

private:
    struct Dest {
        std::unique_ptr<SamSession> session;
        std::atomic<bool> running{true};
        std::thread acceptThread;
    };

    const std::string samHost_;
    const std::uint16_t samPort_;
    DeliveryEngine& engine_;
    const std::filesystem::path stateDir_;
    const std::string sessionIdPrefix_;
    const I2pPrivacy privacy_;
    const std::size_t size_;
    std::vector<std::unique_ptr<Dest>> dests_;
    std::vector<std::string> destinations_;
};

}  // namespace bazarish::server
