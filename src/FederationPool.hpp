// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "Federation.hpp"
#include "I2pFederation.hpp"  // AckSenderFn

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {

class FederationRateLimiter;

// Deterministic, restart- and platform-stable index of the pool destination
// assigned to a user fingerprint. Returns 0 when poolSize is 0.
std::size_t poolIndexFor(const std::string& userFp, std::size_t poolSize);

// A free-tier address pool: N server-owned federation destinations, each a
// persisted encrypted LeaseSet2 (b33) I2P destination with its own inbound accept
// loop feeding the shared DeliveryEngine. Free users are spread deterministically
// across the pool (k-anonymity: a floodfill that sees a pool destination cannot
// tell which of the users behind it a message is for). Keys persist so a pool
// destination keeps its address across restarts. Building the sessions blocks
// while their tunnels build, exactly like the home federation destination.
class FederationPool {
public:
    FederationPool(bazarish::i2p::Router& router, DeliveryEngine& engine,
        std::filesystem::path stateDir, bazarish::i2p::Privacy privacy, std::size_t size,
        int tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity,
        FederationRateLimiter* limiter = nullptr);
    ~FederationPool();

    FederationPool(const FederationPool&) = delete;
    FederationPool& operator=(const FederationPool&) = delete;

    // Brings up every pool destination (reusing persisted keys) and starts their
    // accept loops. Blocks while the tunnels build.
    void start();
    void stop();

    // Wires the contact-card lookup served for op "card" on every pool
    // destination's accept loop. Set before start(). Unset means CARD_UNKNOWN.
    void setGetCard(GetCardFn getCard);
    // Wires the delivered-ack sender (used when a delivery is served on a pool
    // destination) and the ack receiver (when a delivered-ack lands on a pool dest
    // we sent from). Set before start().
    void setAckSender(AckSenderFn ackSender);
    void setOnAck(OnAckFn onAck);

    // The shareable destination of the pool entry assigned to a user.
    // Deterministic by fingerprint, so a user keeps the same pool destination
    // across restarts. Empty when the pool is empty.
    std::string destinationFor(const std::string& userFp) const;
    // The serving sealing key of the pool entry assigned to a user - the key a
    // contact seals the delivery envelope to, whose private half this server
    // holds (so it both surfaces the public half and unseals same-destination
    // local deliveries). Shared by the free users on that pool destination (same
    // k-anonymity set as the destination). Null when the pool is empty.
    std::shared_ptr<Key> servingKeyFor(const std::string& userFp) const;
    // Every pool destination (for the server card / diagnostics).
    const std::vector<std::string>& destinations() const;
    // The serving endpoint backing a pool destination (by routingHost), or null -
    // so outbound federation can dial from the sender's own pool dest.
    std::shared_ptr<bazarish::i2p::Endpoint> endpointForDest(const std::string& dest) const;

private:
    struct Dest {
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        // The pool destination's own serving sealing key: the accept loop
        // unseals delivery envelopes addressed to it with this key.
        std::shared_ptr<Key> sealingKey;
        std::atomic<bool> running{true};
        std::thread acceptThread;
    };

    bazarish::i2p::Router& router_;
    DeliveryEngine& engine_;
    const std::filesystem::path stateDir_;
    const bazarish::i2p::Privacy privacy_;
    const std::size_t size_;
    const int tunnelQuantity_;
    FederationRateLimiter* const limiter_;
    GetCardFn getCard_;
    AckSenderFn ackSender_;
    OnAckFn onAck_;
    std::vector<std::unique_ptr<Dest>> dests_;
    std::vector<std::string> destinations_;
    // Parallel to destinations_: the serving sealing key of each pool entry, for
    // surfacing (public half) and same-destination local delivery (private half).
    std::vector<std::shared_ptr<Key>> servingKeys_;
};

}  // namespace bazarish::server
