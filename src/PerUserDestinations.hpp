// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Sam.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace bazarish::server {

class FederationRateLimiter;

// Operates per-user federation destinations for paid users that own their I2P
// key. The user delegates a time-boxed OFFLINE transient to the server, which
// brings the destination up over SAM as a STANDARD LeaseSet2 (an
// offline-signature destination cannot publish an encrypted LeaseSet2) with its
// own inbound accept loop feeding the shared DeliveryEngine. The destination's
// address equals the user's master b32, so it is stable as the user moves
// between serving servers. Building a session triggers I2P tunnel construction,
// so each destination runs on its own worker thread and provisioning never
// blocks the caller.
class PerUserDestinations {
public:
    PerUserDestinations(std::string samHost, std::uint16_t samPort,
        DeliveryEngine& engine, std::filesystem::path stateDir, I2pPrivacy privacy,
        FederationRateLimiter* limiter = nullptr);
    ~PerUserDestinations();

    PerUserDestinations(const PerUserDestinations&) = delete;
    PerUserDestinations& operator=(const PerUserDestinations&) = delete;

    // Brings up (or replaces) userFp's destination from an offline transient
    // (I2P-base64 PrivateKeys with an offline section), valid until expiresUnix.
    // Persists the transient so the destination survives a restart. A repeat
    // call with the same transient is a no-op; a different transient replaces
    // the running destination.
    void provision(const std::string& userFp, const std::string& transientB64,
        std::int64_t expiresUnix);

    // Tears down and forgets userFp's destination (grant lapsed or revoked).
    void revoke(const std::string& userFp);

    // Re-provisions every persisted, non-expired transient. Called once at
    // startup so paid destinations come back after a restart.
    void reloadPersisted(std::int64_t now);

    // Number of currently provisioned destinations (for tests / diagnostics).
    std::size_t size() const;

    // SubjectPublicKeyInfo DER of userFp's serving sealing key — the public key
    // a contact seals the delivery envelope to for this paid personal
    // destination. Stable across renewals. Empty when the user has none.
    Bytes servingKeyFor(const std::string& userFp) const;

private:
    struct Destination {
        std::atomic<bool> running{true};
        std::thread worker;
        std::string transientB64;
        std::int64_t expiresUnix = 0;
        // The destination's own serving sealing key (private half held here; its
        // public half is surfaced to the user). The accept loop unseals with it.
        std::unique_ptr<Key> sealingKey;
    };

    // Starts the worker that builds the SAM session and serves its accept loop.
    void bringUp(const std::string& userFp, const std::string& transientB64,
        std::int64_t expiresUnix, const std::string& sealingKeyPem);
    void teardownLocked(const std::string& userFp);
    std::filesystem::path pathFor(const std::string& userFp) const;
    std::filesystem::path destsDir() const;

    const std::string samHost_;
    const std::uint16_t samPort_;
    DeliveryEngine& engine_;
    const std::filesystem::path stateDir_;
    const I2pPrivacy privacy_;
    FederationRateLimiter* const limiter_;
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Destination>> dests_;
};

}  // namespace bazarish::server
