// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "Federation.hpp"
#include "I2pFederation.hpp"  // AckSenderFn

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <atomic>
#include <cstdint>
#include <condition_variable>
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
// brings the destination up over I2P as a STANDARD LeaseSet2 (an
// offline-signature destination cannot publish an encrypted LeaseSet2) with its
// own inbound accept loop feeding the shared DeliveryEngine. The destination's
// address equals the user's master b32, so it is stable as the user moves
// between serving servers. Building a session triggers I2P tunnel construction,
// so each destination runs on its own worker thread and provisioning never
// blocks the caller.
class PerUserDestinations {
public:
    // router may be null (provision/reload then only persist + register state;
    // no destination is built - used in tests and when running router-less).
    PerUserDestinations(bazarish::i2p::Router* router, DeliveryEngine& engine,
        std::filesystem::path stateDir, bazarish::i2p::Privacy privacy,
        int tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity,
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
    // startup so delegated destinations come back after a restart, and served
    // until the delegation they were handed with runs out.
    void reloadPersisted(std::int64_t now);

    // Takes down every destination whose delegation has run out and forgets it.
    // A transient is a term, not a gift: past its end the server has no leave to
    // operate the address, and an address left up is one the user believes is
    // theirs. Returns how many were taken down. Runs on its own from a sweeper
    // thread; exposed for the tests.
    std::size_t sweepExpired(std::int64_t now);

    // Wires the contact-card lookup served for op "card" on every per-user
    // destination's accept loop. Set before reloadPersisted/provision. Unset
    // means CARD_UNKNOWN.
    void setGetCard(GetCardFn getCard);
    // Wires the delivered-ack sender (deliveries served here) and receiver (acks
    // for sends originated here). Set before reloadPersisted/provision.
    void setAckSender(AckSenderFn ackSender);
    void setOnAck(OnAckFn onAck);
    // The serving endpoint for a provisioned dest (by routingHost), or null - so
    // the outbound federation path can dial from the sender's own dest.
    std::shared_ptr<bazarish::i2p::Endpoint> endpointForDest(const std::string& dest) const;

    // Number of currently provisioned destinations (for tests / diagnostics).
    std::size_t size() const;

    // userFp's serving sealing key - the key a contact seals the delivery
    // envelope to for this paid personal destination, whose private half this
    // server holds. Stable across renewals. Null when the user has none.
    std::shared_ptr<Key> servingKeyFor(const std::string& userFp) const;

    // Mints a replacement serving sealing key and holds it aside without putting
    // it into service: the key in use keeps serving until commitServingKey, so a
    // rotation that is never finished changes nothing. Returns the new key's
    // public half (base64 SPKI), which the user signs into a fresh contact card.
    std::string prepareServingKey(const std::string& userFp);
    // Puts the prepared key into service and forgets the old one, from which
    // moment an envelope sealed to the old key is refused. False when there is
    // nothing prepared (a commit for a rotation that was never started).
    bool commitServingKey(const std::string& userFp);

    // userFp's personal destination address (the master b32), learned once the
    // destination publishes. Empty when the user has none or it is not up yet.
    std::string destinationFor(const std::string& userFp) const;

    // userFp's personal-destination state, for the status the client polls:
    //   ""          - no personal destination,
    //   "building"  - provisioned, the destination has not published yet (so the
    //                 client must not yet hand out the personal address),
    //   "active"    - published and within the transient's validity,
    //   "expired"   - the offline transient lapsed: the personal destination is
    //                 offline (the user does not fall back to the pool while the
    //                 option is on; they re-issue a transient or top up).
    std::string stateFor(const std::string& userFp, std::int64_t now) const;

private:
    struct Destination {
        std::atomic<bool> running{true};
        std::thread worker;
        std::string transientB64;
        std::int64_t expiresUnix = 0;
        // The destination's own serving sealing key (private half held here; its
        // public half is surfaced to the user). The accept loop unseals with it.
        std::shared_ptr<Key> sealingKey;
        // A replacement minted but not yet in service: the user has to sign it
        // into a card first, and until they do the key above keeps serving.
        std::shared_ptr<Key> pendingSealingKey;
        // The destination's own federation signing key (per-user): it signs the
        // delivered-acks this destination sends, so the signer is bound to the
        // destination, never the server root identity. Stable across renewals.
        std::shared_ptr<Key> signingKey;
        // The published destination address (master b32); set once the
        // destination builds. Guarded by mutex_.
        std::string dest;
        // The serving endpoint, so outbound federation can dial from it. Set once
        // the destination builds. Guarded by mutex_.
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
    };

    // Starts the worker that builds the I2P destination and serves its accept loop.
    void bringUp(const std::string& userFp, const std::string& transientB64,
        std::int64_t expiresUnix, const std::string& sealingKeyPem,
        const std::string& signingKeyPem);
    void teardownLocked(const std::string& userFp);
    // Starts the expiry sweeper once; called from reloadPersisted, which every
    // server runs at start.
    void startSweeper();
    std::filesystem::path pathFor(const std::string& userFp) const;
    std::filesystem::path destsDir() const;

    bazarish::i2p::Router* const router_;
    DeliveryEngine& engine_;
    const std::filesystem::path stateDir_;
    const bazarish::i2p::Privacy privacy_;
    const int tunnelQuantity_;
    FederationRateLimiter* const limiter_;
    GetCardFn getCard_;
    AckSenderFn ackSender_;
    OnAckFn onAck_;
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Destination>> dests_;
    // Watches for delegations running out. Sleeps on stopCv_, so shutdown is
    // immediate rather than one sweep interval away.
    std::thread sweeper_;
    std::condition_variable stopCv_;
    std::mutex stopMutex_;
    bool stopping_ = false;
};

}  // namespace bazarish::server
