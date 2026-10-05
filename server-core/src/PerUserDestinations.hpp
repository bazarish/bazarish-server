// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "Federation.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>
#include <Restart.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {


// Operates the federation destinations of users who own their I2P key. Every
// account has one - it is the base protocol, not a purchase.
//
// The user delegates a time-boxed OFFLINE transient to the server, which brings
// the destination up over I2P as an encrypted LeaseSet2, with its own inbound
// accept loop feeding the shared DeliveryEngine. The delegation carries one
// blinded-key-authorized transient per day, so the server publishes the
// destination blinded without ever holding the master signing key: a floodfill
// sees neither the address nor its tunnels. The address is derived from the user's
// master, so it is stable as the user moves between serving servers.
//
// Building a session triggers I2P tunnel construction, so each destination runs on
// its own worker thread and provisioning never blocks the caller.
class PerUserDestinations {
public:
    // router may be null (provision/reload then only persist + register state;
    // no destination is built - used in tests and when running router-less).
    PerUserDestinations(bazarish::i2p::Router* router, DeliveryEngine& engine,
        std::filesystem::path stateDir, bazarish::i2p::Privacy privacy,
        int tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity,
        RateLimiter* limiter = nullptr);
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
    // The serving endpoint for a provisioned dest (by routingHost), or null - so
    // the outbound federation path can dial from the sender's own dest.
    std::shared_ptr<bazarish::i2p::Endpoint> endpointForDest(const std::string& dest) const;

    // Number of currently provisioned destinations (for tests / diagnostics).
    std::size_t size() const;

    // What a user's own destination amounts to right now. The three are read under
    // one lock: fetched separately, two of them could come from either side of a
    // revoke and the client would be told an address with no key, or the reverse.
    struct Assignment {
        // The destination's b33, learned once it publishes. Empty until then.
        std::string dest;
        // The key a contact seals the delivery envelope to, whose private half
        // this server holds. Stable across renewals; null when the user has no
        // destination here.
        std::shared_ptr<Key> sealingKey;
        // What the client polls for:
        //   "none"      - no destination here,
        //   "building"  - provisioned, not published yet (so the client must not
        //                 hand the address out),
        //   "active"    - published and within the delegation,
        //   "expired"   - the delegation lapsed and the address is offline until
        //                 the client issues the next transient.
        std::string state = "none";
    };
    Assignment assignmentFor(const std::string& userFp, std::int64_t now) const;

    // Mints a replacement serving sealing key and holds it aside without putting
    // it into service: the key in use keeps serving until commitServingKey, so a
    // rotation that is never finished changes nothing. Returns the new key's
    // public half (base64 SPKI), which the user signs into a fresh contact card.
    std::string prepareServingKey(const std::string& userFp);
    // Puts the prepared key into service and forgets the old one, from which
    // moment an envelope sealed to the old key is refused. False when there is
    // nothing prepared (a commit for a rotation that was never started).
    bool commitServingKey(const std::string& userFp);

private:
    struct Destination {
        std::atomic<bool> running{true};
        // Several: one accepted stream must not hold up the next. A destination
        // that serves inbound deliveries one at a time makes every sender behind
        // a slow one wait, and the queue behind it is unbounded.
        std::vector<std::thread> workers;
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
        // The published destination address (the master's b33); set once the
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
    // Takes the destination out of service and hands its threads to reapRetired.
    // It does NOT join them: the callers hold mutex_, the workers take mutex_ per
    // request, and joining under it is a deadlock that freezes every destination.
    void teardownLocked(const std::string& userFp);
    // Joins whatever teardownLocked retired. Called with no lock held.
    void reapRetired();
    // The accept-and-serve loop of one destination, run by each of its workers.
    void serveLoop(Destination* destination, const std::string& userFp);
    // Closes streams whose serve has outstayed its deadline: an I2P read has none
    // of its own, and a peer that opens a stream and says nothing would otherwise
    // hold a worker forever.
    void startWatchdog();
    void watchStream(const std::shared_ptr<bazarish::i2p::Stream>& stream);
    void unwatchStream(const bazarish::i2p::Stream* stream);
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
    RateLimiter* const limiter_;
    GetCardFn getCard_;
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Destination>> dests_;
    // Watches for delegations running out. Sleeps on the gate, so shutdown is
    // immediate rather than one sweep interval away.
    std::thread sweeper_;
    std::thread watchdog_;
    // Destinations taken out of service, waiting to be joined outside mutex_.
    std::mutex retiringMutex_;
    std::vector<std::unique_ptr<Destination>> retiring_;
    // Streams being served now, with the moment each stops being given the
    // benefit of the doubt.
    std::mutex watchMutex_;
    std::vector<std::pair<std::weak_ptr<bazarish::i2p::Stream>,
        std::chrono::steady_clock::time_point>>
        watched_;
    bazarish::StopGate stopGate_;
};

}  // namespace bazarish::server
