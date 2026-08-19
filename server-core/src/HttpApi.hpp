// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "Storage.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/HttpServer.hpp>

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {

// A user's assigned serving destination and its serving sealing key (private
// half held by this server). Used both to surface the destination to the user
// and to decide same-destination local delivery. An empty dest / null key means
// the user has no assigned destination yet.
class EventGate;

struct DestinationAssignment {
    std::string dest;
    std::shared_ptr<Key> servingKey;
    // The serving state surfaced to the client: "none" when the user has no
    // destination yet, else "building" / "active" / "expired" (see
    // PerUserDestinations::stateFor). Lets the client tell an online destination
    // (publish its address) from one still building or offline.
    std::string state;
};

// Resolves the authenticated caller's assigned destination. Looked up
// server-side from the caller's fingerprint - never from a client-supplied
// value - so a sender cannot forge it to force a revealing local delivery.
using AssignDestinationFn = std::function<DestinationAssignment(const std::string& user)>;

struct HttpApiOptions {
    // Hard cap on a single delivery envelope, and with it the point at which a
    // file stops going through the mailbox: a client that gets this cap back as a
    // typed error falls back to transferring the file directly to the recipient.
    // Operators should size it against the quota, not against the smallest thing
    // that works - too small a cap pushes ordinary attachments into a transfer
    // that needs both sides online.
    std::uint64_t perMessageLimitBytes = 1 * 1024 * 1024;
    // The server's default per-user mailbox quota, reported (alongside actual usage)
    // by /v1/messaging/storage-usage when a user has no quota override. Mirrors the
    // delivery engine's defaultQuotaBytes.
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
    // How long a completed send attempt stays pollable.
    std::int64_t attemptRetentionSeconds = 600;
    // Mailbox TTL backstop: a pending blob still un-acked by all of a user's
    // registered devices this long after receipt is reclaimed by the janitor
    // sweep. The primary cleanup is delete-on-all-devices-acked; this only
    // bounds mail for a device that never returns (or a user with no registered
    // clients). 0 disables the sweep.
    std::int64_t mailboxRetentionSeconds = 30 * 24 * 3600;
    // Background delivery (store-and-forward) retry policy for a recipient whose
    // I2P leaseset is momentarily unpublished: how many federation rounds before
    // giving up. The first rounds retry immediately, then the backoff grows (see
    // retryBackoff): rounds 0-2 immediate, 3-5 one second, then +1s capped at 5s.
    int deliveryMaxRounds = 12;
    // Fingerprints of the identities authorised to call the operator-internal
    // endpoints (quota, per-user destination) and /healthz. The caller proves
    // possession by signing the request (hybrid auth); no shared secret. The
    // service node (quota/transient pushes) and the admin panel (management,
    // health) are the operators. Empty authorises nobody.
    std::vector<std::string> operatorFingerprints;
    // Version string reported by /healthz.
    std::string version;
    // Brings up (or replaces) a paid user's personal I2P destination from a
    // client-owned offline transient; the operator-internal i2p-dest endpoint
    // calls it (same operator signature as quota). Empty disables the endpoint.
    std::function<void(const std::string& user, const std::string& transientB64,
        std::int64_t expiresUnix)>
        provisionI2pDest;
    // Tears down a user's personal destination (grant lapsed/revoked).
    std::function<void(const std::string& user)> revokeI2pDest;
    // Resolves the caller's assigned destination + serving key. A send is
    // delivered locally only when its toDest equals the caller's own assigned
    // destination (same i2p destination); every other toDest - including a
    // co-located recipient on a different destination - is federated, so
    // delivery latency cannot reveal co-location (see docs-main
    // api/InviteAnonymity.md). Also backs GET /v1/messaging/destination. Empty
    // disables local delivery (every send federates).
    AssignDestinationFn assignDestination;
    // Hands a starting client a slice of this server's netDb so it can bring up
    // I2P without touching a public reseed host. Unauthenticated on purpose: a
    // client has no I2P yet, and every RouterInfo authenticates itself. Empty
    // disables the endpoint.
    std::function<std::vector<Bytes>(std::size_t count)> reseedSample;
    // Longest a client may ask to be held on the event face. Anything longer is
    // clamped: an idle I2P stream that lives too long is torn down under us.
    int maxEventWaitSeconds = 30;
};

// Result of relaying a sealed envelope to another destination (federation).
struct RemoteDeliveryResult {
    bool reachable = false;
    bool delivered = false;
    std::string errorCode;
    std::string errorMessage;
};

// Relays a sealed envelope to a destination over I2P federation. Dialled from the
// SENDER's own serving destination (senderDest) so a delivery never originates
// from a shared address - the recipient acks back to senderDest. Routing is by
// destination (see docs-main api/InviteAnonymity.md). The default (no transport
// wired) reports unreachable.
// onPhase, when set, is called as the relay progresses through its federation
// phases ("dialing", "connected", "sending", "awaiting-ack") so the caller can
// surface real, human-readable delivery status. Best-effort and may be empty.
using FederationPhaseFn = std::function<void(const std::string& phase)>;
using RemoteDeliverFn = std::function<RemoteDeliveryResult(const std::string& senderDest,
    const std::string& toDest, const Bytes& sealed, const Bytes& payload,
    const FederationPhaseFn& onPhase)>;

// Result of relaying a sealed fetch (card / resolve) to a destination.
struct RemoteFetchResult {
    bool reachable = false;
    bool ok = false;
    Bytes sealed;
    std::string errorCode;
    std::string errorMessage;
};

// Relays a sealed fetch request (op "card" or "resolve") to a destination over
// I2P and returns the sealed response - the proxy fallback for a client without
// its own I2P transport. The default (no transport wired) reports unreachable.
using RemoteFetchFn = std::function<RemoteFetchResult(
    const std::string& toDest, const std::string& op, const Bytes& sealed)>;

// The /v1/messaging/* HTTP API: client registry, token hashes, pending
// fetch/ack and submit+poll sending. A send is routed by its toDest: a delivery
// to the sender's own destination runs the shared DeliveryEngine locally; every
// other destination - even a co-located recipient on a different destination -
// is dialled over I2P federation, so timing reveals no co-location.
class HttpApi {
public:
    HttpApi(Storage& storage, DeliveryEngine& engine, HttpApiOptions options,
        RemoteDeliverFn remoteDeliver = {}, RemoteFetchFn remoteFetch = {});
    // What a waiting client is parked on. Without it the event route is not
    // registered at all and clients fall back to polling.
    void setEventGate(EventGate* gate) { eventGate_ = gate; }
    ~HttpApi();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    // Binds a specific port (0 = any) and returns the one bound, 0 on failure.
    int bindToAnyPort(const std::string& host, int port);
    bool listenAfterBind();
    void stop();

    // Marks the send attempt for this delivery messageId "delivered" (amber), on a
    // verified delivered-ack from the recipient server. Idempotent; a no-op for an
    // unknown id or an already-terminal attempt. Thread-safe.
    void markDeliveredByMessageId(const std::string& messageId);

private:
    struct Attempt {
        std::string status;  // "pending", "delivered", "failed" or "unconfirmed"
        // The live federation phase while status is "pending" ("queued", "dialing",
        // "connected", "sending", "awaiting-ack"), so a polling client can show real
        // delivery progress instead of an opaque "pending". Empty once terminal.
        std::string phase;
        std::string errorCode;
        std::string errorMessage;
        std::int64_t completedAt = 0;
        std::string messageId;  // delivery id, for the messageId -> attempt index
    };

    // A send accepted into the outbound buffer and delivered off the request
    // thread by a background worker (store-and-forward), so the client's POST
    // returns at once. The sealed envelope already names its recipient
    // destination; senderDest/senderServingKey back the same-destination local
    // short-circuit.
    struct DeliveryJob {
        std::string attemptId;
        std::string toDest;
        Bytes sealed;
        Bytes payload;
        std::string senderDest;
        std::shared_ptr<Key> senderServingKey;
    };

    void setupRoutes();
    void deliveryWorkerLoop();
    void runDeliveryJob(const DeliveryJob& job);
    void setAttempt(const std::string& attemptId, const Attempt& attempt);
    // Updates only the live federation phase of an existing, still-pending attempt
    // (a no-op once it is terminal). Thread-safe.
    void setAttemptPhase(const std::string& attemptId, const std::string& phase);
    void stopWorkers();
    // Periodic mailbox TTL sweep (the backstop for never-fully-acked mail).
    void mailboxJanitorLoop();

    Storage& storage_;
    DeliveryEngine& engine_;
    const HttpApiOptions options_;
    RemoteDeliverFn remoteDeliver_;
    RemoteFetchFn remoteFetch_;

    std::unique_ptr<bazarish::http::Server> http_;
    EventGate* eventGate_ = nullptr;
    std::int64_t startedAt_ = 0;

    std::mutex attemptsMutex_;
    std::map<std::string, Attempt> attempts_;
    // delivery messageId -> attemptId, so an inbound delivered-ack (which carries
    // the messageId, not our attempt id) resolves to the right attempt.
    std::map<std::string, std::string> messageIdToAttempt_;

    // Background delivery executor (store-and-forward): the request thread only
    // enqueues; these workers federate with retries and record the outcome.
    std::mutex jobsMutex_;
    std::condition_variable jobsCv_;
    std::deque<DeliveryJob> jobs_;
    std::vector<std::thread> deliveryWorkers_;
    // Background mailbox TTL sweep; shares stopping_/jobsCv_ for shutdown.
    std::thread janitorThread_;
    bool stopping_ = false;

    auth::ReplayCache replayCache_;
};

}  // namespace bazarish::server
