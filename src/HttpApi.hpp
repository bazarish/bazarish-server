// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "I2pBlobFetch.hpp"
#include "Storage.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>

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

namespace httplib {
class Server;
}

namespace bazarish::server {

// A user's assigned serving destination and its serving sealing key (private
// half held by this server). Used both to surface the destination to the user
// and to decide same-destination local delivery. An empty dest / null key means
// the user has no assigned destination yet.
struct DestinationAssignment {
    std::string dest;
    std::shared_ptr<Key> servingKey;
    // The serving mode/state surfaced to the client: "home", "pool", or for a
    // personal destination "building" / "active" / "expired" (see
    // PerUserDestinations::stateFor). Lets the client tell an online personal
    // destination (publish its address) from one still building or offline.
    std::string state;
};

// Resolves the authenticated caller's assigned destination. Looked up
// server-side from the caller's fingerprint - never from a client-supplied
// value - so a sender cannot forge it to force a revealing local delivery.
using AssignDestinationFn = std::function<DestinationAssignment(const std::string& user)>;

struct HttpApiOptions {
    // Hard cap on a single delivery envelope.
    std::uint64_t perMessageLimitBytes = 10 * 1024 * 1024;
    // How long a completed send attempt stays pollable.
    std::int64_t attemptRetentionSeconds = 600;
    // Background delivery (store-and-forward) retry policy for a recipient whose
    // I2P leaseset is momentarily unpublished: how many federation rounds before
    // giving up, and the delay between them (the first round is immediate).
    int deliveryMaxRounds = 12;
    std::int64_t deliveryRetryDelaySeconds = 10;
    // Fingerprints of the identities authorised to call the operator-internal
    // endpoints (quota, per-user destination) and /healthz. The caller proves
    // possession by signing the request (hybrid auth); no shared secret. The
    // service node (quota/transient pushes) and the admin panel (management,
    // health) are the operators. Empty authorises nobody.
    std::vector<std::string> operatorFingerprints;
    // Version string reported by /healthz.
    std::string version;
    // Runs a small blob op over I2P for a client that has no I2P transport of its
    // own (the proxy fallback): used for DELETE (unsend), with an optional
    // delete-token. Empty disables proxy unsend.
    std::function<BlobProxyResult(const std::string& method, const std::string& host,
        const std::string& path, const std::string& deleteToken)>
        blobProxyFetch;
    // Streams a blob download over I2P for a client with no I2P transport of its
    // own (proxy GET): host +
    // path + optional Range -> a pull reader the endpoint drains into the client
    // response a chunk at a time, so a large blob is never buffered whole on the
    // user's own server. Empty disables proxy downloads.
    std::function<std::unique_ptr<I2pBlobReader>(
        const std::string& host, const std::string& path, const std::string& range)>
        blobProxyDownload;
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
};

// Result of relaying a sealed envelope to another destination (federation).
struct RemoteDeliveryResult {
    bool reachable = false;
    bool delivered = false;
    std::string errorCode;
    std::string errorMessage;
};

// Relays a sealed envelope to a destination over I2P federation (dialled
// directly - routing is by destination, not by server fingerprint; see
// docs-main api/InviteAnonymity.md). The default (no transport wired) reports
// unreachable.
using RemoteDeliverFn = std::function<RemoteDeliveryResult(
    const std::string& toDest, const Bytes& sealed, const Bytes& payload)>;

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
    ~HttpApi();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    void stop();

private:
    struct Attempt {
        std::string status;  // "pending", "delivered" or "failed"
        std::string errorCode;
        std::string errorMessage;
        std::int64_t completedAt = 0;
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
    void stopWorkers();

    Storage& storage_;
    DeliveryEngine& engine_;
    const HttpApiOptions options_;
    RemoteDeliverFn remoteDeliver_;
    RemoteFetchFn remoteFetch_;

    std::unique_ptr<httplib::Server> http_;
    std::int64_t startedAt_ = 0;

    std::mutex attemptsMutex_;
    std::map<std::string, Attempt> attempts_;

    // Background delivery executor (store-and-forward): the request thread only
    // enqueues; these workers federate with retries and record the outcome.
    std::mutex jobsMutex_;
    std::condition_variable jobsCv_;
    std::deque<DeliveryJob> jobs_;
    std::vector<std::thread> deliveryWorkers_;
    bool stopping_ = false;

    auth::ReplayCache replayCache_;
};

}  // namespace bazarish::server
