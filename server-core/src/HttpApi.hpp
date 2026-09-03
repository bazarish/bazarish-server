// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "ServerSettings.hpp"
#include "Storage.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/HttpServer.hpp>

#include "SessionStore.hpp"

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
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
    // The settings an operator turns from the panel, and the file they go back
    // to. Null leaves the settings endpoints out: a server started without a
    // config file has nothing to write.
    std::shared_ptr<ServerSettings> settings;
    // Asked for by the panel when a setting only a restart can pick up has been
    // written. Empty answers that this server cannot restart itself, rather than
    // pretending it did.
    std::function<void()> requestRestart;
    // Facts an operator reads on the settings page and cannot change from it.
    std::string stateDirectory;
    std::string fingerprint;
    // The server's default per-user mailbox quota, reported (alongside actual usage)
    // by /v1/messaging/storage-usage when a user has no quota override. Mirrors the
    // delivery engine's defaultQuotaBytes.
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
    // Mailbox TTL backstop: a pending blob still un-acked by all of a user's
    // registered devices this long after receipt is reclaimed by the janitor
    // sweep. The primary cleanup is delete-on-all-devices-acked; this only
    // bounds mail for a device that never returns (or a user with no registered
    // clients). 0 disables the sweep.
    std::int64_t mailboxRetentionSeconds = 30 * 24 * 3600;
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
    // Rotating a user's serving sealing key, in two steps so the switch is the
    // user's to make: prepare mints a replacement and returns its public half
    // (base64 SPKI) while the key in use keeps serving, commit puts it in force
    // once the user has signed it into a card. Empty disables the endpoint.
    std::function<std::string(const std::string& user)> prepareServingKey;
    std::function<bool(const std::string& user)> commitServingKey;
    // Resolves the caller's assigned destination + serving key. A send is
    // delivered locally only when its toDest equals the caller's own assigned
    // destination (same i2p destination); every other toDest - including a
    // co-located recipient on a different destination - is federated, so
    // delivery latency cannot reveal co-location (see docs-main
    // api/InviteAnonymity.md). Also backs GET /v1/messaging/destination. Empty
    // disables local delivery (every send federates).
    AssignDestinationFn assignDestination;

    // What this server's storage actually occupies on disk, for the operator
    // panel. Quotas say what has been promised; only the filesystem says what has
    // been used. Empty = the endpoint answers that it cannot tell.
    std::function<std::uint64_t()> diskUsage;
    // Longest a client may ask to be held on the event face. Anything longer is
    // clamped: an idle I2P stream that lives too long is torn down under us.
    int maxEventWaitSeconds = 30;
};

// The /v1/messaging/* HTTP API: client registry, token hashes, pending fetch/ack
// and the write a device makes into its own account's mailbox. Outgoing mail is
// not here: a client delivers its own, dialling the recipient's destination
// itself, so this server is never asked who its users write to.
class HttpApi {
public:
    HttpApi(Storage& storage, DeliveryEngine& engine, HttpApiOptions options);
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

private:
    // Wakes a user's parked long-poll, if there is a gate. Safe to call with no
    // gate and with no waiter.
    void wakeUser(const std::string& user);

    void setupRoutes();
    // Verifies a request under either scheme - a session MAC or the hybrid
    // signature - and fills the caller's fingerprint. Returns the refusal to send
    // back, or nothing when the caller is who they say they are.
    std::optional<bazarish::http::Response> authenticateRequest(
        const bazarish::http::Request& request, std::string* outUser);
    void stopWorkers();
    // Periodic mailbox TTL sweep (the backstop for never-fully-acked mail).
    void mailboxJanitorLoop();
    // A revocation waiting for the janitor thread: one user, one mask.
    struct Revocation {
        std::string user;
        Bytes mask;
    };
    // Hands one to that thread and wakes it. Called from a request handler, so it
    // does no work of its own.
    void queueRevocation(const std::string& user, Bytes mask);

    Storage& storage_;
    DeliveryEngine& engine_;
    const HttpApiOptions options_;

    std::unique_ptr<bazarish::http::Server> http_;
    EventGate* eventGate_ = nullptr;
    // Sessions clients authenticate with once they have opened one; the hybrid
    // signature stays the way in, and the way back when a session lapses.
    SessionStore sessions_;
    std::int64_t startedAt_ = 0;

    // Shutdown rendezvous for the background threads below.
    std::mutex stopMutex_;
    std::condition_variable stopCv_;
    // Background mailbox TTL sweep (the backstop for never-fully-acked mail).
    std::thread janitorThread_;
    // Guarded by stopMutex_, drained by the janitor thread.
    std::vector<Revocation> revocations_;
    bool stopping_ = false;

    auth::ReplayCache replayCache_;
};

}  // namespace bazarish::server
