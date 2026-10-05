// Bazarish project (c) 2026
#pragma once

#include "ServerSettings.hpp"
#include "Storage.hpp"

#include "SessionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/HttpServer.hpp>
#include <Restart.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {

class EventGate;

// A user's own serving destination and its serving sealing key (private half held
// by this server). Used both to surface the destination to the user and to decide
// same-destination local delivery. An empty dest / null key means the user has no
// destination yet.
struct DestinationAssignment {
    std::string dest;
    std::shared_ptr<Key> servingKey;
    // "none" / "building" / "active" / "expired", so the client can tell an online
    // destination (publish its address) from one still building or offline.
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
    std::int64_t mailboxRetentionSeconds = 30 * kSecondsPerDay;
    // Fingerprints of the identities authorised to call the operator-internal
    // endpoints (quota, per-user destination) and /healthz. The caller proves
    // possession by signing the request (hybrid auth); no shared secret. The
    // service node (quota/transient pushes) and the admin panel (management,
    // health) are the operators. Empty authorises nobody.
    std::vector<std::string> operatorFingerprints;
    // Version string reported by /healthz.
    std::string version;
    // Brings up (or replaces) a user's own I2P destination from the offline
    // transient they delegated; the operator-internal i2p-dest endpoint calls it
    // (same operator signature as quota). Empty disables the endpoint.
    std::function<void(const std::string& user, const std::string& transientB64,
        std::int64_t expiresUnix)>
        provisionI2pDest;
    // Tears down a user's destination (delegation lapsed or revoked).
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

    // A slice of this server's netDb, for the reseed archive below. Absent when
    // the server runs without a router, and then it serves no archive.
    std::function<std::vector<Bytes>(std::size_t count)> reseedSample;
    // What this server's storage actually occupies on disk, for the operator
    // panel. Quotas say what has been promised; only the filesystem says what has
    // been used. Empty = the endpoint answers that it cannot tell.
    std::function<std::uint64_t()> diskUsage;
    // Longest a client may ask to be held on the event face. Anything longer is
    // clamped: an idle I2P stream that lives too long is torn down under us.
    int maxEventWaitSeconds = 30;
    // What a waiting client is parked on. Null leaves the event route unregistered
    // and clients fall back to polling.
    EventGate* eventGate = nullptr;
    // This server's own signing identity: it signs the account calls it forwards
    // to the service node, which is how the node knows the call is one this
    // server authenticated and whose it is.
    std::shared_ptr<const Identity> identity;
    // This server's sealing key: what a client's tunnel hello is sealed to. The
    // public half rides in the server card below, which the client verifies
    // against the fingerprint it already had, so the facade in between can
    // withhold the card but never substitute one of its own.
    std::shared_ptr<Key> sealingKey;
    // The signed server card, served as-is to any caller: it is public, it is the
    // same answer for everybody, and it is what bootstraps the tunnel.
    Bytes serverCardDer;
    // Where the service node answers. A client's account calls arrive inside the
    // tunnel and are forwarded there under this server's own signature: the node
    // never sees a client, and the facade never sees which of the two a request
    // was for.
    std::string serviceNodeUrl;
};

// The /v1/messaging/* HTTP API: client registry, delivery passes, pending
// fetch/ack and the write a device makes into its own account's mailbox. Outgoing
// mail is not here: a client delivers its own, dialling the recipient's
// destination itself, so this server is never asked who its users write to.
class HttpApi {
public:
    HttpApi(Storage& storage, HttpApiOptions options);
    ~HttpApi();

    HttpApi(const HttpApi&) = delete;
    HttpApi& operator=(const HttpApi&) = delete;

    // Binds and starts serving (port 0 lets the kernel pick). Returns the bound
    // port, 0 when the socket could not be taken.
    int bind(const std::string& host, int port);
    // Parks the caller until stop(). The engine serves on its own threads.
    void wait();
    void stop();

private:
    // Wakes a user's parked long-poll, if there is a gate. Safe to call with no
    // gate and with no waiter.
    void wakeUser(const std::string& user);

    void setupRoutes();
    // Verifies a request under either scheme - a session MAC or the hybrid
    // signature - and fills the caller's fingerprint. Returns the refusal to send
    // back, or nothing when the caller is who they say they are.
    // allowSession false accepts the signature only: opening a session is the one
    // thing a session may not do, or a leaked secret would renew itself into a
    // credential that never expires and the identity would never be presented
    // again.
    std::optional<bazarish::http::Response> authenticateRequest(
        const bazarish::http::Request& request, std::string* outUser,
        bool allowSession = true);
    // The one route a facade can see. Opens the frame, runs what was inside
    // through this server's own routes, and seals the answer back.
    void serveTunnel(const bazarish::http::Request& request, bazarish::http::Responder respond);
    // An account call that arrived in a tunnel: forwarded to the service node
    // under this server's signature, which vouches for whose call it is.
    bazarish::http::Response forwardToNode(
        const bazarish::http::Request& request, const std::string& user);
    // The reseed archive this server hands out, packed from a slice of its netDb
    // and rebuilt no more often than kReseedRefreshSeconds. One archive for
    // everyone who asks within that hour: it costs the disk one walk, and it
    // leaves nobody a way to pull the netDb by asking repeatedly.
    std::string reseedArchive();

    // Periodic mailbox TTL sweep: the backstop for mail no device ever acked.
    void mailboxJanitorLoop();

    std::mutex reseedMutex_;
    std::string reseedSu3_;
    std::int64_t reseedPackedAt_ = 0;

    Storage& storage_;
    const HttpApiOptions options_;

    std::unique_ptr<bazarish::http::Server> http_;
    // Sessions clients authenticate with once they have opened one; the hybrid
    // signature stays the way in, and the way back when a session lapses.
    SessionStore sessions_;
    std::int64_t startedAt_ = 0;

    // What the janitor sleeps against and a main() parks on, so a stop reaches
    // both at once.
    bazarish::StopGate stopGate_;
    std::thread janitorThread_;

    auth::ReplayCache replayCache_;
};

}  // namespace bazarish::server
