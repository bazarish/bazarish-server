// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "I2pBlobFetch.hpp"
#include "Storage.hpp"

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace httplib {
class Server;
}

namespace bazarish::server {

struct HttpApiOptions {
    // Hard cap on a single delivery envelope.
    std::uint64_t perMessageLimitBytes = 10 * 1024 * 1024;
    // How long a completed send attempt stays pollable.
    std::int64_t attemptRetentionSeconds = 600;
    // Shared secret authorising the operator-internal quota endpoint (checked
    // against the X-Operator-Secret header). Empty disables that endpoint.
    std::string operatorSecret;
    // Runs a small blob op over I2P for a client that has no SAM bridge of its
    // own (the proxy fallback): used for DELETE (unsend), with an optional
    // delete-token. Empty disables proxy unsend.
    std::function<BlobProxyResult(const std::string& method, const std::string& host,
        const std::string& path, const std::string& deleteToken)>
        blobProxyFetch;
    // Streams a blob download over I2P for a no-SAM client (proxy GET): host +
    // path + optional Range → a pull reader the endpoint drains into the client
    // response a chunk at a time, so a large blob is never buffered whole on the
    // user's own server. Empty disables proxy downloads.
    std::function<std::unique_ptr<I2pBlobReader>(
        const std::string& host, const std::string& path, const std::string& range)>
        blobProxyDownload;
    // Brings up (or replaces) a paid user's personal I2P destination from a
    // client-owned offline transient; the operator-internal i2p-dest endpoint
    // calls it (same X-Operator-Secret as quota). Empty disables the endpoint.
    std::function<void(const std::string& user, const std::string& transientB64,
        std::int64_t expiresUnix)>
        provisionI2pDest;
    // Tears down a user's personal destination (grant lapsed/revoked).
    std::function<void(const std::string& user)> revokeI2pDest;
    // This server's own home delivery destination (its I2P destination). A send
    // whose toDest equals it is delivered locally with the engine's home key;
    // any other toDest is federated (dialled directly over I2P). Empty disables
    // local delivery (every send federates).
    std::string localDest;
};

// Result of relaying a sealed envelope to another destination (federation).
struct RemoteDeliveryResult {
    bool reachable = false;
    bool delivered = false;
    std::string errorCode;
    std::string errorMessage;
};

// Relays a sealed envelope to a destination over I2P federation (dialled
// directly — routing is by destination, not by server fingerprint; see
// docs-main api/InviteAnonymity.md). The default (no transport wired) reports
// unreachable.
using RemoteDeliverFn = std::function<RemoteDeliveryResult(
    const std::string& toDest, const Bytes& sealed, const Bytes& payload)>;

// The /v1/messaging/* HTTP API: client registry, token hashes, pending
// fetch/ack and submit+poll sending. A send is routed by its toDest: a delivery
// to this server's own destination runs the shared DeliveryEngine locally; any
// other destination is dialled directly over I2P federation.
class HttpApi {
public:
    HttpApi(Storage& storage, DeliveryEngine& engine, HttpApiOptions options,
        RemoteDeliverFn remoteDeliver = {});
    ~HttpApi();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    void stop();

private:
    struct Attempt {
        std::string status;  // "delivered" or "failed"
        std::string errorCode;
        std::string errorMessage;
        std::int64_t completedAt = 0;
    };

    void setupRoutes();

    Storage& storage_;
    DeliveryEngine& engine_;
    const HttpApiOptions options_;
    RemoteDeliverFn remoteDeliver_;

    std::unique_ptr<httplib::Server> http_;

    std::mutex attemptsMutex_;
    std::map<std::string, Attempt> attempts_;
};

}  // namespace bazarish::server
