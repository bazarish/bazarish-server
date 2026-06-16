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
};

// Result of relaying a sealed envelope to another server (federation).
struct RemoteDeliveryResult {
    bool reachable = false;
    bool delivered = false;
    std::string errorCode;
    std::string errorMessage;
};

// Relays a sealed envelope to the named server over a federation transport.
// The default (no transport wired) reports unreachable.
using RemoteDeliverFn = std::function<RemoteDeliveryResult(
    const std::string& toServer, const Bytes& sealed, const Bytes& payload)>;

// The /v1/messaging/* HTTP API: client registry, token hashes, pending
// fetch/ack and submit+poll sending. Local deliveries (toServer == this
// server) run the shared DeliveryEngine; remote ones go through the
// injected federation transport.
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
