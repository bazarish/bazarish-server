// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <string>

namespace bazarish::service {

// Pushes a paid user's client-owned offline I2P transient to the messaging
// server's operator-internal per-user-destination endpoint (PUT
// /v1/messaging/i2p-dest), authorised by the shared operator secret over the
// private channel. An empty transient revokes the destination. The service node
// calls this when a user with an active i2pDest entitlement delegates a fresh
// transient. Best effort: a failed push is swallowed (the next delegation
// re-publishes). A no-op when not configured (empty base URL).
class TransientPublisher {
public:
    TransientPublisher(std::string baseUrl, std::string operatorSecret,
        std::string endpointPath = "/v1/messaging/i2p-dest");

    // Provisions (non-empty transient) or revokes (empty transient) a user's
    // destination. Returns whether the push was accepted (false on no-op or any
    // failure).
    bool publish(const std::string& user, const std::string& transientB64,
        std::int64_t expiresUnix) const;

private:
    std::string baseUrl_;  // http://host:port, empty disables
    std::string operatorSecret_;
    std::string endpointPath_;
};

}  // namespace bazarish::service
