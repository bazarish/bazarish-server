// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <string>

namespace bazarish {
class Identity;
}

namespace bazarish::service {

// Pushes a user's effective storage quota to a backend's operator-internal quota
// endpoint, authorised by an operator signature over the private channel: the
// service node signs the request with its own identity and the backend authorises
// that fingerprint (no shared secret). Two backends consume it: the messaging
// server (PUT /v1/messaging/quota, mailbox quota) and the blob store
// (PUT /v1/storage/quota, blob-hosting quota). The service node calls this when a
// user's storage plan changes (subscribe/renew, buy storage). Best effort: a
// failed push is swallowed (the next subscribe re-publishes), so a momentarily-
// down backend never fails a portal action. A no-op when not configured (empty
// base URL).
class QuotaPublisher {
public:
    QuotaPublisher(std::string baseUrl, const Identity& signer,
        std::string endpointPath = "/v1/messaging/quota");

    // Returns whether the push was accepted (false on no-op or any failure).
    bool publish(const std::string& user, std::uint64_t quotaBytes) const;

private:
    std::string baseUrl_;  // http://host:port, empty disables
    const Identity& signer_;
    std::string endpointPath_;
};

}  // namespace bazarish::service
