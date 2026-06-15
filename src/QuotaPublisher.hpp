// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <string>

namespace bazarish::service {

// Pushes a user's effective storage quota to the messaging server's
// operator-internal endpoint (PUT /v1/messaging/quota), authorised by the
// shared operator secret over the private channel. The service node calls this
// when a user's storage plan changes (subscribe/renew, buy storage). Best
// effort: a failed push is swallowed (the next subscribe re-publishes), so a
// momentarily-down messaging server never fails a portal action. A no-op when
// not configured (empty messaging URL).
class QuotaPublisher {
public:
    QuotaPublisher(std::string messagingUrl, std::string operatorSecret);

    // Returns whether the push was accepted (false on no-op or any failure).
    bool publish(const std::string& user, std::uint64_t quotaBytes) const;

private:
    std::string messagingUrl_;  // http://host:port, empty disables
    std::string operatorSecret_;
};

}  // namespace bazarish::service
