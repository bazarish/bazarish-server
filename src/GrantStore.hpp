// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>

namespace bazarish::service {

// Pending entitlement grants, set by the portal once a user has passed the
// captcha (free tier) or paid (paid tier), and consumed when the Client submits
// the corresponding user-signed certificate. This is how a browser flow (no
// private key) authorises an artifact only the Client can sign: the portal
// grants, the Client submits, the node checks the grant.
//
// Layout: <root>/grants/<fingerprint>.json  { "subscription": {...}? }
class GrantStore {
public:
    struct SubscriptionGrant {
        std::uint64_t quotaBytes = 0;
        std::int64_t termSeconds = 0;
        std::int64_t grantedAt = 0;
    };

    // A paid service entitlement (username / i2pDest / storage), valid until
    // paidThrough (unix seconds).
    struct ServiceGrant {
        std::int64_t paidThrough = 0;
        std::int64_t grantedAt = 0;
    };

    explicit GrantStore(std::filesystem::path root);

    // Grants (or refreshes) a pending subscription for the user — the quota and
    // maximum term the node will then accept on the user's submitted cert.
    void grantSubscription(const std::string& user, std::uint64_t quotaBytes,
        std::int64_t termSeconds, std::int64_t now);

    // The pending subscription grant without consuming it (UI / checks).
    std::optional<SubscriptionGrant> peekSubscription(const std::string& user);

    // Consumes the pending subscription grant (one-shot); nullopt if none.
    std::optional<SubscriptionGrant> takeSubscription(const std::string& user);

    // Records a paid service entitlement valid until paidThrough (a purchase or
    // renewal). Unlike a subscription grant this is not one-shot — it is the
    // standing paid-through marker the downstream feature reads.
    void grantService(const std::string& user, const std::string& service,
        std::int64_t paidThrough, std::int64_t now);

    // The current entitlement for a service; nullopt if never bought.
    std::optional<ServiceGrant> peekService(const std::string& user, const std::string& service);

private:
    std::filesystem::path grantPath(const std::string& user) const;

    std::filesystem::path root_;
    std::mutex mutex_;
};

}  // namespace bazarish::service
