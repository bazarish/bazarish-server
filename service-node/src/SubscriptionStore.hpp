// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <vector>
#include <string>

namespace bazarish::service {

// Persistent user-management state for one service node: subscriptions. The
// service node owns the limit (quota) and the certificates; content usage
// lives on the messaging server.
//
// Layout under the root directory:
//   subscriptions/<fingerprint>.json   {user, issuedAt, notAfter, quotaBytes, cert}
class SubscriptionStore {
public:
    struct Subscription {
        std::string user;
        std::int64_t issuedAt = 0;
        std::int64_t notAfter = 0;
        std::uint64_t quotaBytes = 0;
        // The hybrid-signed subscription certificate (DER).
        Bytes certificate;
    };

    explicit SubscriptionStore(const std::filesystem::path& root);

    void putSubscription(const Subscription& subscription);
    std::optional<Subscription> getSubscription(const std::string& user);
    // Every subscription on file, for the reconciliation this node owes the
    // messaging server at start (quotas it may have missed).
    std::vector<Subscription> allSubscriptions() const;
    void deleteSubscription(const std::string& user);

private:
    std::filesystem::path subscriptionPath(const std::string& user) const;

    std::filesystem::path root_;
    mutable std::mutex mutex_;
};

}  // namespace bazarish::service
