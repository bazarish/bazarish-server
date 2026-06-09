// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>

namespace bazarish::service {

// Persistent user-management state for one service node: subscriptions and
// aliases. The service node owns the limit (quota) and the certificates;
// content usage lives on the messaging server.
//
// Layout under the root directory:
//   subscriptions/<fingerprint>.json   {user, issuedAt, notAfter, quotaBytes, cert}
//   aliases/<alias>.json               {alias, user, cert}
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

    struct Alias {
        std::string alias;
        std::string user;
        // The hybrid-signed alias certificate (DER).
        Bytes certificate;
    };

    explicit SubscriptionStore(const std::filesystem::path& root);

    void putSubscription(const Subscription& subscription);
    std::optional<Subscription> getSubscription(const std::string& user);
    void deleteSubscription(const std::string& user);

    // Registers the alias. Returns false (and changes nothing) when the
    // alias already belongs to a different user; re-registering one's own
    // alias succeeds (refresh).
    bool putAlias(const Alias& alias);
    std::optional<Alias> getAlias(const std::string& alias);
    // Deletes the alias only when owned by the given user; returns whether
    // a deletion happened.
    bool deleteAlias(const std::string& alias, const std::string& user);

private:
    std::filesystem::path subscriptionPath(const std::string& user) const;
    std::filesystem::path aliasPath(const std::string& alias) const;

    std::filesystem::path root_;
    std::mutex mutex_;
};

}  // namespace bazarish::service
