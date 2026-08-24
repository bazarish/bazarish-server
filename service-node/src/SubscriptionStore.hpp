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

// Persistent user-management state for one service node: the accounts it serves.
// An account has no term - registration opens an unbounded channel - so what is
// kept is the quota this node granted, the user's published contact card, and
// when the user last delegated a destination. That last one is the only clock:
// an account that stops delegating is swept.
//
// Layout under the root directory:
//   subscriptions/<fingerprint>.json   {user, registeredAt, quotaBytes, dest,
//                                       delegatedAt, card}
class SubscriptionStore {
public:
    struct Account {
        std::string user;
        std::int64_t registeredAt = 0;
        std::uint64_t quotaBytes = 0;
        // The I2P destination the user published in their card, kept out of it
        // so a listing can show and search addresses without verifying a
        // signature per row. Empty until the user publishes routing.
        std::string dest;
        // When the server last held a delegation for that destination. Zero
        // means the user has never delegated one.
        std::int64_t delegatedAt = 0;
        // The serving key from that card (base64url), kept beside it so a card
        // lookup can check the key it was asked with before it verifies
        // anything: a signature verify that only happens for a user this node
        // has is a timing answer to "do you have them?".
        std::string servingKey;
        // The hybrid-signed contact card (DER), as published by the user.
        Bytes card;
    };

    explicit SubscriptionStore(const std::filesystem::path& root);

    void putAccount(const Account& account);
    std::optional<Account> getAccount(const std::string& user);
    // Every account on file, for the reconciliation this node owes the messaging
    // server at start (quotas it may have missed) and for the idle sweep.
    std::vector<Account> allAccounts() const;
    void deleteAccount(const std::string& user);

private:
    std::filesystem::path accountPath(const std::string& user) const;

    std::filesystem::path root_;
    mutable std::mutex mutex_;
};

}  // namespace bazarish::service
