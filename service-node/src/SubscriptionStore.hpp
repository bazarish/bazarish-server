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

class SubscriptionStore {
public:
    struct Account {
        std::string user;
        std::int64_t registeredAt = 0;
        std::uint64_t quotaBytes = 0;
        std::string dest;
        std::int64_t delegatedAt = 0;
        Bytes card;
    };

    explicit SubscriptionStore(const std::filesystem::path& root);

    void putAccount(const Account& account);
    std::optional<Account> getAccount(const std::string& user);
    std::vector<Account> allAccounts() const;
    void deleteAccount(const std::string& user);

private:
    std::filesystem::path accountPath(const std::string& user) const;

    std::filesystem::path root_;
    mutable std::mutex mutex_;
};

}  // namespace bazarish::service
