// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::service {

class GrantStore {
public:
    struct SubscriptionGrant {
        std::uint64_t quotaBytes = 0;
        std::int64_t grantedAt = 0;
    };

    struct Transient {
        std::int64_t expires = 0;
        std::int64_t updatedAt = 0;
    };

    explicit GrantStore(std::filesystem::path root);

    void grantSubscription(const std::string& user, std::uint64_t quotaBytes,
        std::int64_t now);

    std::optional<SubscriptionGrant> peekSubscription(const std::string& user);

    std::optional<SubscriptionGrant> takeSubscription(const std::string& user);

    void setI2pTransient(
        const std::string& user, std::int64_t transientExpires, std::int64_t updatedAt);

    std::optional<Transient> peekTransient(const std::string& user);

    struct Approval {
        std::int64_t requestedAt = 0;
        std::int64_t approvedAt = 0;
        std::string message;

        bool pending() const { return approvedAt == 0; }
    };

    void recordRegistration(const std::string& user, std::int64_t now, bool approved);

    std::optional<Approval> peekApproval(const std::string& user);

    void approve(const std::string& user, std::int64_t now);

    void hold(const std::string& user, const std::string& message, std::int64_t now);

    std::vector<std::string> allUsers() const;

    void erase(const std::string& user);

    void ban(const std::string& user, const std::string& reason, std::int64_t now);

    struct Ban {
        std::string reason;
        std::int64_t bannedAt = 0;
    };

    std::optional<Ban> peekBan(const std::string& user) const;

    void unban(const std::string& user);

private:
    std::filesystem::path grantPath(const std::string& user) const;
    std::filesystem::path banPath(const std::string& user) const;

    std::filesystem::path root_;
    mutable std::mutex mutex_;
};

}  // namespace bazarish::service
