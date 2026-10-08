// Bazarish project (c) 2026
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace bazarish {
class Identity;
}

namespace bazarish::service {

struct MailboxUsage {
    std::uint64_t usedBytes = 0;
    std::uint64_t quotaBytes = 0;
    std::size_t devices = 0;
};

class OperatorPush {
public:
    static constexpr int kBackgroundAttempts = 3;
    static constexpr int kPromptAttempts = 1;

    OperatorPush(
        std::string baseUrl, const Identity& signer, int attempts = kBackgroundAttempts);

    bool waitReachable(std::chrono::seconds budget) const;

    bool publish(const std::string& user, const std::string& transientB64,
        std::int64_t expiresUnix) const;
    std::optional<MailboxUsage> accountUsage(const std::string& user) const;

    bool forgetMailbox(const std::string& user) const;

    bool publishQuota(const std::string& user, std::uint64_t quotaBytes) const;


private:
    std::optional<std::string> send(const std::string& method, const std::string& path,
        const std::string& target, const std::string& bodyText) const;
    std::optional<std::string> putBody(const std::string& path, const std::string& bodyText) const;
    bool put(const std::string& path, const std::string& bodyText) const;

    std::string baseUrl_;
    const Identity& signer_;
    const int attempts_;
};

}  // namespace bazarish::service
