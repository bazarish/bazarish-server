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

struct ServedDestination {
    std::string dest;
};

// The keys an account issued for its address: a node passes them to the messaging server.
struct AddressKeys {
    std::string sealingPem;
    std::string signingPem;
};

class OperatorPush {
public:
    static constexpr int kBackgroundAttempts = 3;
    static constexpr int kPromptAttempts = 1;

    struct Dial {
        std::string url;
        std::string pin;
        std::string certificate;
        std::string key;
    };

    OperatorPush(Dial backend, const Identity& signer, int attempts = kBackgroundAttempts);

    bool waitReachable(std::chrono::seconds budget) const;

    std::optional<ServedDestination> publish(const std::string& user,
        const std::string& transientB64, std::int64_t expiresUnix, const AddressKeys& keys) const;
    std::optional<MailboxUsage> accountUsage(const std::string& user) const;

    bool forgetMailbox(const std::string& user) const;

    bool publishQuota(const std::string& user, std::uint64_t quotaBytes) const;

    std::string reseedArchive() const;

private:
    std::optional<std::string> send(const std::string& method, const std::string& path,
        const std::string& target, const std::string& bodyText) const;
    std::optional<std::string> putBody(const std::string& path, const std::string& bodyText) const;
    bool put(const std::string& path, const std::string& bodyText) const;

    Dial backend_;
    const Identity& signer_;
    const int attempts_;
};

}  // namespace bazarish::service
