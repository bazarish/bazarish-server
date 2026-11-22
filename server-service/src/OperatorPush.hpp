// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/HttpClient.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
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

enum class PushOutcome {
    eDelivered,
    eRefused,
    eUnreachable,
};

struct AddressKeys {
    std::string sealingPem;
    std::string signingPem;
};

class OperatorPush {
public:
    struct Dial {
        std::string url;
        std::string pin;
        std::string certificate;
        std::string key;
    };

    OperatorPush(Dial backend, const Identity& signer, std::function<void()> answered = {});

    std::optional<ServedDestination> publish(const std::string& user,
        const std::string& transientB64, std::int64_t expiresUnix, const AddressKeys& keys) const;
    std::optional<MailboxUsage> accountUsage(const std::string& user) const;

    PushOutcome publishQuota(const std::string& user, std::uint64_t quotaBytes) const;
    PushOutcome publishCardChanged(const std::string& user) const;
    PushOutcome takeDownAddress(const std::string& user) const;
    PushOutcome forgetAccount(const std::string& user) const;

    std::string reseedArchive() const;

    std::optional<Bytes> nodeCard(const Bytes& sealingPublicKeyDer) const;

private:
    bazarish::http::ClientResponse call(
        const std::string& method, const std::string& pathAndQuery, const std::string& body) const;
    struct Answer {
        PushOutcome outcome = PushOutcome::eUnreachable;
        std::string body;
    };
    Answer exchange(const std::string& method, const std::string& path,
        const std::string& target, const std::string& bodyText) const;
    std::optional<std::string> send(const std::string& method, const std::string& path,
        const std::string& target, const std::string& bodyText) const;
    std::optional<std::string> putBody(const std::string& path, const std::string& bodyText) const;

    Dial backend_;
    const Identity& signer_;
    const std::function<void()> answered_;
};

}  // namespace bazarish::service
