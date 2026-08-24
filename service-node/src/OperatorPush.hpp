// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace bazarish {
class Identity;
}

namespace bazarish::service {

// The service node's operator channel to the messaging server: requests signed
// with the node's own identity, which the backend authorises by fingerprint.
// Carries the two things the node owns and the messaging server must obey - the
// user's client-owned offline I2P transient (an empty one revokes) and the
// storage quota their subscription grants. Best effort: a failed push is
// swallowed (the next subscribe/delegation re-pushes). A no-op when not
// configured (empty base URL).
class OperatorPush {
public:
    OperatorPush(std::string baseUrl, const Identity& signer,
        std::string destPath = "/v1/messaging/i2p-dest",
        std::string quotaPath = "/v1/messaging/quota");

    // Provisions (non-empty transient) or revokes (empty transient) a user's
    // destination. Returns whether the push was accepted (false on no-op or any
    // failure).
    bool publish(const std::string& user, const std::string& transientB64,
        std::int64_t expiresUnix) const;
    // What the messaging server holds for a user: the mailbox as it stands and
    // how many devices are collecting it. The node has neither number - it owns
    // the account, the messaging server owns the mail. Nullopt when the server
    // is not configured or did not answer.
    struct AccountUsage {
        std::uint64_t usedBytes = 0;
        std::uint64_t quotaBytes = 0;
        std::size_t devices = 0;
    };
    std::optional<AccountUsage> accountUsage(const std::string& user) const;

    // Sets the user's mailbox quota to what their subscription granted, so the
    // messaging server stops falling back to its own default and the two numbers
    // cannot drift apart.
    bool publishQuota(const std::string& user, std::uint64_t quotaBytes) const;

    // Rotating a user's serving sealing key on the messaging server, in the two
    // phases the switch needs: the prepared key is returned (base64 SPKI) for the
    // user to sign into a card, and only the commit puts it in force. Nullopt /
    // false when the server did not answer or had nothing prepared.
    std::optional<std::string> prepareServingKey(const std::string& user) const;
    bool commitServingKey(const std::string& user) const;

private:
    // One signed PUT of a JSON body to the messaging server; the answer's body
    // when it was accepted, nothing when it was not.
    std::optional<std::string> putBody(const std::string& path, const std::string& bodyText) const;
    bool put(const std::string& path, const std::string& bodyText) const;

    std::string baseUrl_;  // http://host:port, empty disables
    const Identity& signer_;
    std::string destPath_;
    std::string quotaPath_;
    std::string servingKeyPath_ = "/v1/messaging/serving-key";
};

}  // namespace bazarish::service
