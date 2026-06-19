// Bazarish project (c) 2026
#pragma once

#include "Storage.hpp"

#include <bazarish/Crypto.hpp>

#include <cstdint>
#include <string>

namespace bazarish::server {

struct DeliveryEngineOptions {
    std::uint64_t defaultQuotaBytes = 10 * 1024 * 1024;
    std::uint64_t contactRequestLimitBytes = 256;
};

// The delivery pipeline for one server: unseal the envelope, deduplicate by
// messageId, consume a one-time token (or admit a contact request), check
// size/quota and store. Shared by local sends (sender == this server) and
// incoming federation deliveries - both end at the same mailbox rules.
class DeliveryEngine {
public:
    DeliveryEngine(Storage& storage, std::string serverFingerprint, Key sealingKey,
        DeliveryEngineOptions options);

    struct Outcome {
        bool delivered = false;
        // Empty when delivered; otherwise a typed error code string.
        std::string errorCode;
        std::string errorMessage;
    };

    // sealed is the CMS envelope addressed to the serving sealing key of the
    // destination it arrived on; payload is the opaque E2E blob. The caller
    // (each accept loop / the local send path) supplies the sealing key for
    // that destination - a home/pool/per-user destination each has its own (see
    // docs-main api/InviteAnonymity.md). now is unix seconds.
    Outcome deliver(
        const Bytes& sealed, const Bytes& payload, std::int64_t now, const Key& sealingKey);

    const std::string& serverFingerprint() const;
    // The home destination's serving sealing key (also the default for callers
    // that operate only the home destination).
    const Key& sealingKey() const;

private:
    Storage& storage_;
    const std::string serverFingerprint_;
    const Key sealingKey_;
    const DeliveryEngineOptions options_;
};

}  // namespace bazarish::server
