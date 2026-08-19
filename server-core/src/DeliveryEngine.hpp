// Bazarish project (c) 2026
#pragma once

#include "Storage.hpp"

#include <bazarish/Crypto.hpp>

#include <cstdint>
#include <functional>
#include <string>

namespace bazarish::server {

struct DeliveryEngineOptions {
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
    // Cap on a TOKENLESS contact-class payload (the delivered, CMS-sealed bytes).
    // The contact class carries one kind of tokenless delivery, the contact request:
    // bootstrap (hybrid sealing prekey + dest + serving key) plus a 64-token reply
    // batch, ~8 KB sealed with the hybrid PQ keys. Sized to fit that with headroom;
    // tokenless deliveries remain rate-limited and quota-bound.
    std::uint64_t contactRequestLimitBytes = 16 * 1024;
    // Called with the recipient's fingerprint the moment a delivery lands, so a
    // client holding a long-poll open is answered instead of waiting out its
    // timeout. Empty when nobody is listening (tests, or a node without the
    // event face).
    std::function<void(const std::string& user)> onDelivered;
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
        // The delivery messageId parsed from the envelope (set whenever the
        // envelope parsed, even on a dedup hit), so the caller can acknowledge it
        // back to the sending server.
        std::string messageId;
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
