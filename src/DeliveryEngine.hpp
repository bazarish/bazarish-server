// Bazarish project (c) 2026
#pragma once

#include "Storage.hpp"

#include <bazarish/Crypto.hpp>

#include <cstdint>
#include <string>

namespace bazarish::server {

struct DeliveryEngineOptions {
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
    // Cap on a TOKENLESS contact-class payload (the delivered, CMS-sealed bytes).
    // The contact class carries two kinds of tokenless delivery, and the server sees
    // only opaque sealed bytes so it cannot tell them apart - one cap covers both:
    //   - a contact request: bootstrap (hybrid sealing prekey + dest + serving key)
    //     plus a 64-token reply batch, ~8 KB sealed with the hybrid PQ keys;
    //   - a group.roster / group.tokens broadcast: the signed roster carries EVERY
    //     member's hybrid (ML-KEM / ML-DSA) routing keys plus a hybrid signature, so
    //     it grows ~3-4 KB per member and reaches hundreds of KB for a large group.
    // The old 8 KB cap fit a contact request but rejected any roster past ~2 members,
    // so adding members to a group failed ("contact request exceeds 8192 bytes") and
    // existing members never got the roster update. Sized for the ~100-member group
    // target. Tokenless deliveries remain rate-limited and quota-bound. (A future
    // optimisation could externalise an oversized roster to a blob pointer, like a
    // large content message, and keep this cap tight.)
    std::uint64_t contactRequestLimitBytes = 512 * 1024;
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
