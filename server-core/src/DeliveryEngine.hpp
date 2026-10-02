// Bazarish project (c) 2026
#pragma once

#include "Storage.hpp"

#include <bazarish/Crypto.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace bazarish::server {

struct DeliveryEngineOptions {
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
    // Called with the recipient's fingerprint the moment a delivery lands, so a
    // client holding a long-poll open is answered instead of waiting out its
    // timeout. Empty when nobody is listening (tests, or a node without the
    // event face).
    std::function<void(const std::string& user)> onDelivered;
};

// The delivery pipeline for one server: unseal the envelope, deduplicate by
// deliveryId, admit it on the delivery pass it presents (or as a contact request,
// which presents none), check size and quota, store. Shared by every destination's
// accept loop - they all end at the same mailbox rules.
class DeliveryEngine {
public:
    // sealingKey is the default serving key, shared rather than copied: a key
    // round-tripped through its own PEM is a second copy of a secret and a second
    // place to forget to wipe it.
    DeliveryEngine(Storage& storage, std::string serverFingerprint,
        std::shared_ptr<const Key> sealingKey, DeliveryEngineOptions options);

    struct Outcome {
        bool delivered = false;
        // Empty when delivered; otherwise a typed error code string.
        std::string errorCode;
        std::string errorMessage;
        // The delivery deliveryId parsed from the envelope (set whenever the
        // envelope parsed, even on a dedup hit), so the caller can acknowledge it
        // back to the sending server.
        std::string deliveryId;
    };

    // sealed is the CMS envelope addressed to the serving sealing key of the
    // destination it arrived on; payload is the opaque E2E blob. The caller
    // (each accept loop / the local send path) supplies the sealing key for
    // that destination - every per-user destination has its own (see docs-main
    // api/InviteAnonymity.md). now is unix seconds.
    //
    // owner is the user that destination belongs to. Mail addressed to anyone else
    // does not belong here: a contact request is answered exactly as a delivered
    // one and dropped without touching anything (refusing it would answer "whose
    // destination is this?"), and a content delivery is refused like any other bad
    // admission. Empty owner disables the check, for callers that operate no
    // destination.
    Outcome deliver(const Bytes& sealed, const Bytes& payload, std::int64_t now,
        const Key& sealingKey, const std::string& owner = {});

    const std::string& serverFingerprint() const;
    // The default serving sealing key, for callers that operate no destination
    // of their own.
    const Key& sealingKey() const;

private:
    Storage& storage_;
    const std::string serverFingerprint_;
    const std::shared_ptr<const Key> sealingKey_;
    const DeliveryEngineOptions options_;
};

}  // namespace bazarish::server
