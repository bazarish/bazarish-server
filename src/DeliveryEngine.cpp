// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Tokens.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace bazarish::server {

DeliveryEngine::DeliveryEngine(Storage& storage, std::string serverFingerprint, Key sealingKey,
    const DeliveryEngineOptions options)
    : storage_(storage)
    , serverFingerprint_(std::move(serverFingerprint))
    , sealingKey_(std::move(sealingKey))
    , options_(options)
{
}

const std::string& DeliveryEngine::serverFingerprint() const
{
    return serverFingerprint_;
}

const Key& DeliveryEngine::sealingKey() const
{
    return sealingKey_;
}

DeliveryEngine::Outcome DeliveryEngine::deliver(
    const Bytes& sealed, const Bytes& payload, const std::int64_t now)
{
    Outcome outcome;
    const auto fail = [&outcome](const ErrorCode code, const std::string& message) {
        outcome.delivered = false;
        outcome.errorCode = std::string(toString(code));
        outcome.errorMessage = message;
        return outcome;
    };
    const auto delivered = [&outcome]() {
        outcome.delivered = true;
        return outcome;
    };

    // Anti-enumeration: every structural or admission failure below
    // collapses into DELIVERY_REJECTED; only token holders see the
    // detailed quota errors.
    std::string mailbox;
    std::string kind;
    std::string messageId;
    Bytes token;
    try {
        const Bytes plain = cms::unseal(sealed, sealingKey_);
        const nlohmann::json inner = nlohmann::json::parse(plain.begin(), plain.end());
        kind = inner.at("kind").get<std::string>();
        mailbox = inner.at("mailbox").get<std::string>();
        messageId = inner.at("messageId").get<std::string>();
        if (kind == "message") {
            token = fromBase64(inner.at("token").get<std::string>());
        } else if (kind != "contact-request") {
            return fail(ErrorCode::kDeliveryRejected, "unknown delivery kind");
        }
        if (!isFingerprint(mailbox)) {
            return fail(ErrorCode::kDeliveryRejected, "mailbox is not a fingerprint");
        }
    } catch (const std::exception&) {
        return fail(ErrorCode::kDeliveryRejected, "envelope rejected");
    }

    // Dedup before anything else: a retry of a delivered message must
    // succeed without consuming a second token.
    if (storage_.hasBlob(mailbox, messageId)) {
        return delivered();
    }

    if (kind == "contact-request") {
        if (payload.size() > options_.contactRequestLimitBytes) {
            return fail(ErrorCode::kContactRequestTooLarge,
                "contact request exceeds " + std::to_string(options_.contactRequestLimitBytes)
                    + " bytes");
        }
    } else {
        if (token.size() != kDeliveryTokenSize
            || !storage_.consumeTokenHash(mailbox, deliveryTokenHash(token))) {
            return fail(ErrorCode::kDeliveryRejected, "delivery rejected");
        }
    }

    const Storage::PutResult result = storage_.putBlob(
        mailbox, messageId, payload, kind, now, options_.defaultQuotaBytes);
    if (result == Storage::PutResult::kQuotaExceeded) {
        if (kind == "message") {
            // The store did not happen: restore the token so the sender
            // can retry after the recipient frees space.
            storage_.registerTokenHashes(mailbox, {deliveryTokenHash(token)});
            return fail(ErrorCode::kStorageFull, "recipient storage quota is exhausted");
        }
        return fail(ErrorCode::kDeliveryRejected, "delivery rejected");
    }
    return delivered();
}

}  // namespace bazarish::server
