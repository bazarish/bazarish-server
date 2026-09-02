// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"

#include <bazarish/Log.hpp>

#include <bazarish/Address.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Limits.hpp>
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
    const Bytes& sealed, const Bytes& payload, const std::int64_t now, const Key& sealingKey,
    const std::string& owner)
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
    // Delivery class: the server-visible admission selector. A closed set of
    // exactly two values; the content type lives end-to-end and is never seen
    // here (see docs Messages.md).
    std::string deliveryClass;
    std::string deliveryId;
    Bytes token;
    try {
        const Bytes plain = cms::unseal(sealed, sealingKey);
        const nlohmann::json inner = nlohmann::json::parse(plain.begin(), plain.end());
        deliveryClass = inner.at("class").get<std::string>();
        mailbox = inner.at("mailbox").get<std::string>();
        deliveryId = inner.at("deliveryId").get<std::string>();
        if (deliveryClass == kContentDeliveryClass) {
            token = fromBase64(inner.at("token").get<std::string>());
        } else if (deliveryClass != kContactDeliveryClass) {
            return fail(ErrorCode::eDeliveryRejected, "unknown delivery class");
        }
        if (!isFingerprint(mailbox)) {
            return fail(ErrorCode::eDeliveryRejected, "mailbox is not a fingerprint");
        }
    } catch (const std::exception&) {
        return fail(ErrorCode::eDeliveryRejected, "envelope rejected");
    }
    // Expose the parsed id so the caller can acknowledge it (even a dedup hit).
    outcome.deliveryId = deliveryId;

    // The tokenless path is bounded on the destination this arrived on - not on
    // the mailbox the envelope names. That is what lets the refusal be explicit:
    // the answer cannot depend on whether the named mailbox is the right one, so
    // it says nothing about who is served here, and a real contact request is
    // told to come back instead of vanishing.
    if (!owner.empty() && deliveryClass == kContactDeliveryClass
        && !storage_.allowContactRequest(owner, now, kContactRequestsPerMinute)) {
        return fail(ErrorCode::eContactRateLimited,
            "this address is taking too many contact requests right now - try again shortly");
    }

    // The destination this arrived on belongs to one user, and only their mail
    // belongs in it. Anything else is dropped here - before the dedup and the
    // seen-cache, which must not be touched: marking a foreign deliveryId seen
    // would let anyone censor a real message by delivering its id to the wrong
    // destination first.
    if (!owner.empty() && mailbox != owner) {
        if (deliveryClass == kContactDeliveryClass) {
            // Tokenless, so there is nothing to fail on: answering anything but
            // "delivered" would say whose destination this is. It goes nowhere.
            return delivered();
        }
        // The client is told nothing that would say whose destination this is;
        // the server writes down which of the three refusals it was, because
        // otherwise a rejected delivery leaves no trace anywhere and the two
        // sides can only guess.
        bazarish::log::debug("delivery refused: this destination is not that mailbox's");
        return fail(ErrorCode::eDeliveryRejected, "delivery rejected");
    }

    // Dedup before anything else: a retry of a delivered message must
    // succeed without consuming a second token.
    if (storage_.hasBlob(mailbox, deliveryId)) {
        return delivered();
    }

    // Replay protection: a deliveryId admitted earlier - even one since fetched,
    // acked and swept from the mailbox - must not be re-admitted. The one-time
    // token already guards content replays, but a tokenless contact request has
    // no token to spend, so the seen-cache is what closes that gap. Idempotent
    // success: no token spend, no second store.
    if (storage_.hasSeen(mailbox, deliveryId)) {
        return delivered();
    }

    // One message carries a message. Anything larger is a file, which travels
    // client to client and never enters a mailbox - so the limit is the
    // protocol's, not an operator's, and it is checked before any token is spent.
    if (payload.size() > kMaxMessagePayloadBytes) {
        return fail(ErrorCode::eMessageTooLarge,
            "a message may carry at most " + std::to_string(kMaxMessagePayloadBytes) + " bytes");
    }

    if (deliveryClass == kContactDeliveryClass) {
        if (payload.size() > kMaxContactRequestBytes) {
            return fail(ErrorCode::eContactRequestTooLarge,
                "contact request exceeds " + std::to_string(kMaxContactRequestBytes) + " bytes");
        }
    } else {
        if (token.size() != kDeliveryTokenSize || !storage_.consumeToken(mailbox, token)) {
            bazarish::log::debug("delivery refused: {} for {}",
                token.size() != kDeliveryTokenSize ? "malformed delivery token"
                                                   : "delivery token not accepted (unknown or "
                                                     "already spent)",
                bazarish::log::redact(mailbox));
            return fail(ErrorCode::eDeliveryRejected, "delivery rejected");
        }
    }

    const Storage::PutResult result = storage_.putBlob(mailbox, deliveryId, payload, deliveryClass,
        now, storage_.userQuota(mailbox, options_.defaultQuotaBytes));
    if (result == Storage::PutResult::eQuotaExceeded) {
        if (deliveryClass == "content") {
            // The store did not happen: restore the token so the sender
            // can retry after the recipient frees space.
            storage_.registerTokens(mailbox, {token});
            return fail(ErrorCode::eStorageFull, "recipient storage quota is exhausted");
        }
        bazarish::log::debug("delivery refused: mailbox is full and this is not content");
        return fail(ErrorCode::eDeliveryRejected, "delivery rejected");
    }

    // Record the admitted deliveryId so a later replay (after this blob is acked
    // and swept) is recognised by the hasSeen check above and refused.
    storage_.markSeen(mailbox, deliveryId, now);
    if (options_.onDelivered) {
        options_.onDelivered(mailbox);  // wake whoever is holding a request open
    }
    return delivered();
}

}  // namespace bazarish::server
