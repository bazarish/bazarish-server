// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"

#include <bazarish/DeliveryEnvelope.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/Log.hpp>

#include <bazarish/Address.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Pass.hpp>

#include <nlohmann/json.hpp>

namespace bazarish::server {

namespace {

constexpr std::size_t kRefusedPassPrefixChars = 12;

constexpr const char* kContactsWaitingRefusal
    = "this address has too many contact requests waiting - try again later";

}  // namespace

DeliveryEngine::DeliveryEngine(DiskStorage& storage, const DeliveryEngineOptions options)
    : storage_(storage)
    , options_(options)
    , contactSources_(kContactSourceMemorySeconds)
    , mailPerPass_(kMailPerPassPerMinute, kSecondsPerMinute)
{
}

DeliveryEngine::Outcome DeliveryEngine::deliver(
    const Bytes& sealed, const Bytes& payload, const std::int64_t now, const Key& sealingKey,
    const std::string& owner, const std::string& peer)
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

    DeliveryEnvelope envelope;
    try {
        envelope = openDeliveryEnvelope(sealed, sealingKey);
    } catch (const std::exception&) {
        return fail(ErrorCode::eDeliveryRejected, "envelope rejected");
    }
    if (envelope.deliveryClass == kContentDeliveryClass && !envelope.pass.has_value()) {
        return fail(ErrorCode::eDeliveryRejected, "envelope rejected");
    }
    if (envelope.deliveryClass != kContentDeliveryClass
        && envelope.deliveryClass != kContactDeliveryClass) {
        return fail(ErrorCode::eDeliveryRejected, "unknown delivery class");
    }
    if (!isFingerprint(envelope.mailbox)) {
        return fail(ErrorCode::eDeliveryRejected, "mailbox is not a fingerprint");
    }
    const std::string& mailbox = envelope.mailbox;
    const std::string& deliveryClass = envelope.deliveryClass;
    const std::string& deliveryId = envelope.deliveryId;
    const Bytes pass = envelope.pass.value_or(Bytes());
    outcome.deliveryId = deliveryId;

    const bool servedHere = mailbox == owner;
    if (servedHere
        && (storage_.hasBlob(mailbox, deliveryId) || storage_.hasSeen(mailbox, deliveryId))) {
        return delivered();
    }

    if (deliveryClass == kContactDeliveryClass) {
        if (!storage_.allowContactRequest(owner, now)) {
            return fail(ErrorCode::eContactRateLimited,
                "this address is taking too many contact requests right now - try again shortly");
        }
        if (storage_.countHeld(owner, kContactDeliveryClass) >= kMaxPendingContactRequests) {
            bazarish::log::debug("contact request deferred: {} already holds {}",
                bazarish::log::redact(owner), kMaxPendingContactRequests);
            return fail(ErrorCode::eContactRateLimited, kContactsWaitingRefusal);
        }
    }

    if (!servedHere) {
        if (deliveryClass == kContactDeliveryClass) {
            return delivered();
        }
        bazarish::log::debug("delivery refused: this destination is not that mailbox's");
        return fail(ErrorCode::eDeliveryRejected, "delivery rejected");
    }

    if (deliveryClass == kContactDeliveryClass) {
        if (payload.size() > kMaxContactRequestBytes) {
            return fail(ErrorCode::eContactRequestTooLarge,
                "contact request exceeds " + std::to_string(kMaxContactRequestBytes) + " bytes");
        }
    } else if (!storage_.hasPass(mailbox, sha256(pass))) {
        bazarish::log::debug("delivery refused: pass {}... unknown for {} on {}, id {}",
            toHex(pass).substr(0, kRefusedPassPrefixChars), bazarish::log::redact(mailbox),
            bazarish::log::redact(owner),
            deliveryId.substr(0, kRefusedPassPrefixChars));
        return fail(ErrorCode::eDeliveryRejected, "delivery rejected");
    }

    if (payload.size() > kMaxMessagePayloadBytes) {
        return fail(ErrorCode::eMessageTooLarge,
            "a message may carry at most " + std::to_string(kMaxMessagePayloadBytes) + " bytes");
    }

    if (deliveryClass == kContactDeliveryClass && !contactSources_.admit(owner, peer, now)) {
        return fail(ErrorCode::eContactRateLimited,
            "this address has already sent a contact request; a request comes from an address "
            "of its own");
    }

    if (deliveryClass == kContentDeliveryClass && !mailPerPass_.allow(toHex(sha256(pass)), now)) {
        return fail(ErrorCode::eContactRateLimited,
            "this correspondent is sending more than " + std::to_string(kMailPerPassPerMinute)
                + " messages a minute - try again shortly");
    }

    const std::optional<std::size_t> heldLimit = deliveryClass == kContactDeliveryClass
        ? std::optional<std::size_t>(kMaxPendingContactRequests)
        : std::nullopt;
    const DiskStorage::PutResult result = storage_.putBlob(mailbox, deliveryId, payload, deliveryClass,
        storage_.userQuota(mailbox, options_.defaultQuotaBytes), now, {}, heldLimit);
    if (result == DiskStorage::PutResult::eClassFull) {
        return fail(ErrorCode::eContactRateLimited, kContactsWaitingRefusal);
    }
    if (result == DiskStorage::PutResult::eQuotaExceeded) {
        if (deliveryClass == kContentDeliveryClass) {
            return fail(ErrorCode::eStorageFull, "recipient storage quota is exhausted");
        }
        bazarish::log::debug("contact request deferred: the mailbox of {} is full",
            bazarish::log::redact(mailbox));
        return fail(ErrorCode::eContactRateLimited, kContactsWaitingRefusal);
    }

    if (options_.onDelivered) {
        options_.onDelivered(mailbox);
    }
    return delivered();
}

}  // namespace bazarish::server
