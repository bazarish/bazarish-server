// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"

#include <bazarish/Log.hpp>

#include <bazarish/Address.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Pass.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace bazarish::server {

namespace {

constexpr std::size_t kRefusedPassPrefixChars = 12;

}  // namespace

DeliveryEngine::DeliveryEngine(Storage& storage, std::string serverFingerprint,
    std::shared_ptr<const Key> sealingKey, const DeliveryEngineOptions options)
    : storage_(storage)
    , serverFingerprint_(std::move(serverFingerprint))
    , sealingKey_(std::move(sealingKey))
    , options_(options)
    , contactSources_(kContactSourceMemorySeconds)
    , mailPerPass_(kMailPerPassPerMinute, kSecondsPerMinute)
{
}

const std::string& DeliveryEngine::serverFingerprint() const
{
    return serverFingerprint_;
}

const Key& DeliveryEngine::sealingKey() const
{
    return *sealingKey_;
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

    std::string mailbox;
    std::string deliveryClass;
    std::string deliveryId;
    Bytes pass;
    try {
        const Bytes plain = hybrid::unseal(sealed, sealingKey);
        const nlohmann::json inner = nlohmann::json::parse(plain.begin(), plain.end());
        deliveryClass = inner.at("class").get<std::string>();
        mailbox = inner.at("mailbox").get<std::string>();
        deliveryId = inner.at("deliveryId").get<std::string>();
        if (deliveryClass == kContentDeliveryClass) {
            pass = fromBase64(inner.at("pass").get<std::string>());
        } else if (deliveryClass != kContactDeliveryClass) {
            return fail(ErrorCode::eDeliveryRejected, "unknown delivery class");
        }
        if (!isFingerprint(mailbox)) {
            return fail(ErrorCode::eDeliveryRejected, "mailbox is not a fingerprint");
        }
    } catch (const std::exception&) {
        return fail(ErrorCode::eDeliveryRejected, "envelope rejected");
    }
    outcome.deliveryId = deliveryId;

    if (!owner.empty() && deliveryClass == kContactDeliveryClass) {
        if (!storage_.allowContactRequest(owner, now, kContactRequestsPerMinute)) {
            return fail(ErrorCode::eContactRateLimited,
                "this address is taking too many contact requests right now - try again shortly");
        }
        if (storage_.countHeld(owner, kContactDeliveryClass) >= kMaxPendingContactRequests) {
            bazarish::log::debug("contact request deferred: {} already holds {}",
                bazarish::log::redact(owner), kMaxPendingContactRequests);
            return fail(ErrorCode::eContactRateLimited,
                "this address has too many contact requests waiting - try again later");
        }
    }

    if (!owner.empty() && mailbox != owner) {
        if (deliveryClass == kContactDeliveryClass) {
            return delivered();
        }
        bazarish::log::debug("delivery refused: this destination is not that mailbox's");
        return fail(ErrorCode::eDeliveryRejected, "delivery rejected");
    }

    if (storage_.hasBlob(mailbox, deliveryId)) {
        return delivered();
    }

    if (storage_.hasSeen(mailbox, deliveryId)) {
        return delivered();
    }

    if (deliveryClass == kContactDeliveryClass) {
        if (payload.size() > kMaxContactRequestBytes) {
            return fail(ErrorCode::eContactRequestTooLarge,
                "contact request exceeds " + std::to_string(kMaxContactRequestBytes) + " bytes");
        }
    } else if (!storage_.hasPass(mailbox, sha256(pass))) {
        bazarish::log::debug("delivery refused: pass {}... unknown for {} on {}, id {}",
            toHex(pass).substr(0, kRefusedPassPrefixChars), bazarish::log::redact(mailbox),
            owner.empty() ? std::string("the server's own address") : bazarish::log::redact(owner),
            deliveryId.substr(0, kRefusedPassPrefixChars));
        return fail(ErrorCode::eDeliveryRejected, "delivery rejected");
    }

    if (payload.size() > kMaxMessagePayloadBytes) {
        return fail(ErrorCode::eMessageTooLarge,
            "a message may carry at most " + std::to_string(kMaxMessagePayloadBytes) + " bytes");
    }

    if (deliveryClass == kContactDeliveryClass && !contactSources_.admit(peer, now)) {
        return fail(ErrorCode::eContactRateLimited,
            "this address has already sent a contact request; a request comes from an address "
            "of its own");
    }

    if (deliveryClass == kContentDeliveryClass && !mailPerPass_.allow(toHex(sha256(pass)), now)) {
        return fail(ErrorCode::eContactRateLimited,
            "this correspondent is sending more than " + std::to_string(kMailPerPassPerMinute)
                + " messages a minute - try again shortly");
    }

    const Storage::PutResult result = storage_.putBlob(mailbox, deliveryId, payload, deliveryClass,
        storage_.userQuota(mailbox, options_.defaultQuotaBytes));
    if (result == Storage::PutResult::eQuotaExceeded) {
        if (deliveryClass == kContentDeliveryClass) {
            return fail(ErrorCode::eStorageFull, "recipient storage quota is exhausted");
        }
        bazarish::log::debug("delivery refused: mailbox is full and this is not content");
        return fail(ErrorCode::eDeliveryRejected, "delivery rejected");
    }

    storage_.markSeen(mailbox, deliveryId, now);
    if (options_.onDelivered) {
        options_.onDelivered(mailbox);
    }
    return delivered();
}

}  // namespace bazarish::server
