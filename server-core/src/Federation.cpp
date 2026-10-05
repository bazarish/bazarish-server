// Bazarish project (c) 2026
#include "Federation.hpp"
#include <bazarish/Log.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Limits.hpp>

#include <bazarish/Cms.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Resolve.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace bazarish::server {

void federationServeFrame(const std::string& headerLine,
    const std::function<Bytes(std::size_t)>& readPayload,
    const std::function<void(const std::string&)>& writeReply, DeliveryEngine& engine,
    const std::int64_t now, const Key* const sealingKey, const std::string& owner,
    const GetCardFn& getCard, const SignAckFn& signAck)
{
    const nlohmann::json header = nlohmann::json::parse(headerLine);
    const std::string op = header.at("op").get<std::string>();

    if (op == "deliver") {
        const Bytes sealed = fromBase64(header.at("sealed").get<std::string>());
        const std::size_t length = header.at("len").get<std::size_t>();
        const Bytes payload = readPayload(length);

        const DeliveryEngine::Outcome outcome = engine.deliver(sealed, payload, now,
            sealingKey != nullptr ? *sealingKey : engine.sealingKey(), owner);
        nlohmann::json reply = {{"delivered", outcome.delivered}};
        if (!outcome.delivered) {
            reply["errorCode"] = outcome.errorCode;
            reply["errorMessage"] = outcome.errorMessage;
        }
        if (outcome.delivered && signAck && !outcome.deliveryId.empty()) {
            Bytes signerPublicDer;
            Bytes signature;
            signAck(outcome.deliveryId, signerPublicDer, signature);
            if (!signature.empty()) {
                reply["deliveryId"] = outcome.deliveryId;
                reply["signerPub"] = toBase64(signerPublicDer);
                reply["sig"] = toBase64(signature);
            }
        }
        writeReply(reply.dump());
        return;
    }

    if (op == "card") {
        if (getCard) {
            const Bytes queryBytes = fromBase64(header.at("sealed").get<std::string>());
            const CardFetchQuery query = cardFetchQueryFromJson(nlohmann::json::parse(queryBytes));
            if (!owner.empty() && query.fingerprint != owner) {
                writeReply(
                    nlohmann::json({{"ok", false}, {"errorCode", "CARD_UNKNOWN"}}).dump());
                return;
            }
            const std::optional<Bytes> cardDer = getCard(query.fingerprint, query.view);
            if (cardDer) {
                writeReply(
                    nlohmann::json({{"ok", true}, {"sealed", toBase64(*cardDer)}}).dump());
                return;
            }
        }
        writeReply(nlohmann::json({{"ok", false}, {"errorCode", "CARD_UNKNOWN"}}).dump());
        return;
    }

    throw std::runtime_error("unknown federation op");
}

}  // namespace bazarish::server
