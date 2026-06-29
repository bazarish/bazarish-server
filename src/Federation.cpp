// Bazarish project (c) 2026
#include "Federation.hpp"

#include <bazarish/Cms.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Resolve.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace bazarish::server {

std::string buildFederationDeliverHeader(const Bytes& sealed, const std::size_t payloadLen)
{
    const nlohmann::json header = {
        {"op", "deliver"},
        {"sealed", toBase64(sealed)},
        {"len", payloadLen},
    };
    return header.dump();
}

FederationDeliverResult parseFederationDeliverReply(const std::string& line)
{
    const nlohmann::json reply = nlohmann::json::parse(line);
    FederationDeliverResult result;
    result.delivered = reply.at("delivered").get<bool>();
    if (reply.contains("errorCode")) {
        result.errorCode = reply.at("errorCode").get<std::string>();
    }
    if (reply.contains("errorMessage")) {
        result.errorMessage = reply.at("errorMessage").get<std::string>();
    }
    return result;
}

std::string buildFederationFetchHeader(const std::string& op, const Bytes& sealed)
{
    const nlohmann::json header = {{"op", op}, {"sealed", toBase64(sealed)}};
    return header.dump();
}

std::string buildFederationDeliveredAck(
    const std::string& messageId, const Bytes& signerPublicDer, const Bytes& signature)
{
    const nlohmann::json header = {
        {"op", "delivered-ack"},
        {"messageId", messageId},
        {"signerPub", toBase64(signerPublicDer)},
        {"sig", toBase64(signature)},
    };
    return header.dump();
}

FederationFetchResult parseFederationFetchReply(const std::string& line)
{
    const nlohmann::json reply = nlohmann::json::parse(line);
    FederationFetchResult result;
    result.ok = reply.at("ok").get<bool>();
    if (reply.contains("sealed")) {
        result.sealed = fromBase64(reply.at("sealed").get<std::string>());
    }
    if (reply.contains("errorCode")) {
        result.errorCode = reply.at("errorCode").get<std::string>();
    }
    if (reply.contains("errorMessage")) {
        result.errorMessage = reply.at("errorMessage").get<std::string>();
    }
    return result;
}

void federationServeFrame(const std::string& headerLine,
    const std::function<Bytes(std::size_t)>& readPayload,
    const std::function<void(const std::string&)>& writeReply, DeliveryEngine& engine,
    const std::int64_t now, const Key* const sealingKey, const GetCardFn& getCard,
    const OnDeliveredFn& onDelivered, const OnAckFn& onAck)
{
    const nlohmann::json header = nlohmann::json::parse(headerLine);
    const std::string op = header.at("op").get<std::string>();

    if (op == "deliver") {
        const Bytes sealed = fromBase64(header.at("sealed").get<std::string>());
        const std::size_t length = header.at("len").get<std::size_t>();
        // DIAGNOSTIC (temporary): pinpoint where an inbound deliver dies - reading the
        // payload off the (possibly flaky) stream, the engine, or writing the reply.
        bazarish::log::warn("fed-serve: deliver in, payload {} bytes; reading...", length);
        const Bytes payload = readPayload(length);
        bazarish::log::warn("fed-serve: payload read OK ({} bytes); engine.deliver...", payload.size());

        const DeliveryEngine::Outcome outcome = engine.deliver(
            sealed, payload, now, sealingKey != nullptr ? *sealingKey : engine.sealingKey());
        bazarish::log::warn("fed-serve: engine done (delivered={}, err='{}'); writing reply",
            outcome.delivered, outcome.errorCode);
        nlohmann::json reply = {{"delivered", outcome.delivered}};
        if (!outcome.delivered) {
            reply["errorCode"] = outcome.errorCode;
            reply["errorMessage"] = outcome.errorMessage;
        }
        // Reply on the accepted stream FIRST, then trigger the delivered-ack.
        // onDelivered sends the signed ack over a FRESH outbound connection, which on
        // a slow path can take seconds to dial; running it before the reply would
        // hold the reply past the sender's read timeout - the sender then reads a
        // stream EOF and retries a message we already stored - and would stall this
        // destination's single accept loop for every later inbound delivery. The
        // synchronous reply stays best-effort; the signed delivered-ack the caller
        // receives over its own dest remains the authoritative confirmation.
        writeReply(reply.dump());
        bazarish::log::warn("fed-serve: reply written ({})", outcome.delivered ? "delivered" : "rejected");
        if (outcome.delivered && onDelivered) {
            onDelivered(outcome.messageId);
        }
        return;
    }

    if (op == "delivered-ack") {
        // The recipient server confirms it stored a message we sent. Verify the
        // signature over the messageId with the included key (self-consistent);
        // the messageId itself is the capability - only a server that unsealed our
        // envelope could know it - so this authenticates the confirmation.
        const std::string messageId = header.at("messageId").get<std::string>();
        const Bytes signerPub = fromBase64(header.at("signerPub").get<std::string>());
        const Bytes signature = fromBase64(header.at("sig").get<std::string>());
        const Bytes signedBytes(messageId.begin(), messageId.end());
        bool valid = false;
        try {
            valid = bazarish::verify(Key::fromPublicDer(signerPub), signedBytes, signature);
        } catch (const std::exception&) {
            valid = false;
        }
        if (valid && onAck) {
            onAck(messageId);
        }
        return;  // no reply: the sender drains until we close
    }

    if (op == "card") {
        // First-contact card fetch: unseal the query with this destination's
        // serving key, look up the requested user's contact card, and seal the
        // response to the query's ephemeral response key.
        const Bytes sealedQuery = fromBase64(header.at("sealed").get<std::string>());
        if (getCard) {
            const Key& key = sealingKey != nullptr ? *sealingKey : engine.sealingKey();
            const CardFetchQuery query
                = cardFetchQueryFromJson(nlohmann::json::parse(cms::unseal(sealedQuery, key)));
            const std::optional<Bytes> certDer = getCard(query.fingerprint);
            if (certDer) {
                const std::string responseJson = toJson(CardFetchResponse{*certDer}).dump();
                const Bytes sealedResponse = cms::seal(Bytes(responseJson.begin(), responseJson.end()),
                    Key::fromPublicDer(query.responseKeyDer));
                writeReply(nlohmann::json({{"ok", true}, {"sealed", toBase64(sealedResponse)}}).dump());
                return;
            }
        }
        writeReply(nlohmann::json({{"ok", false}, {"errorCode", "CARD_UNKNOWN"}}).dump());
        return;
    }

    throw std::runtime_error("unknown federation op");
}

}  // namespace bazarish::server
