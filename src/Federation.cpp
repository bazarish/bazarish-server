// Bazarish project (c) 2026
#include "Federation.hpp"

#include <bazarish/Cms.hpp>
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
    const std::int64_t now, const Key* const sealingKey, const GetCardFn& getCard)
{
    const nlohmann::json header = nlohmann::json::parse(headerLine);
    const std::string op = header.at("op").get<std::string>();

    if (op == "deliver") {
        const Bytes sealed = fromBase64(header.at("sealed").get<std::string>());
        const std::size_t length = header.at("len").get<std::size_t>();
        const Bytes payload = readPayload(length);

        const DeliveryEngine::Outcome outcome = engine.deliver(
            sealed, payload, now, sealingKey != nullptr ? *sealingKey : engine.sealingKey());
        nlohmann::json reply = {{"delivered", outcome.delivered}};
        if (!outcome.delivered) {
            reply["errorCode"] = outcome.errorCode;
            reply["errorMessage"] = outcome.errorMessage;
        }
        writeReply(reply.dump());
        return;
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
