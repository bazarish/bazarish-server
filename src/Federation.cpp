// Bazarish project (c) 2026
#include "Federation.hpp"

#include "FederationRateLimiter.hpp"

#include <bazarish/Cms.hpp>
#include <bazarish/Resolve.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace bazarish::server {

namespace {

// Reads a newline-terminated header line from the stream.
std::string readHeaderLine(SamStream& stream)
{
    std::string line;
    char c = 0;
    while (true) {
        stream.readExact(&c, 1);
        if (c == '\n') {
            break;
        }
        line.push_back(c);
        if (line.size() > 64 * 1024) {
            throw std::runtime_error("federation header line too long");
        }
    }
    return line;
}

void writeHeaderLine(SamStream& stream, const std::string& line)
{
    const std::string framed = line + "\n";
    stream.writeAll(framed.data(), framed.size());
}

}  // namespace

FederationDeliverResult federationSendDeliver(
    SamStream& stream, const Bytes& sealed, const Bytes& payload)
{
    const nlohmann::json header = {
        {"op", "deliver"},
        {"sealed", toBase64(sealed)},
        {"len", payload.size()},
    };
    writeHeaderLine(stream, header.dump());
    if (!payload.empty()) {
        stream.writeAll(payload.data(), payload.size());
    }
    // No half-close: the framing is length-prefixed both ways, and SAM
    // propagates a SHUT_WR as a full stream teardown.

    const nlohmann::json reply = nlohmann::json::parse(readHeaderLine(stream));
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

FederationFetchResult federationSendFetch(
    SamStream& stream, const std::string& op, const Bytes& sealed)
{
    const nlohmann::json header = {{"op", op}, {"sealed", toBase64(sealed)}};
    writeHeaderLine(stream, header.dump());

    const nlohmann::json reply = nlohmann::json::parse(readHeaderLine(stream));
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

void federationServeOnce(SamStream& stream, DeliveryEngine& engine, const std::int64_t now,
    const std::string& peerDest, FederationRateLimiter* const limiter, const Key* const sealingKey,
    const GetCardFn& getCard)
{
    if (limiter != nullptr && !limiter->allow(peerDest, now)) {
        // Over the per-peer rate limit: drop the connection without serving.
        return;
    }
    const nlohmann::json header = nlohmann::json::parse(readHeaderLine(stream));
    const std::string op = header.at("op").get<std::string>();

    if (op == "deliver") {
        const Bytes sealed = fromBase64(header.at("sealed").get<std::string>());
        const std::size_t length = header.at("len").get<std::size_t>();

        Bytes payload(length);
        if (length > 0) {
            stream.readExact(payload.data(), length);
        }

        const DeliveryEngine::Outcome outcome = engine.deliver(
            sealed, payload, now, sealingKey != nullptr ? *sealingKey : engine.sealingKey());
        nlohmann::json reply = {{"delivered", outcome.delivered}};
        if (!outcome.delivered) {
            reply["errorCode"] = outcome.errorCode;
            reply["errorMessage"] = outcome.errorMessage;
        }
        writeHeaderLine(stream, reply.dump());
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
                const Bytes sealedResponse
                    = cms::seal(Bytes(responseJson.begin(), responseJson.end()),
                        Key::fromPublicDer(query.responseKeyDer));
                writeHeaderLine(stream,
                    nlohmann::json({{"ok", true}, {"sealed", toBase64(sealedResponse)}}).dump());
                return;
            }
        }
        writeHeaderLine(
            stream, nlohmann::json({{"ok", false}, {"errorCode", "CARD_UNKNOWN"}}).dump());
        return;
    }

    throw std::runtime_error("unknown federation op");
}

}  // namespace bazarish::server
