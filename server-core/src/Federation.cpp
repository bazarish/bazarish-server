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
        // The length is the peer's word. What is done with it is bounded by the
        // reader, which never allocates more than a message may be: the refusal
        // that follows is the engine's, and it travels back as a typed answer
        // rather than as a stream closed under a sender still writing.
        const Bytes payload = readPayload(length);

        const DeliveryEngine::Outcome outcome = engine.deliver(sealed, payload, now,
            sealingKey != nullptr ? *sealingKey : engine.sealingKey(), owner);
        nlohmann::json reply = {{"delivered", outcome.delivered}};
        if (!outcome.delivered) {
            reply["errorCode"] = outcome.errorCode;
            reply["errorMessage"] = outcome.errorMessage;
        }
        // The confirmation goes home on this stream, signed with the key of the
        // destination that took the delivery. It used to be dialled back to the
        // sender on a connection of its own, because a reply lost on a flaky return
        // leg left the sender unsure about a message that had in fact been stored.
        // The sender now dials from a one-time destination nobody can dial back, and
        // a lost reply is answered by its own spool: the retry arrives here, is
        // recognised by its deliveryId and confirmed again.
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
        // First-contact card fetch. The query names the fingerprint and returns
        // the descriptor's view capability; both it and the answer travel in the
        // clear, because this only ever arrives over a direct I2P stream, which
        // is already encrypted and authenticated to this destination.
        //
        // A destination answers for the one user it belongs to, and for nobody
        // else. Without that check any destination of a node answers for any
        // fingerprint the node serves, which turns every published address into
        // an oracle: hold two invites, ask one destination for the other's card,
        // and a "yes" says the two are served by the same server. That is the
        // co-location signal this protocol treats as a critical fault. The
        // capability the query carries does not help - it is the account-wide
        // view, and it rides in the routing block of every message a contact
        // ever receives.
        //
        // Nothing legitimate is refused by this: a card is fetched by dialling
        // the destination of the very account whose card is wanted.
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
