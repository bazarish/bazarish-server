// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"

#include <bazarish/Resolve.hpp>
#include "FederationRateLimiter.hpp"

#include <bazarish/Bytes.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>

namespace bazarish::server {

// Server-to-server framing over an I2P stream (any type exposing
// readExact/writeAll, e.g. bazarish::i2p::Stream or a test double):
//   deliver request: one JSON header line "{op:deliver,sealed,len}\n" + len bytes
//   deliver reply:   one JSON line "{delivered,errorCode,errorMessage}\n"
//   fetch request:   one JSON header line "{op,sealed}\n" (no payload)
//   fetch reply:     one JSON line "{ok,sealed,errorCode,errorMessage}\n"
// JSON control + raw binary body, matching the system-wide wire format. The
// stream-coupled entry points are thin templates; the JSON/engine logic lives in
// the non-template helpers below (defined in the .cpp).

struct FederationDeliverResult {
    bool delivered = false;
    std::string errorCode;
    std::string errorMessage;
    // The recipient's signature over the deliveryId, made with the signing key of
    // the destination that took the delivery, and that key. Empty when the store
    // did not happen. This rides the reply because the sender dialled from a
    // one-time destination that nobody can dial back (see OutboundLeases): the
    // confirmation has to come home on the leg that is already open.
    std::string deliveryId;
    Bytes signerPublicDer;
    Bytes signature;
};

// Looks up a local user's contact card (subscription certificate DER) by
// fingerprint for the federation card fetch; nullopt when the user is unknown.
// Looks up a local user's contact card. The view is the capability from the
// descriptor the asker holds; a wrong one must read exactly like an unknown
// user, so this returns nothing in both cases and the caller cannot tell them
// apart.
using GetCardFn = std::function<std::optional<Bytes>(
    const std::string& fingerprint, const std::string& view)>;

struct FederationFetchResult {
    bool ok = false;
    Bytes sealed;
    std::string errorCode;
    std::string errorMessage;
};

// Called on the sender when the recipient's signed confirmation has been verified,
// to mark the matching send attempt delivered.
using OnAckFn = std::function<void(const std::string& deliveryId)>;
// Signs the deliveryId with the signing key of the destination the delivery
// arrived on, and hands back that key: what makes the confirmation in the reply
// something only the server that unsealed the envelope could have written.
using SignAckFn = std::function<void(
    const std::string& deliveryId, Bytes& outSignerPublicDer, Bytes& outSignature)>;

namespace detail {

// Reads a newline-terminated header line from the stream (64 KiB guard).
template <class Stream>
std::string readFederationHeaderLine(Stream& stream)
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

template <class Stream>
void writeFederationHeaderLine(Stream& stream, const std::string& line)
{
    const std::string framed = line + "\n";
    stream.writeAll(framed.data(), framed.size());
}

}  // namespace detail

// Non-template framing helpers (the JSON/engine/cms logic), defined in the .cpp.
std::string buildFederationDeliverHeader(const Bytes& sealed, std::size_t payloadLen);
FederationDeliverResult parseFederationDeliverReply(const std::string& line);
std::string buildFederationFetchHeader(const std::string& op, const Bytes& sealed);
FederationFetchResult parseFederationFetchReply(const std::string& line);
// The card fetch rides the same fetch frame, but its request and answer travel
// in the clear: the query names the fingerprint and hands back the descriptor's
// view capability, and the answer is the card itself. Nothing is sealed because
// the stream already is - and no relayed path is allowed, so there is no third
// party to hide it from.
// Serves one already-read request header: reads the deliver payload via
// readPayload(len) when needed, runs the engine / card lookup, and writes the
// reply line via writeReply. sealingKey null => the engine's default key.
// owner is the user whose destination this arrived on; mail for anyone else is
// not stored (see DeliveryEngine::deliver).
void federationServeFrame(const std::string& headerLine,
    const std::function<Bytes(std::size_t)>& readPayload,
    const std::function<void(const std::string&)>& writeReply, DeliveryEngine& engine,
    std::int64_t now, const Key* sealingKey, const std::string& owner, const GetCardFn& getCard,
    const SignAckFn& signAck = {});

// Client side: send one deliver request and read the result.
template <class Stream>
FederationDeliverResult federationSendDeliver(Stream& stream, const Bytes& sealed, const Bytes& payload)
{
    detail::writeFederationHeaderLine(stream, buildFederationDeliverHeader(sealed, payload.size()));
    if (!payload.empty()) {
        stream.writeAll(payload.data(), payload.size());
    }
    return parseFederationDeliverReply(detail::readFederationHeaderLine(stream));
}

// Client side: send one sealed fetch request {op, sealed} (no payload).
template <class Stream>
FederationFetchResult federationSendFetch(Stream& stream, const std::string& op, const Bytes& sealed)
{
    detail::writeFederationHeaderLine(stream, buildFederationFetchHeader(op, sealed));
    return parseFederationFetchReply(detail::readFederationHeaderLine(stream));
}

// Server side: read one request, run the engine / card lookup, write the reply.
// peerDest/limiter give per-peer rate-limiting (the request is dropped without
// serving when over the limit). An unknown op throws.
template <class Stream>
void federationServeOnce(Stream& stream, DeliveryEngine& engine, const std::int64_t now,
    const std::string& peerDest = std::string(), FederationRateLimiter* const limiter = nullptr,
    const Key* const sealingKey = nullptr, const std::string& owner = std::string(),
    const GetCardFn& getCard = {}, const SignAckFn& signAck = {})
{
    if (limiter != nullptr && !limiter->allow(peerDest, now)) {
        return;  // over the per-peer rate limit: drop without serving
    }
    const std::string headerLine = detail::readFederationHeaderLine(stream);
    federationServeFrame(
        headerLine,
        [&stream](std::size_t len) {
            Bytes payload(len);
            if (len > 0) {
                stream.readExact(payload.data(), len);
            }
            return payload;
        },
        [&stream](const std::string& line) { detail::writeFederationHeaderLine(stream, line); },
        engine, now, sealingKey, owner, getCard, signAck);
}

}  // namespace bazarish::server
