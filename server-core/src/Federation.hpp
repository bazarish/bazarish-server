// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include <bazarish/Limits.hpp>
#include <algorithm>
#include <array>

#include <bazarish/Resolve.hpp>
#include "FederationRateLimiter.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/FederationFrame.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace bazarish::server {

// The serving half of the federation frame. The framing itself and the dialling
// half are shared with the client and live in common: a client delivers its own
// messages over the very same frame this serves.

// Looks up a local user's contact card (subscription certificate DER) by
// fingerprint for the federation card fetch; nullopt when the user is unknown.
// Looks up a local user's contact card. The view is the capability from the
// descriptor the asker holds; a wrong one must read exactly like an unknown
// user, so this returns nothing in both cases and the caller cannot tell them
// apart.
using GetCardFn = std::function<std::optional<Bytes>(
    const std::string& fingerprint, const std::string& view)>;

// Signs the deliveryId with the signing key of the destination the delivery
// arrived on, and hands back that key: what makes the confirmation in the reply
// something only the server that unsealed the envelope could have written.
using SignAckFn = std::function<void(
    const std::string& deliveryId, Bytes& outSignerPublicDer, Bytes& outSignature)>;

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

// What a frame may make this server read before it is not a message at all, and
// the piece the surplus is read in. Reading the surplus is what lets the sender
// hear a typed refusal instead of a stream that closed while it was still
// writing - and a sender that hears nothing is a sender that tries again forever.
inline constexpr std::size_t kDiscardChunkBytes = 64 * 1024;
inline constexpr std::size_t kMaxDiscardBytes = 4 * kMaxMessagePayloadBytes;

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
    // One reader for the whole frame: the header and the payload behind it come
    // out of the same buffer, so nothing read ahead is lost.
    detail::FrameReader<Stream> reader(stream);
    const std::string headerLine = reader.line();
    federationServeFrame(
        headerLine,
        [&reader](std::size_t len) {
            // Never allocate what a peer claims: one byte past the protocol's
            // ceiling is enough for the engine to refuse it, and the rest is
            // read and thrown away in fixed pieces so the sender - which is
            // already writing - gets a typed answer instead of a closed stream.
            // Past a few times the ceiling it is not a message at all and the
            // stream is not worth the bandwidth.
            const std::size_t keep = std::min<std::size_t>(len, kMaxMessagePayloadBytes + 1);
            Bytes payload(keep);
            if (keep > 0) {
                reader.read(payload.data(), keep);
            }
            if (len > kMaxDiscardBytes) {
                throw std::runtime_error("a delivery claiming " + std::to_string(len)
                    + " bytes is not a message");
            }
            std::size_t left = len - keep;
            std::array<unsigned char, kDiscardChunkBytes> sink{};
            while (left > 0) {
                const std::size_t chunk = std::min<std::size_t>(left, sink.size());
                reader.read(sink.data(), chunk);
                left -= chunk;
            }
            return payload;
        },
        [&stream](const std::string& line) { detail::writeFederationHeaderLine(stream, line); },
        engine, now, sealingKey, owner, getCard, signAck);
}

}  // namespace bazarish::server
