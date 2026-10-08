// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/FederationFrame.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <RateLimiter.hpp>
#include <bazarish/Resolve.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace bazarish::server {

// Looks up a local user's contact card (DER) for the federation card fetch.
using GetCardFn = std::function<std::optional<Bytes>(const std::string& fingerprint)>;

using SignAckFn = std::function<void(
    const std::string& deliveryId, Bytes& outSignerPublicDer, Bytes& outSignature)>;

void federationServeFrame(const std::string& headerLine,
    const std::function<Bytes(std::size_t)>& readPayload,
    const std::function<void(const std::string&)>& writeReply, DeliveryEngine& engine,
    std::int64_t now, const Key* sealingKey, const std::string& owner, const GetCardFn& getCard,
    const SignAckFn& signAck = {});

inline constexpr std::size_t kDiscardChunkBytes = 64 * 1024;
inline constexpr std::size_t kMaxDiscardBytes = 4 * kMaxMessagePayloadBytes;

template <class Stream>
void federationServeOnce(Stream& stream, DeliveryEngine& engine, const std::int64_t now,
    const std::string& peerDest = std::string(), RateLimiter* const limiter = nullptr,
    const Key* const sealingKey = nullptr, const std::string& owner = std::string(),
    const GetCardFn& getCard = {}, const SignAckFn& signAck = {})
{
    if (limiter != nullptr && !limiter->allow(peerDest, now)) {
        return;
    }
    detail::FrameReader<Stream> reader(stream);
    try {
        const std::string headerLine = reader.line();
        federationServeFrame(
        headerLine,
        [&reader](std::size_t len) {
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
    } catch (const std::exception& error) {
        bazarish::log::warn("serving a federation frame failed: {}", error.what());
        detail::writeFederationHeaderLine(stream,
            nlohmann::json({{"ok", false}, {"delivered", false},
                {"errorCode", std::string(bazarish::toString(bazarish::ErrorCode::eDeliveryRejected))}})
                .dump());
    }
}

}  // namespace bazarish::server
