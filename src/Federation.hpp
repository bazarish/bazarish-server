// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
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
};

// Looks up a local user's contact card (subscription certificate DER) by
// fingerprint for the federation card fetch; nullopt when the user is unknown.
using GetCardFn = std::function<std::optional<Bytes>(const std::string& fingerprint)>;

struct FederationFetchResult {
    bool ok = false;
    Bytes sealed;
    std::string errorCode;
    std::string errorMessage;
};

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
// Serves one already-read request header: reads the deliver payload via
// readPayload(len) when needed, runs the engine / card lookup, and writes the
// reply line via writeReply. sealingKey null => the engine's home key.
void federationServeFrame(const std::string& headerLine,
    const std::function<Bytes(std::size_t)>& readPayload,
    const std::function<void(const std::string&)>& writeReply, DeliveryEngine& engine,
    std::int64_t now, const Key* sealingKey, const GetCardFn& getCard);

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
    const Key* const sealingKey = nullptr, const GetCardFn& getCard = {})
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
        engine, now, sealingKey, getCard);
}

}  // namespace bazarish::server
