// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Sam.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace bazarish::server {

class FederationRateLimiter;

// Server-to-server framing over an I2P stream (or any SamStream):
//   deliver request: one JSON header line "{op:deliver,sealed,len}\n" + len bytes
//   deliver reply:   one JSON line "{delivered,errorCode,errorMessage}\n"
//   fetch request:   one JSON header line "{op,sealed}\n" (no payload)
//   fetch reply:     one JSON line "{ok,sealed,errorCode,errorMessage}\n"
// JSON control + raw binary body, matching the system-wide wire format.

struct FederationDeliverResult {
    bool delivered = false;
    std::string errorCode;
    std::string errorMessage;
};

// Client side: send one deliver request and read the result.
FederationDeliverResult federationSendDeliver(
    SamStream& stream, const Bytes& sealed, const Bytes& payload);

// Looks up a local user's contact card (subscription certificate DER) by
// fingerprint for the federation card fetch; nullopt when the user is unknown.
using GetCardFn = std::function<std::optional<Bytes>(const std::string& fingerprint)>;

// Result of a sealed fetch (op "card" - and "resolve" at the central resolver):
// an opaque sealed response, or an error.
struct FederationFetchResult {
    bool ok = false;
    Bytes sealed;
    std::string errorCode;
    std::string errorMessage;
};

// Client side: send one sealed fetch request {op, sealed} (no payload) and read
// the {ok, sealed, errorCode} result.
FederationFetchResult federationSendFetch(
    SamStream& stream, const std::string& op, const Bytes& sealed);

// Server side: read one deliver request, run the engine and write the result.
// now is unix seconds. peerDest is the connecting peer's I2P destination; when
// limiter is set and the peer is over its rate limit, the request is dropped
// without serving. sealingKey is the serving sealing key of the destination
// that accepted this connection (the envelope is sealed to it); when null the
// engine's home key is used. peerDest/limiter default to no rate-limiting.
// op "deliver" runs the engine; op "card" unseals a CardFetchQuery with the
// destination's sealing key, looks the card up via getCard and seals the
// CardFetchResponse to the query's response key (CARD_UNKNOWN when getCard is
// unset or returns nothing). An unknown op throws.
void federationServeOnce(SamStream& stream, DeliveryEngine& engine, std::int64_t now,
    const std::string& peerDest = std::string(), FederationRateLimiter* limiter = nullptr,
    const Key* sealingKey = nullptr, const GetCardFn& getCard = {});

}  // namespace bazarish::server
