// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Sam.hpp>

#include <cstdint>
#include <string>

namespace bazarish::server {

// Server-to-server delivery framing over an I2P stream (or any SamStream):
//   request:  one JSON header line "{op,sealed,len}\n" + len raw payload bytes
//   response: one JSON line "{delivered,errorCode,errorMessage}\n"
// JSON control + raw binary body, matching the system-wide wire format.

struct FederationDeliverResult {
    bool delivered = false;
    std::string errorCode;
    std::string errorMessage;
};

// Client side: send one deliver request and read the result.
FederationDeliverResult federationSendDeliver(
    SamStream& stream, const Bytes& sealed, const Bytes& payload);

// Server side: read one deliver request, run the engine and write the
// result. now is unix seconds.
void federationServeOnce(SamStream& stream, DeliveryEngine& engine, std::int64_t now);

}  // namespace bazarish::server
