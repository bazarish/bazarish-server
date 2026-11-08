// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>
#include <bazarish/HttpClient.hpp>

#include <chrono>
#include <string>

namespace bazarish::server {

// Another service of the fleet, reached over TLS pinned to its key with this one's certificate.
struct OpsTarget {
    std::string url;
    std::string pin;
    std::string certificate;
    std::string key;
};

struct OpsTimeouts {
    std::chrono::seconds connect;
    std::chrono::seconds exchange;
};

// One call signed by the operator key; the target may carry a query, which the signature leaves
// out as the receiving side does.
http::ClientResponse opsCall(const OpsTarget& target, const Identity& signer,
    const std::string& method, const std::string& pathAndQuery, const std::string& body,
    const OpsTimeouts& timeouts);

}  // namespace bazarish::server
