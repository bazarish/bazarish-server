// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <string>

namespace bazarish::server {

struct BlobProxyResult {
    int status = 0;
    Bytes body;
};

// Fetches a blob over I2P on a client's behalf (the proxy-fetch fallback for
// clients without a local SAM bridge): opens a FRESH transient SAM session (a
// throwaway destination — unlinkability) to the .b32.i2p host and does an
// HTTP/1.1 GET of path. Construction blocks on tunnel build. Throws on transport
// failure.
BlobProxyResult fetchBlobOverI2p(const std::string& samHost, std::uint16_t samPort,
    const std::string& host, const std::string& path);

}  // namespace bazarish::server
