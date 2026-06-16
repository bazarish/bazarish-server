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

// Performs a blob operation over I2P on a client's behalf (the proxy fallback
// for clients without a local SAM bridge): opens a FRESH transient SAM session
// (a throwaway destination — unlinkability) to the .b32.i2p host and runs the
// HTTP/1.1 request (method GET for download, DELETE for unsend) on path. A
// non-empty deleteToken is sent as the X-Delete-Token header. Construction
// blocks on tunnel build. Throws on transport failure.
BlobProxyResult fetchBlobOverI2p(const std::string& samHost, std::uint16_t samPort,
    const std::string& host, const std::string& path, const std::string& method = "GET",
    const std::string& deleteToken = "");

}  // namespace bazarish::server
