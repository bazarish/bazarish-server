// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
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
// blocks on tunnel build. Throws on transport failure. Buffers the whole
// response — used for small ops (DELETE); downloads stream (see below).
BlobProxyResult fetchBlobOverI2p(const std::string& samHost, std::uint16_t samPort,
    const std::string& host, const std::string& path, const std::string& method = "GET",
    const std::string& deleteToken = "");

// Pull-style reader for a STREAMED blob download over I2P: the proxy drains it
// into the client response a chunk at a time, so a multi-gigabyte blob is never
// buffered whole on the user's own server. status()/headers() reflect the
// upstream response head (read at construction); readBody() pulls the body.
class I2pBlobReader {
public:
    virtual ~I2pBlobReader() = default;
    virtual int status() const = 0;
    // Upstream response headers, names lowercased (carries content-length /
    // content-range, from which the proxy derives the full blob length).
    virtual const std::map<std::string, std::string>& headers() const = 0;
    // Pulls up to len bytes of the body into out; returns the count, 0 at EOF
    // (a clean close or a mid-stream drop both surface as EOF — the recipient
    // resumes via a Range request).
    virtual std::size_t readBody(char* out, std::size_t len) = 0;
};

// Opens a streaming GET of path on the .b32.i2p host over a fresh transient SAM
// session, with an optional Range header (e.g. "bytes=N-" to resume). Blocks on
// tunnel build and reading the response head. Throws on transport failure before
// the head is read.
std::unique_ptr<I2pBlobReader> openBlobDownload(const std::string& samHost, std::uint16_t samPort,
    const std::string& host, const std::string& path, const std::string& range = "");

}  // namespace bazarish::server
