// Bazarish project (c) 2026
#include "I2pBlobFetch.hpp"

#include <bazarish/Sam.hpp>

#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>

namespace bazarish::server {

namespace {

// Parses the status code from an HTTP status line ("HTTP/1.1 404 Not Found").
int parseStatus(const std::string& head)
{
    const std::size_t space = head.find(' ');
    if (space == std::string::npos) {
        throw std::runtime_error("malformed i2p http status line");
    }
    return std::stoi(head.substr(space + 1, 3));
}

}  // namespace

BlobProxyResult fetchBlobOverI2p(const std::string& samHost, const std::uint16_t samPort,
    const std::string& host, const std::string& path)
{
    // Mirrors the client's BlobTransport::i2pRequest GET path; dedupe into common
    // when the SAM HTTP helper is shared. No half-close — SAM treats SHUT_WR as a
    // full stream teardown — so Connection: close drives the response to EOF.
    SamSession session(samHost, samPort, "blobproxy-" + toHex(randomBytes(6)));
    SamStream stream = session.connect(host);

    const std::string request
        = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    stream.writeAll(request.data(), request.size());

    std::string raw;
    std::array<char, 65536> buffer{};
    for (;;) {
        const std::size_t got = stream.readSome(buffer.data(), buffer.size());
        if (got == 0) {
            break;
        }
        raw.append(buffer.data(), got);
    }

    const std::size_t headerEnd = raw.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        throw std::runtime_error("malformed i2p http response");
    }
    BlobProxyResult result;
    result.status = parseStatus(raw.substr(0, raw.find("\r\n")));
    const std::string payload = raw.substr(headerEnd + 4);
    result.body = Bytes(payload.begin(), payload.end());
    return result;
}

}  // namespace bazarish::server
