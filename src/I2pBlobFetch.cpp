// Bazarish project (c) 2026
#include "I2pBlobFetch.hpp"

#include <bazarish/Sam.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <map>
#include <memory>
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

// Parses the header lines after the status line into a lowercased map.
std::map<std::string, std::string> parseHeaders(const std::string& head)
{
    std::map<std::string, std::string> headers;
    const std::size_t firstLineEnd = head.find("\r\n");
    std::size_t lineStart = (firstLineEnd == std::string::npos) ? head.size() : firstLineEnd + 2;
    while (lineStart < head.size()) {
        const std::size_t lineEnd = head.find("\r\n", lineStart);
        const std::size_t stop = (lineEnd == std::string::npos) ? head.size() : lineEnd;
        const std::string line = head.substr(lineStart, stop - lineStart);
        lineStart = (lineEnd == std::string::npos) ? head.size() : lineEnd + 2;
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        std::string key = line.substr(0, colon);
        std::transform(key.begin(), key.end(), key.begin(),
            [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::size_t valueStart = colon + 1;
        while (valueStart < line.size() && (line[valueStart] == ' ' || line[valueStart] == '\t')) {
            ++valueStart;
        }
        headers[key] = line.substr(valueStart);
    }
    return headers;
}

// Streaming download over a fresh transient SAM session: reads the response head
// at construction, then hands out body bytes incrementally (leftover head bytes
// first, then straight off the stream).
class I2pBlobDownload final : public I2pBlobReader {
public:
    I2pBlobDownload(const std::string& samHost, const std::uint16_t samPort,
        const std::string& host, const std::string& path, const std::string& range)
        : session_(std::make_unique<SamSession>(
              samHost, samPort, "blobproxy-" + toHex(randomBytes(6))))
    {
        // No half-close — SAM treats SHUT_WR as a full stream teardown — so
        // Connection: close drives the response to EOF.
        stream_ = std::make_unique<SamStream>(session_->connect(host));
        std::string request = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n";
        if (!range.empty()) {
            request += "Range: " + range + "\r\n";
        }
        request += "Content-Length: 0\r\nConnection: close\r\n\r\n";
        stream_->writeAll(request.data(), request.size());

        std::string head;
        std::array<char, 65536> buffer{};
        std::size_t headerEnd = std::string::npos;
        while ((headerEnd = head.find("\r\n\r\n")) == std::string::npos) {
            const std::size_t got = stream_->readSome(buffer.data(), buffer.size());
            if (got == 0) {
                throw std::runtime_error("malformed i2p http response");
            }
            head.append(buffer.data(), got);
        }
        const std::string headBlock = head.substr(0, headerEnd);
        status_ = parseStatus(headBlock.substr(0, headBlock.find("\r\n")));
        headers_ = parseHeaders(headBlock);
        leftover_ = head.substr(headerEnd + 4);
    }

    int status() const override { return status_; }
    const std::map<std::string, std::string>& headers() const override { return headers_; }

    std::size_t readBody(char* out, const std::size_t len) override
    {
        if (leftoverPos_ < leftover_.size()) {
            const std::size_t take = std::min(len, leftover_.size() - leftoverPos_);
            std::memcpy(out, leftover_.data() + leftoverPos_, take);
            leftoverPos_ += take;
            return take;
        }
        return stream_->readSome(out, len);
    }

private:
    std::unique_ptr<SamSession> session_;
    std::unique_ptr<SamStream> stream_;
    int status_ = 0;
    std::map<std::string, std::string> headers_;
    std::string leftover_;
    std::size_t leftoverPos_ = 0;
};

}  // namespace

BlobProxyResult fetchBlobOverI2p(const std::string& samHost, const std::uint16_t samPort,
    const std::string& host, const std::string& path, const std::string& method,
    const std::string& deleteToken)
{
    // Mirrors the client's BlobTransport::i2pRequest; dedupe into common when the
    // SAM HTTP helper is shared. No half-close — SAM treats SHUT_WR as a full
    // stream teardown — so Connection: close drives the response to EOF.
    SamSession session(samHost, samPort, "blobproxy-" + toHex(randomBytes(6)));
    SamStream stream = session.connect(host);

    std::string request = method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n";
    if (!deleteToken.empty()) {
        request += "X-Delete-Token: " + deleteToken + "\r\n";
    }
    request += "Content-Length: 0\r\nConnection: close\r\n\r\n";
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

std::unique_ptr<I2pBlobReader> openBlobDownload(const std::string& samHost,
    const std::uint16_t samPort, const std::string& host, const std::string& path,
    const std::string& range)
{
    return std::make_unique<I2pBlobDownload>(samHost, samPort, host, path, range);
}

}  // namespace bazarish::server
