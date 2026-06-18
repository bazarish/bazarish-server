// Bazarish project (c) 2026
#include "I2pBlobFetch.hpp"

#include <bazarish/Sam.hpp>
#include <bazarish/SamHttp.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <map>
#include <memory>
#include <string>

namespace bazarish::server {

namespace {

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
        std::map<std::string, std::string> headers;
        if (!range.empty()) {
            headers["Range"] = range;
        }
        const std::string request = buildSamHttpRequest("GET", host, path, headers, 0);
        stream_->writeAll(request.data(), request.size());

        SamHttpHead head = readSamHttpHead(*stream_);
        status_ = head.status;
        headers_ = std::move(head.headers);
        leftover_ = std::move(head.leftover);
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
    // Shares the SAM HTTP wire format and response parser with the client's blob
    // fetch (common SamHttp). No half-close — SAM treats SHUT_WR as a full stream
    // teardown — so Connection: close drives the response to EOF.
    SamSession session(samHost, samPort, "blobproxy-" + toHex(randomBytes(6)));
    SamStream stream = session.connect(host);

    std::map<std::string, std::string> headers;
    if (!deleteToken.empty()) {
        headers["X-Delete-Token"] = deleteToken;
    }
    const std::string request = buildSamHttpRequest(method, host, path, headers, 0);
    stream.writeAll(request.data(), request.size());

    const SamHttpResponse response = readSamHttpResponse(stream);
    BlobProxyResult result;
    result.status = response.status;
    result.body = Bytes(response.body.begin(), response.body.end());
    return result;
}

std::unique_ptr<I2pBlobReader> openBlobDownload(const std::string& samHost,
    const std::uint16_t samPort, const std::string& host, const std::string& path,
    const std::string& range)
{
    return std::make_unique<I2pBlobDownload>(samHost, samPort, host, path, range);
}

}  // namespace bazarish::server
