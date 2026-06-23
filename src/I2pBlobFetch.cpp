// Bazarish project (c) 2026
#include "I2pBlobFetch.hpp"

#include <bazarish/I2pHttp.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>

namespace bazarish::server {

namespace {

constexpr std::chrono::seconds kConnectTimeout{60};

// Streaming download over a client endpoint: reads the response head at
// construction, then hands out body bytes incrementally (leftover head bytes
// first, then straight off the stream).
class I2pBlobDownload final : public I2pBlobReader {
public:
    I2pBlobDownload(bazarish::i2p::Endpoint& endpoint, const std::string& host,
        const std::string& path, const std::string& range)
    {
        stream_ = endpoint.connect(host, kConnectTimeout);
        if (!stream_) {
            throw std::runtime_error("i2p blob download: cannot reach " + host);
        }
        std::map<std::string, std::string> headers;
        if (!range.empty()) {
            headers["Range"] = range;
        }
        const std::string request = buildI2pHttpRequest("GET", host, path, headers, 0);
        stream_->writeAll(request.data(), request.size());

        I2pHttpHead head = readI2pHttpHead(*stream_);
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
    std::unique_ptr<bazarish::i2p::Stream> stream_;
    int status_ = 0;
    std::map<std::string, std::string> headers_;
    std::string leftover_;
    std::size_t leftoverPos_ = 0;
};

}  // namespace

BlobProxyResult fetchBlobOverI2p(bazarish::i2p::Endpoint& endpoint, const std::string& host,
    const std::string& path, const std::string& method, const std::string& deleteToken)
{
    auto stream = endpoint.connect(host, kConnectTimeout);
    if (!stream) {
        throw std::runtime_error("i2p blob fetch: cannot reach " + host);
    }

    std::map<std::string, std::string> headers;
    if (!deleteToken.empty()) {
        headers["X-Delete-Token"] = deleteToken;
    }
    const std::string request = buildI2pHttpRequest(method, host, path, headers, 0);
    stream->writeAll(request.data(), request.size());

    const I2pHttpResponse response = readI2pHttpResponse(*stream);
    BlobProxyResult result;
    result.status = response.status;
    result.body = Bytes(response.body.begin(), response.body.end());
    return result;
}

std::unique_ptr<I2pBlobReader> openBlobDownload(bazarish::i2p::Endpoint& endpoint,
    const std::string& host, const std::string& path, const std::string& range)
{
    return std::make_unique<I2pBlobDownload>(endpoint, host, path, range);
}

}  // namespace bazarish::server
