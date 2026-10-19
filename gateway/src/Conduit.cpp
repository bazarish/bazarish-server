// Bazarish project (c) 2026
#include "Conduit.hpp"

#include <TlsPipe.hpp>

#include <nlohmann/json.hpp>

#include <utility>

namespace bazarish::gateway {

namespace {

constexpr std::size_t kMaxAnswerBytes = 256;

class I2pConduit : public Conduit {
public:
    explicit I2pConduit(std::unique_ptr<i2p::Stream> stream)
        : stream_(std::move(stream))
    {
    }

    std::size_t readSome(void* buffer, const std::size_t size) override
    {
        return stream_->readSome(buffer, size);
    }

    void writeAll(const void* data, const std::size_t size) override
    {
        stream_->writeAll(data, size);
    }

    void close() override { stream_->close(); }

private:
    std::unique_ptr<i2p::Stream> stream_;
};

class TlsConduit : public Conduit {
public:
    explicit TlsConduit(std::unique_ptr<server::TlsPipe> pipe)
        : pipe_(std::move(pipe))
    {
    }

    std::size_t readSome(void* buffer, const std::size_t size) override
    {
        return pipe_->readSome(buffer, size);
    }

    void writeAll(const void* data, const std::size_t size) override
    {
        pipe_->writeAll(data, size);
    }

    void close() override { pipe_->close(); }

private:
    std::unique_ptr<server::TlsPipe> pipe_;
};

}  // namespace

std::unique_ptr<Conduit> overI2p(std::unique_ptr<i2p::Stream> stream)
{
    if (stream == nullptr) {
        return nullptr;
    }
    return std::make_unique<I2pConduit>(std::move(stream));
}

std::unique_ptr<Conduit> overTls(const DirectRoute& route, const std::chrono::seconds deadline)
{
    return std::make_unique<TlsConduit>(
        server::TlsPipe::dial(route.host, route.port, route.pin, deadline));
}

std::unique_ptr<Conduit> overServer(const ServerLink& server, const tls::Credential& own,
    const std::string& to, const std::string& from, const std::chrono::seconds deadline)
{
    std::unique_ptr<server::TlsPipe> pipe
        = server::TlsPipe::dial(server.host, server.port, server.pin, deadline, &own);
    const std::string preface = nlohmann::json({{"to", to}, {"from", from}}).dump() + "\n";
    pipe->writeAll(preface.data(), preface.size());
    if (!nlohmann::json::parse(pipe->readLine(kMaxAnswerBytes)).value("ok", false)) {
        throw std::runtime_error("the server does not serve " + to);
    }
    return std::make_unique<TlsConduit>(std::move(pipe));
}

}  // namespace bazarish::gateway
