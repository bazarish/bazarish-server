// Bazarish project (c) 2026
#include "Conduit.hpp"

#include <bazarish/Tls.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>

#include <stdexcept>
#include <string>
#include <utility>

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using boost::asio::ip::tcp;

namespace bazarish::gateway {

namespace {

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
    TlsConduit(const DirectRoute& route, const std::chrono::seconds deadline)
        : context_(ssl::context::tls_client)
        , stream_(io_, context_)
    {
        stream_.set_verify_mode(ssl::verify_none);
        tcp::resolver resolver(io_);
        const tcp::resolver::results_type found
            = resolver.resolve(route.host, std::to_string(route.port));

        boost::system::error_code failure = asio::error::would_block;
        asio::async_connect(stream_.next_layer(), found,
            [&failure](const boost::system::error_code& code, const tcp::endpoint&) {
                failure = code;
            });
        waitFor(deadline);
        if (failure) {
            throw std::runtime_error("direct route: " + failure.message());
        }

        failure = asio::error::would_block;
        stream_.async_handshake(ssl::stream_base::client,
            [&failure](const boost::system::error_code& code) { failure = code; });
        waitFor(deadline);
        if (failure) {
            throw std::runtime_error("direct route: " + failure.message());
        }
        if (tls::pinOf(stream_.native_handle()) != route.pin) {
            throw std::runtime_error("direct route: the key is not the pinned one");
        }
        stream_.next_layer().non_blocking(false);
    }

    std::size_t readSome(void* buffer, const std::size_t size) override
    {
        boost::system::error_code failure;
        const std::size_t got = stream_.read_some(asio::buffer(buffer, size), failure);
        if (failure == asio::error::eof || failure == ssl::error::stream_truncated) {
            return 0;
        }
        if (failure) {
            throw std::runtime_error("direct route: " + failure.message());
        }
        return got;
    }

    void writeAll(const void* data, const std::size_t size) override
    {
        asio::write(stream_, asio::buffer(data, size));
    }

    void close() override
    {
        boost::system::error_code ignored;
        // A close alone does not wake a read blocked on this socket in another thread.
        stream_.next_layer().shutdown(tcp::socket::shutdown_both, ignored);
        stream_.next_layer().close(ignored);
    }

private:
    void waitFor(const std::chrono::seconds deadline)
    {
        io_.restart();
        io_.run_for(deadline);
    }

    asio::io_context io_;
    ssl::context context_;
    ssl::stream<tcp::socket> stream_;
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
    return std::make_unique<TlsConduit>(route, deadline);
}

}  // namespace bazarish::gateway
