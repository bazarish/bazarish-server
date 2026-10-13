// Bazarish project (c) 2026
#include "Conduit.hpp"

#include <bazarish/Tls.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using boost::asio::ip::tcp;

namespace bazarish::gateway {

namespace {

constexpr std::size_t kChunkBytes = 16 * 1024;

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

// One thread owns the TLS stream: OpenSSL takes no concurrent reader and writer on one SSL.
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
        io_.restart();
        alive_.emplace(asio::make_work_guard(io_));
        readNext();
        loop_ = std::thread([this]() { io_.run(); });
    }

    ~TlsConduit() override
    {
        close();
        loop_.join();
    }

    std::size_t readSome(void* buffer, const std::size_t size) override
    {
        std::unique_lock<std::mutex> lock(mutex_);
        changed_.wait(lock, [this]() { return !inbox_.empty() || ended_; });
        if (inbox_.empty()) {
            if (failure_) {
                throw std::runtime_error("direct route: " + failure_.message());
            }
            return 0;
        }
        const std::size_t got = std::min(size, inbox_.size());
        std::copy(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(got),
            static_cast<unsigned char*>(buffer));
        inbox_.erase(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(got));
        return got;
    }

    void writeAll(const void* data, const std::size_t size) override
    {
        if (closed_.load()) {
            throw std::runtime_error("direct route: the conduit is closed");
        }
        const unsigned char* const at = static_cast<const unsigned char*>(data);
        auto written = std::make_shared<std::promise<boost::system::error_code>>();
        std::future<boost::system::error_code> done = written->get_future();
        asio::post(io_, [this, piece = std::vector<unsigned char>(at, at + size), written]() mutable {
            outbox_.emplace_back(std::move(piece), std::move(written));
            if (outbox_.size() == 1) {
                writeNext();
            }
        });
        const boost::system::error_code failure = done.get();
        if (failure) {
            throw std::runtime_error("direct route: " + failure.message());
        }
    }

    void close() override
    {
        if (closed_.exchange(true)) {
            return;
        }
        asio::post(io_, [this]() {
            boost::system::error_code ignored;
            stream_.next_layer().shutdown(tcp::socket::shutdown_both, ignored);
            stream_.next_layer().close(ignored);
            alive_.reset();
        });
    }

private:
    using Written = std::shared_ptr<std::promise<boost::system::error_code>>;

    void waitFor(const std::chrono::seconds deadline)
    {
        io_.restart();
        io_.run_for(deadline);
    }

    void readNext()
    {
        stream_.async_read_some(asio::buffer(chunk_),
            [this](const boost::system::error_code& failure, const std::size_t got) {
                {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    inbox_.insert(inbox_.end(), chunk_.begin(),
                        chunk_.begin() + static_cast<std::ptrdiff_t>(got));
                    if (failure) {
                        ended_ = true;
                        const bool closedCleanly = failure == asio::error::eof
                            || failure == ssl::error::stream_truncated;
                        if (!closedCleanly) {
                            failure_ = failure;
                        }
                    }
                }
                changed_.notify_all();
                if (!failure) {
                    readNext();
                }
            });
    }

    void writeNext()
    {
        asio::async_write(stream_, asio::buffer(outbox_.front().first),
            [this](const boost::system::error_code& failure, std::size_t) {
                outbox_.front().second->set_value(failure);
                outbox_.pop_front();
                if (!outbox_.empty()) {
                    writeNext();
                }
            });
    }

    asio::io_context io_;
    std::optional<asio::executor_work_guard<asio::io_context::executor_type>> alive_;
    std::atomic<bool> closed_{false};
    ssl::context context_;
    ssl::stream<tcp::socket> stream_;
    std::array<unsigned char, kChunkBytes> chunk_{};
    std::thread loop_;
    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<unsigned char> inbox_;
    bool ended_ = false;
    boost::system::error_code failure_;
    std::deque<std::pair<std::vector<unsigned char>, Written>> outbox_;
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
