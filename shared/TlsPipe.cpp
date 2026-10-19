// Bazarish project (c) 2026
#include "TlsPipe.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <openssl/ssl.h>

#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using boost::asio::ip::tcp;

namespace bazarish::server {

namespace {

constexpr std::size_t kChunkBytes = 16 * 1024;

using Written = std::shared_ptr<std::promise<boost::system::error_code>>;

ssl::context contextFor(const ssl::context::method method, const tls::Credential* const own)
{
    ssl::context context(method);
    if (SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_3_VERSION) != 1) {
        throw std::runtime_error("tls pipe: TLS 1.3 cannot be required");
    }
    if (own != nullptr) {
        context.use_certificate_chain_file(own->certificate.string());
        context.use_private_key_file(own->key.string(), ssl::context::pem);
    }
    return context;
}

}  // namespace

// One thread owns the TLS stream: OpenSSL takes no concurrent reader and writer on one SSL.
struct TlsPipe::Impl {
    Impl(const ssl::context::method method, const tls::Credential* const own)
        : context(contextFor(method, own))
        , stream(io, context)
        , expiry(io)
    {
    }

    void finish(const std::chrono::seconds deadline, const char* const what)
    {
        io.restart();
        io.run_for(deadline);
        if (failure == asio::error::would_block) {
            throw std::runtime_error(std::string("tls pipe: ") + what + " took too long");
        }
        if (failure) {
            throw std::runtime_error(std::string("tls pipe: ") + what + ": " + failure.message());
        }
    }

    void begin()
    {
        io.restart();
        alive.emplace(asio::make_work_guard(io));
        readNext();
        loop = std::thread([this]() { io.run(); });
    }

    void readNext()
    {
        stream.async_read_some(asio::buffer(chunk),
            [this](const boost::system::error_code& code, const std::size_t got) {
                std::function<void()> told;
                {
                    const std::lock_guard<std::mutex> lock(mutex);
                    inbox.insert(inbox.end(), chunk.begin(),
                        chunk.begin() + static_cast<std::ptrdiff_t>(got));
                    if (code) {
                        ended = true;
                        const bool closedCleanly
                            = code == asio::error::eof || code == ssl::error::stream_truncated;
                        if (!closedCleanly) {
                            failure = code;
                        }
                        told = std::move(onEnded);
                    }
                }
                changed.notify_all();
                if (told) {
                    told();
                }
                if (!code) {
                    readNext();
                }
            });
    }

    void writeNext()
    {
        asio::async_write(stream, asio::buffer(outbox.front().first),
            [this](const boost::system::error_code& code, std::size_t) {
                outbox.front().second->set_value(code);
                outbox.pop_front();
                if (!outbox.empty()) {
                    writeNext();
                }
            });
    }

    void shut()
    {
        boost::system::error_code ignored;
        expiry.cancel();
        stream.next_layer().shutdown(tcp::socket::shutdown_both, ignored);
        stream.next_layer().close(ignored);
        alive.reset();
    }

    asio::io_context io;
    std::optional<asio::executor_work_guard<asio::io_context::executor_type>> alive;
    std::atomic<bool> closed{false};
    ssl::context context;
    ssl::stream<tcp::socket> stream;
    asio::steady_timer expiry;
    boost::system::error_code failure = asio::error::would_block;
    std::string peerPin;
    std::array<unsigned char, kChunkBytes> chunk{};
    std::thread loop;
    std::mutex mutex;
    std::condition_variable changed;
    std::deque<unsigned char> inbox;
    bool ended = false;
    std::function<void()> onEnded;
    std::deque<std::pair<std::vector<unsigned char>, Written>> outbox;
};

TlsPipe::TlsPipe(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl))
{
}

TlsPipe::~TlsPipe()
{
    close();
    impl_->loop.join();
}

std::unique_ptr<TlsPipe> TlsPipe::dial(const std::string& host, const int port,
    const std::string& pin, const std::chrono::seconds deadline, const tls::Credential* const own)
{
    auto impl = std::make_unique<Impl>(ssl::context::tls_client, own);
    impl->stream.set_verify_mode(ssl::verify_none);
    tcp::resolver resolver(impl->io);
    const tcp::resolver::results_type found = resolver.resolve(host, std::to_string(port));
    Impl* const raw = impl.get();
    asio::async_connect(raw->stream.next_layer(), found,
        [raw](const boost::system::error_code& code, const tcp::endpoint&) {
            raw->failure = code;
        });
    raw->finish(deadline, "connecting");
    raw->failure = asio::error::would_block;
    raw->stream.async_handshake(ssl::stream_base::client,
        [raw](const boost::system::error_code& code) { raw->failure = code; });
    raw->finish(deadline, "the handshake");
    raw->peerPin = tls::pinOf(raw->stream.native_handle());
    if (raw->peerPin != pin) {
        throw std::runtime_error("tls pipe: the key is not the pinned one");
    }
    raw->begin();
    return std::unique_ptr<TlsPipe>(new TlsPipe(std::move(impl)));
}

std::unique_ptr<TlsPipe> TlsPipe::serve(const int protocolFamily, const int socket,
    const tls::Credential& own, const std::chrono::seconds deadline)
{
    auto impl = std::make_unique<Impl>(ssl::context::tls_server, &own);
    impl->stream.set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
    impl->stream.set_verify_callback([](bool, ssl::verify_context&) { return true; });
    impl->stream.next_layer().assign(protocolFamily == AF_INET6 ? tcp::v6() : tcp::v4(), socket);
    Impl* const raw = impl.get();
    raw->stream.async_handshake(ssl::stream_base::server,
        [raw](const boost::system::error_code& code) { raw->failure = code; });
    raw->finish(deadline, "the handshake");
    raw->peerPin = tls::pinOf(raw->stream.native_handle());
    raw->begin();
    return std::unique_ptr<TlsPipe>(new TlsPipe(std::move(impl)));
}

const std::string& TlsPipe::peerPin() const
{
    return impl_->peerPin;
}

std::size_t TlsPipe::readSome(void* const buffer, const std::size_t size)
{
    std::unique_lock<std::mutex> lock(impl_->mutex);
    impl_->changed.wait(lock, [this]() { return !impl_->inbox.empty() || impl_->ended; });
    if (impl_->inbox.empty()) {
        if (impl_->failure) {
            throw std::runtime_error("tls pipe: " + impl_->failure.message());
        }
        return 0;
    }
    const std::size_t got = std::min(size, impl_->inbox.size());
    std::copy(impl_->inbox.begin(), impl_->inbox.begin() + static_cast<std::ptrdiff_t>(got),
        static_cast<unsigned char*>(buffer));
    impl_->inbox.erase(
        impl_->inbox.begin(), impl_->inbox.begin() + static_cast<std::ptrdiff_t>(got));
    return got;
}

std::string TlsPipe::readLine(const std::size_t maxBytes)
{
    std::unique_lock<std::mutex> lock(impl_->mutex);
    for (;;) {
        const auto newline = std::find(impl_->inbox.begin(), impl_->inbox.end(), '\n');
        if (newline != impl_->inbox.end()) {
            std::string line(impl_->inbox.begin(), newline);
            impl_->inbox.erase(impl_->inbox.begin(), newline + 1);
            return line;
        }
        if (impl_->inbox.size() > maxBytes) {
            throw std::runtime_error("tls pipe: a line longer than " + std::to_string(maxBytes));
        }
        if (impl_->ended) {
            throw std::runtime_error("tls pipe: the line was cut off");
        }
        impl_->changed.wait(lock);
    }
}

void TlsPipe::writeAll(const void* const data, const std::size_t size)
{
    if (impl_->closed.load()) {
        throw std::runtime_error("tls pipe: closed");
    }
    const unsigned char* const at = static_cast<const unsigned char*>(data);
    auto written = std::make_shared<std::promise<boost::system::error_code>>();
    std::future<boost::system::error_code> done = written->get_future();
    Impl* const impl = impl_.get();
    asio::post(impl->io,
        [impl, piece = std::vector<unsigned char>(at, at + size), written]() mutable {
            impl->outbox.emplace_back(std::move(piece), std::move(written));
            if (impl->outbox.size() == 1) {
                impl->writeNext();
            }
        });
    const boost::system::error_code failure = done.get();
    if (failure) {
        throw std::runtime_error("tls pipe: " + failure.message());
    }
}

void TlsPipe::close()
{
    if (impl_->closed.exchange(true)) {
        return;
    }
    Impl* const impl = impl_.get();
    asio::post(impl->io, [impl]() { impl->shut(); });
}

void TlsPipe::closeAfter(const std::chrono::seconds wait)
{
    Impl* const impl = impl_.get();
    asio::post(impl->io, [impl, wait]() {
        if (impl->closed.load()) {
            return;
        }
        impl->expiry.expires_after(wait);
        impl->expiry.async_wait([impl](const boost::system::error_code& code) {
            if (!code && !impl->closed.exchange(true)) {
                impl->shut();
            }
        });
    });
}

void TlsPipe::keepOpen()
{
    Impl* const impl = impl_.get();
    asio::post(impl->io, [impl]() { impl->expiry.cancel(); });
}

void TlsPipe::whenEnded(std::function<void()> ended)
{
    {
        const std::lock_guard<std::mutex> lock(impl_->mutex);
        if (!impl_->ended) {
            impl_->onEnded = std::move(ended);
            return;
        }
    }
    ended();
}

}  // namespace bazarish::server
