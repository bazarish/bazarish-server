// Bazarish project (c) 2026
#include "GatewayLink.hpp"

#include <bazarish/Log.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <exception>
#include <stdexcept>
#include <utility>

namespace asio = boost::asio;
using boost::asio::ip::tcp;

namespace bazarish::server {

namespace {

constexpr std::chrono::seconds kHandshake{10};
constexpr std::size_t kMaxPrefaceBytes = 4096;

void answer(TlsPipe& pipe, const bool ok)
{
    const std::string line = nlohmann::json({{"ok", ok}}).dump() + "\n";
    pipe.writeAll(line.data(), line.size());
}

}  // namespace

struct GatewayLink::Impl {
    asio::io_context io;
    tcp::acceptor acceptor{io};
};

GatewayLink::GatewayLink(
    tls::Credential own, std::vector<std::string> gateways, Listed listed, Serve serve)
    : own_(std::move(own))
    , listed_(std::move(listed))
    , serve_(std::move(serve))
    , impl_(std::make_unique<Impl>())
    , gateways_(std::move(gateways))
{
}

GatewayLink::~GatewayLink()
{
    stop();
}

int GatewayLink::start(const std::string& host, const int port)
{
    const tcp::endpoint at(asio::ip::make_address(host), static_cast<unsigned short>(port));
    impl_->acceptor.open(at.protocol());
    impl_->acceptor.set_option(tcp::acceptor::reuse_address(true));
    impl_->acceptor.bind(at);
    impl_->acceptor.listen();
    running_.store(true);
    accept();
    loop_ = std::thread([this]() { impl_->io.run(); });
    return impl_->acceptor.local_endpoint().port();
}

void GatewayLink::stop()
{
    if (!running_.exchange(false)) {
        return;
    }
    asio::post(impl_->io, [this]() {
        boost::system::error_code ignored;
        impl_->acceptor.close(ignored);
    });
    loop_.join();
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const std::weak_ptr<TlsPipe>& held : open_) {
            if (const std::shared_ptr<TlsPipe> pipe = held.lock()) {
                pipe->close();
            }
        }
    }
    changed_.notify_all();
    reap(true);
}

void GatewayLink::setGateways(std::vector<std::string> gateways)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    gateways_ = std::move(gateways);
    for (const std::weak_ptr<TlsPipe>& held : open_) {
        const std::shared_ptr<TlsPipe> pipe = held.lock();
        if (pipe != nullptr
            && std::find(gateways_.begin(), gateways_.end(), pipe->peerPin()) == gateways_.end()) {
            pipe->close();
        }
    }
}

void GatewayLink::servedChanged()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        ++version_;
    }
    changed_.notify_all();
}

bool GatewayLink::admitted(const std::string& pin) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return std::find(gateways_.begin(), gateways_.end(), pin) != gateways_.end();
}

void GatewayLink::accept()
{
    impl_->acceptor.async_accept(
        [this](const boost::system::error_code& failure, tcp::socket socket) {
            if (failure) {
                if (running_.load()) {
                    bazarish::log::warn("gateway link: accept failed: {}", failure.message());
                }
                return;
            }
            const int family = socket.local_endpoint().protocol().family();
            const int native = socket.release();
            reap(false);
            auto done = std::make_shared<std::atomic<bool>>(false);
            const std::lock_guard<std::mutex> lock(mutex_);
            handlers_.push_back({std::thread([this, family, native, done]() {
                handle(family, native);
                done->store(true);
            }),
                done});
            accept();
        });
}

void GatewayLink::reap(const bool all)
{
    std::list<Handler> finished;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (auto at = handlers_.begin(); at != handlers_.end();) {
            if (all || at->done->load()) {
                finished.push_back(std::move(*at));
                at = handlers_.erase(at);
            } else {
                ++at;
            }
        }
        open_.remove_if([](const std::weak_ptr<TlsPipe>& held) { return held.expired(); });
    }
    for (Handler& handler : finished) {
        handler.thread.join();
    }
}

void GatewayLink::handle(const int family, const int socket)
{
    std::shared_ptr<TlsPipe> pipe;
    try {
        pipe = TlsPipe::serve(family, socket, own_, kHandshake);
    } catch (const std::exception& error) {
        bazarish::log::debug("gateway link: a handshake did not finish: {}", error.what());
        return;
    }
    if (!admitted(pipe->peerPin())) {
        bazarish::log::warn("gateway link: a caller with an unlisted key was refused");
        return;
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!running_.load()) {
            return;
        }
        open_.push_back(pipe);
    }
    try {
        pipe->closeAfter(kHandshake);
        const nlohmann::json asked = nlohmann::json::parse(pipe->readLine(kMaxPrefaceBytes));
        if (asked.value("watch", false)) {
            pipe->keepOpen();
            watch(pipe);
            return;
        }
        const std::string to = asked.value("to", std::string());
        const std::string from = asked.value("from", std::string());
        if (to.empty() || from.empty()) {
            throw std::runtime_error("a preface asks to watch or names a stream");
        }
        const std::vector<std::string> served = listed_();
        const bool serving = std::find(served.begin(), served.end(), to) != served.end();
        answer(*pipe, serving);
        if (serving && !serve_(to, from, *pipe)) {
            bazarish::log::info("gateway link: a destination went while a stream to it opened");
        }
    } catch (const std::exception& error) {
        bazarish::log::warn("gateway link: {}", error.what());
    }
}

void GatewayLink::watch(const std::shared_ptr<TlsPipe>& pipe)
{
    const auto ended = std::make_shared<std::atomic<bool>>(false);
    pipe->whenEnded([this, ended]() {
        ended->store(true);
        changed_.notify_all();
    });
    std::uint64_t told = 0;
    for (;;) {
        std::uint64_t now = 0;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            changed_.wait(lock, [this, &ended, told]() {
                return ended->load() || !running_.load() || version_ != told;
            });
            if (ended->load() || !running_.load()) {
                return;
            }
            now = version_;
        }
        const std::string line = nlohmann::json({{"dests", listed_()}}).dump() + "\n";
        pipe->writeAll(line.data(), line.size());
        told = now;
    }
}

}  // namespace bazarish::server
