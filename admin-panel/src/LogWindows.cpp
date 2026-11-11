// Bazarish project (c) 2026
#include "LogWindows.hpp"

#include "ServiceClient.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/Log.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/this_coro.hpp>

#include <nlohmann/json.hpp>

#include <exception>
#include <string>
#include <utility>
#include <vector>

namespace asio = boost::asio;

namespace bazarish::admin {

namespace {

constexpr int kOk = 200;

class WindowSlot {
public:
    explicit WindowSlot(std::shared_ptr<std::atomic<std::size_t>> open)
        : open_(std::move(open))
    {
    }
    ~WindowSlot()
    {
        if (open_) {
            --*open_;
        }
    }
    WindowSlot(WindowSlot&& other) noexcept = default;
    WindowSlot(const WindowSlot&) = delete;
    WindowSlot& operator=(const WindowSlot&) = delete;
    WindowSlot& operator=(WindowSlot&&) = delete;

private:
    std::shared_ptr<std::atomic<std::size_t>> open_;
};

void sendFrame(http::Socket& socket, const nlohmann::json& frame)
{
    // A service's i2pd lines are not promised to be UTF-8.
    const std::string text = frame.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    socket.send(std::vector<unsigned char>(text.begin(), text.end()));
}

asio::awaitable<void> pump(const http::SocketPtr socket, const LogWindow window,
    const Identity& identity, const tls::Credential credential, [[maybe_unused]] WindowSlot slot)
{
    const asio::any_io_executor executor = co_await asio::this_coro::executor;
    std::uint64_t after = window.after;
    std::string instance = window.instance;
    try {
        while (socket->open()) {
            if (!window.live()) {
                socket->close();
                co_return;
            }
            const server::OpsExchange exchange = logsExchange(window.service, identity,
                credential, window.path + "?after=" + std::to_string(after));
            const http::Response answer = co_await http::fetch(
                executor, exchange.host, exchange.port, exchange.request, exchange.options);
            if (!socket->open()) {
                co_return;
            }
            if (!window.live()) {
                socket->close();
                co_return;
            }
            if (answer.status != kOk) {
                JsonResult failed;
                failed.status = answer.status;
                failed.body = answer.body;
                failed.error = window.service.name + " unreachable";
                refuseLogWindow(*socket, failureText(failed));
                co_return;
            }
            nlohmann::json page = parseJson(answer.body);
            const std::string seen = page.at("instance").get<std::string>();
            if (!instance.empty() && seen != instance) {
                instance = seen;
                after = 0;
                continue;
            }
            instance = seen;
            const nlohmann::json& lines = page.at("lines");
            if (lines.empty()) {
                continue;
            }
            after = lines.back().at("seq").get<std::uint64_t>();
            page["type"] = "lines";
            sendFrame(*socket, page);
        }
    } catch (const std::exception& error) {
        bazarish::log::warn("log window of {} closed: {}", window.service.name, error.what());
        refuseLogWindow(*socket, error.what());
    }
}

}  // namespace

void refuseLogWindow(http::Socket& socket, const std::string& message)
{
    sendFrame(socket, nlohmann::json{{"type", "error"}, {"message", message}});
    socket.close();
}

LogWindows::LogWindows(const Identity& identity, tls::Credential credential)
    : identity_(identity)
    , credential_(std::move(credential))
    , open_(std::make_shared<std::atomic<std::size_t>>(0))
{
}

void LogWindows::open(const asio::any_io_executor& executor, const http::SocketPtr& socket,
    LogWindow window)
{
    if (open_->fetch_add(1) >= kMaxLogWindows) {
        --*open_;
        refuseLogWindow(*socket,
            "at most " + std::to_string(kMaxLogWindows) + " log windows are open at once");
        return;
    }
    WindowSlot slot(open_);
    asio::co_spawn(executor,
        pump(socket, std::move(window), identity_, credential_, std::move(slot)), asio::detached);
}

std::size_t LogWindows::count() const
{
    return open_->load();
}

}  // namespace bazarish::admin
