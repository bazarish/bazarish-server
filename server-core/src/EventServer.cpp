// Bazarish project (c) 2026
#include "EventServer.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Log.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <map>
#include <sstream>
#include <vector>

namespace bazarish::server {

namespace {

namespace asio = boost::asio;
using asio::ip::tcp;

// A signed request's head is dominated by the hybrid keys and the post-quantum
// signature: measured at ~8.3 KB for one call, so 8 KB rejected every authentic
// request. Sized with room for growth, still bounded.
constexpr std::size_t kMaxHeadBytes = 64 * 1024;
constexpr const char* kRoute = "/v1/messaging/events";

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

std::string lowered(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

// One request line + headers, as far as this route needs them. The body is
// always empty here (a GET), so nothing more is read off the socket.
struct Request {
    std::string method;
    std::string target;  // path with query
    std::map<std::string, std::string> headers;  // keys lowercased
};

std::string queryValue(const std::string& target, const std::string& key)
{
    const std::size_t mark = target.find('?');
    if (mark == std::string::npos) {
        return {};
    }
    std::string rest = target.substr(mark + 1);
    while (!rest.empty()) {
        const std::size_t amp = rest.find('&');
        const std::string pair = rest.substr(0, amp);
        const std::size_t eq = pair.find('=');
        if (eq != std::string::npos && pair.substr(0, eq) == key) {
            return pair.substr(eq + 1);
        }
        if (amp == std::string::npos) {
            break;
        }
        rest = rest.substr(amp + 1);
    }
    return {};
}

std::string pathOf(const std::string& target)
{
    const std::size_t mark = target.find('?');
    return mark == std::string::npos ? target : target.substr(0, mark);
}

std::string response(const int status, const std::string& body)
{
    const std::string reason = status == 200 ? "OK" : (status == 401 ? "Unauthorized" : "Bad Request");
    std::ostringstream out;
    out << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    return out.str();
}

std::string pendingBody(Storage& storage, const std::string& user, const std::string& clientId)
{
    nlohmann::json pending = nlohmann::json::array();
    for (const Storage::PendingEntry& entry : storage.listPending(user, clientId)) {
        pending.push_back({{"id", entry.blobId}, {"class", entry.deliveryClass}});
    }
    return nlohmann::json{{"pending", pending}}.dump();
}

}  // namespace

struct EventServer::Impl {
    Storage& storage;
    EventGate& gate;
    Options options;
    asio::io_context io;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::vector<std::thread> workers;

    Impl(Storage& s, EventGate& g, Options o)
        : storage(s)
        , gate(g)
        , options(std::move(o))
    {
    }

    asio::awaitable<void> serve(tcp::socket socket);
    asio::awaitable<void> accept();
};

asio::awaitable<void> EventServer::Impl::serve(tcp::socket socket)
{
    try {
        std::string head;
        head.reserve(kMaxHeadBytes);
        asio::dynamic_string_buffer buffer(head, kMaxHeadBytes);
        boost::system::error_code readError;
        co_await asio::async_read_until(socket, buffer, "\r\n\r\n",
            asio::redirect_error(asio::use_awaitable, readError));
        if (readError) {
            // Too large, or the peer went away mid-head: say so rather than close
            // on a client that would otherwise wait for an answer that never comes.
            co_await asio::async_write(socket,
                asio::buffer(response(400, R"({"error":{"code":"DELIVERY_REJECTED",)"
                                           R"("message":"malformed request head"}})")),
                asio::use_awaitable);
            co_return;
        }

        Request request;
        std::istringstream lines(head);
        std::string line;
        std::getline(lines, line);
        {
            std::istringstream first(line);
            first >> request.method >> request.target;
        }
        while (std::getline(lines, line) && line != "\r" && !line.empty()) {
            const std::size_t colon = line.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            std::string value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.back() == '\r')) {
                if (value.front() == ' ') {
                    value.erase(value.begin());
                } else {
                    value.pop_back();
                }
            }
            request.headers[lowered(line.substr(0, colon))] = value;
        }

        if (request.method != "GET" || pathOf(request.target) != kRoute) {
            co_await asio::async_write(socket,
                asio::buffer(response(400, R"({"error":{"code":"DELIVERY_REJECTED",)"
                                           R"("message":"unknown route"}})")),
                asio::use_awaitable);
            co_return;
        }

        bazarish::auth::Headers authHeaders;
        for (const char* const name : {bazarish::auth::kHeaderKeys, bazarish::auth::kHeaderTimestamp,
                 bazarish::auth::kHeaderSignatureClassical, bazarish::auth::kHeaderSignaturePq}) {
            const auto found = request.headers.find(lowered(name));
            if (found != request.headers.end()) {
                authHeaders[name] = found->second;
            }
        }
        std::string user;
        std::string authError;
        try {
            // Signed over the full target, exactly as the client signed it.
            user = bazarish::auth::verifyRequest(
                authHeaders, nowSeconds(), request.method, request.target, Bytes{});
        } catch (const std::exception& error) {
            authError = error.what();
        }
        if (!authError.empty()) {
            co_await asio::async_write(socket,
                asio::buffer(response(401,
                    nlohmann::json{
                        {"error", {{"code", "DELIVERY_REJECTED"}, {"message", authError}}}}
                        .dump())),
                asio::use_awaitable);
            co_return;
        }

        const std::string clientId = queryValue(request.target, "client");
        if (clientId.empty()) {
            co_await asio::async_write(socket,
                asio::buffer(response(400, R"({"error":{"code":"DELIVERY_REJECTED",)"
                                           R"("message":"client id required"}})")),
                asio::use_awaitable);
            co_return;
        }

        std::string body;
        std::string listError;
        try {
            body = pendingBody(storage, user, clientId);
        } catch (const std::exception& error) {
            listError = error.what();
        }
        if (!listError.empty()) {
            // Answer, do not drop the connection: a client left waiting on a
            // closed socket cannot tell a refusal from a network fault.
            co_await asio::async_write(socket,
                asio::buffer(response(400,
                    nlohmann::json{
                        {"error", {{"code", "DELIVERY_REJECTED"}, {"message", listError}}}}
                        .dump())),
                asio::use_awaitable);
            co_return;
        }
        if (nlohmann::json::parse(body).at("pending").empty()) {
            int wait = options.maxWaitSeconds;
            const std::string asked = queryValue(request.target, "wait");
            if (!asked.empty()) {
                try {
                    wait = std::min(std::stoi(asked), options.maxWaitSeconds);
                } catch (const std::exception& error) {
                    // An unparseable wait is the default one, not an error - but a
                    // client asking for nonsense is worth one line.
                    bazarish::log::debug("event face: bad wait '{}': {}", asked, error.what());
                }
            }
            // Nothing to report: suspend here. No thread is held - the coroutine
            // resumes when the gate fires or the wait runs out.
            asio::steady_timer resume(co_await asio::this_coro::executor);
            resume.expires_at(std::chrono::steady_clock::time_point::max());
            gate.wait(co_await asio::this_coro::executor, user, std::chrono::seconds(wait),
                [&resume]() { resume.cancel(); });
            boost::system::error_code ignored;
            co_await resume.async_wait(asio::redirect_error(asio::use_awaitable, ignored));
            try {
                body = pendingBody(storage, user, clientId);
            } catch (const std::exception& error) {
                bazarish::log::warn("event face: {}", error.what());
                body = R"({"pending":[]})";
            }
        }
        co_await asio::async_write(socket, asio::buffer(response(200, body)), asio::use_awaitable);
    } catch (const std::exception& error) {
        bazarish::log::debug("event stream ended: {}", error.what());
    }
    boost::system::error_code ignored;
    socket.shutdown(tcp::socket::shutdown_both, ignored);
}

asio::awaitable<void> EventServer::Impl::accept()
{
    for (;;) {
        tcp::socket socket = co_await acceptor->async_accept(asio::use_awaitable);
        asio::co_spawn(io, serve(std::move(socket)), asio::detached);
    }
}

EventServer::EventServer(Storage& storage, EventGate& gate, Options options)
    : impl_(std::make_unique<Impl>(storage, gate, std::move(options)))
{
}

EventServer::~EventServer()
{
    stop();
}

int EventServer::start()
{
    const tcp::endpoint endpoint(
        asio::ip::make_address(impl_->options.host), static_cast<unsigned short>(impl_->options.port));
    impl_->acceptor = std::make_unique<tcp::acceptor>(impl_->io, endpoint);
    asio::co_spawn(impl_->io, impl_->accept(), asio::detached);
    for (int i = 0; i < std::max(1, impl_->options.threads); ++i) {
        impl_->workers.emplace_back([this]() { impl_->io.run(); });
    }
    return impl_->acceptor->local_endpoint().port();
}

void EventServer::stop()
{
    if (impl_->workers.empty()) {
        return;
    }
    impl_->io.stop();
    for (std::thread& worker : impl_->workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    impl_->workers.clear();
}

}  // namespace bazarish::server
