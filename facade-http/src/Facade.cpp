// Bazarish project (c) 2026
#include "Facade.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Health.hpp>

#include <bazarish/HttpClient.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/HttpServer.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <system_error>

namespace bazarish::facade {

namespace {

// How long the facade waits on a backend. Longer than the event face's own cap,
// so a held request is answered by the backend rather than cut short here.
constexpr int kUpstreamTimeoutSeconds = 60;


// Backends a request can be routed to.
enum class Backend {
    eNone,
    eMessaging,
    eAccount,
};

bool startsWith(const std::string& text, const std::string& prefix)
{
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

std::int64_t nowSeconds()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Collects the four request-auth headers from a request into the map the auth
// primitives expect.
bazarish::auth::Headers collectAuthHeaders(const bazarish::http::Request& request)
{
    bazarish::auth::Headers headers;
    for (const char* const name : {bazarish::auth::kHeaderKeys, bazarish::auth::kHeaderTimestamp,
             bazarish::auth::kHeaderSignatureClassical, bazarish::auth::kHeaderSignaturePq}) {
        if (request.hasHeader(name)) {
            headers[name] = request.header(name);
        }
    }
    return headers;
}

// The path portion of a request target, without the query string.
std::string pathOf(const std::string& target)
{
    return target.substr(0, target.find('?'));
}

Backend routeOf(const std::string& path)
{
    if (startsWith(path, "/v1/messaging/")) {
        return Backend::eMessaging;
    }
    // Session issue lives with the messaging server, because the key a session
    // secret is sealed to is the one that server holds.
    if (startsWith(path, "/v1/auth/")) {
        return Backend::eMessaging;
    }
    if (startsWith(path, "/v1/account/")) {
        return Backend::eAccount;
    }
    return Backend::eNone;
}

struct Route {
    Backend backend = Backend::eNone;
    std::string host;
    int port = 0;
    std::string target;  // request target with the secret base path stripped
};

// Resolves the backend and stripped target for a request. Returns nullopt and
// sets a 404 on the response when the base path is wrong or the path is not one
// the facade forwards.
std::optional<Route> resolveRoute(
    const bazarish::facade::FacadeOptions& options, const bazarish::http::Request& request)
{
    std::string target = request.target;
    if (!options.basePath.empty()) {
        if (!startsWith(target, options.basePath)) {
            return std::nullopt;
        }
        target = target.substr(options.basePath.size());
    }

    Route route;
    route.backend = routeOf(pathOf(target));
    route.target = target;
    switch (route.backend) {
    case Backend::eMessaging:
        route.host = options.messagingHost;
        route.port = options.messagingPort;
        break;
    case Backend::eAccount:
        route.host = options.accountHost;
        route.port = options.accountPort;
        break;
    case Backend::eNone:
        return std::nullopt;
    }
    return route;
}

// The 404 every refusal looks like: bare, with no body and no content type. An
// unknown base path and an unroutable path answer identically, and neither says
// what is behind them - an error envelope with our own code would.
bazarish::http::Response notFound()
{
    return {404, "", {}, ""};
}

bazarish::http::Response gatewayFailure()
{
    // The facade is a dumb pipe: a backend that did not answer is a gateway
    // failure, not a protocol error of the caller's.
    return {502, "application/json", {},
        R"({"error":{"code":"FACADE_UPSTREAM","message":"backend unreachable"}})"};
}

}  // namespace

Facade::Facade(FacadeOptions options)
    : options_(std::move(options))
    , startedAt_(nowSeconds())
{
}

Facade::~Facade()
{
    stop();
}

bool Facade::listen(const std::string& host, const int port)
{
    return bind(host, port) && listenAfterBind();
}

bool Facade::bind(const std::string& host, const int port)
{
    return bindToAnyPort(host, port) > 0;
}

int Facade::bindToAnyPort(const std::string& host)
{
    return bindToAnyPort(host, 0);
}

int Facade::bindToAnyPort(const std::string& host, const int port)
{
    bazarish::http::Server::Options options;
    options.host = host;
    options.port = port;
    // A forwarded long poll is held here as well, so the front has to be able to
    // wait without spending a thread on each client.
    options.readTimeout = std::chrono::seconds(kUpstreamTimeoutSeconds + 30);
    http_ = std::make_unique<bazarish::http::Server>(options);
    setupRoutes();
    try {
        return http_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("facade cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

bool Facade::listenAfterBind()
{
    std::unique_lock<std::mutex> lock(stopMutex_);
    stopCv_.wait(lock, [this]() { return stopping_; });
    return true;
}

bool Facade::bindOps(const std::string& host, const int port)
{
    return bindOpsToAnyPort(host, port) > 0;
}

int Facade::bindOpsToAnyPort(const std::string& host)
{
    return bindOpsToAnyPort(host, 0);
}

int Facade::bindOpsToAnyPort(const std::string& host, const int port)
{
    bazarish::http::Server::Options options;
    options.host = host;
    options.port = port;
    options.threads = 1;  // one operator poller, not a crowd
    ops_ = std::make_unique<bazarish::http::Server>(options);
    setupOpsRoutes();
    try {
        return ops_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("facade ops cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

bool Facade::listenOpsAfterBind()
{
    std::unique_lock<std::mutex> lock(stopMutex_);
    stopCv_.wait(lock, [this]() { return stopping_; });
    return true;
}

void Facade::stop()
{
    {
        const std::lock_guard<std::mutex> lock(stopMutex_);
        stopping_ = true;
    }
    stopCv_.notify_all();
    if (http_) {
        http_->stop();
    }
    if (ops_) {
        ops_->stop();
    }
}

void Facade::setupRoutes()
{
    // Buffered catch-all for the methods whose bodies are small (or empty):
    // strip the secret base path, route by prefix and relay verbatim.
    const auto handler = [this](const bazarish::http::Request& request,
                             bazarish::http::Responder respond)
        -> std::optional<bazarish::http::Response> {
        const std::optional<Route> route = resolveRoute(options_, request);
        if (!route.has_value()) {
            return notFound();
        }
        bazarish::http::ClientRequest forwarded;
        forwarded.method = request.method;
        forwarded.target = route->target;
        forwarded.headers = request.headers;
        forwarded.body = request.body;
        // Hop-by-hop headers belong to the connection we received on, not to the
        // one we are about to open, and the client below frames the body itself.
        for (const char* const hop : {"host", "connection", "keep-alive", "proxy-connection",
                 "transfer-encoding", "content-length", "upgrade", "te", "trailer"}) {
            forwarded.headers.erase(hop);
        }

        // Forwarded on the front's own loop: a backend that holds the request
        // open (the event face does, by design) holds a coroutine here, not a
        // thread, so one waiting client costs what one timer costs.
        boost::asio::co_spawn(
            http_->executor(),
            [executor = http_->executor(), host = route->host, port = route->port,
                forwarded = std::move(forwarded), respond]() -> boost::asio::awaitable<void> {
                const bazarish::http::Response upstream = co_await bazarish::http::fetch(
                    executor, host, port, forwarded, std::chrono::seconds(kUpstreamTimeoutSeconds));
                respond(upstream.status == 0 ? gatewayFailure() : upstream);
            },
            boost::asio::detached);
        return std::nullopt;  // answered when the backend does
    };

    // Register the catch-all for the methods the API uses. Nothing streams
    // through the facade any more: the only large payload there ever was - a file
    // upload - now goes directly between clients.
    for (const char* const method : {"GET", "POST", "PUT", "DELETE"}) {
        http_->routeAsync(method, "(.*)", handler);
    }
}

void Facade::setupOpsRoutes()
{
    // Operator-signed liveness for the admin panel, answered locally and served
    // on the ops socket only: on the public one it would identify the host as a
    // facade to anyone who does not know the secret base path.
    ops_->get("/healthz",
        [this](const bazarish::http::Request& request) -> bazarish::http::Response {
            try {
                bazarish::auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(),
                    request.method, request.path, bazarish::Bytes(), options_.operatorFingerprints);
            } catch (const std::exception& error) {
                bazarish::log::debug("ops healthz refused: {}", error.what());
                return {403, "application/json", {},
                    R"({"error":{"message":"operator authentication required"}})"};
            }
            return {200, "application/json", {},
                health::reportJson("facade", options_.version, startedAt_, nowSeconds())};
        });
}

}  // namespace bazarish::facade
