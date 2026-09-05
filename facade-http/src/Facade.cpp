// Bazarish project (c) 2026
#include "Facade.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Tunnel.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Health.hpp>

#include <bazarish/HttpClient.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>

#include <utility>

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
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <string>
#include <system_error>

namespace bazarish::facade {

namespace {

// What a listener may be told to bind, and how many destinations one facade may
// be asked to publish. The port range is TCP's without 0, which means "any free
// port"; the destination ceiling is a guard against a typo that would have the
// facade build tunnels for hours.
constexpr int kMinPort = 1;
constexpr int kMaxPort = 65535;
constexpr int kMaxI2pDestinations = 8;


// How long the facade waits on a backend. Longer than the event face's own cap,
// so a held request is answered by the backend rather than cut short here.
constexpr int kUpstreamTimeoutSeconds = 60;


// Backends a request can be routed to.
enum class Backend {
    eNone,
    eMessaging,
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

// Three paths, and nothing else exists as far as this program is concerned.
//
// A client speaks to its server through one of them - a sealed tunnel - and this
// process cannot read a byte of what it carries: not who is calling, not what
// they are asking, not what comes back. It cannot even tell an account call from
// a message being fetched. That is the point: this is the least trusted piece of
// the system, and it now holds nothing worth taking.
//
// The other two are public by nature and identical for every caller, so serving
// them tells nobody anything: the signed server card, which is what lets a client
// seal the tunnel in the first place, and the reseed archive, which is what a
// client with no I2P yet bootstraps from and therefore cannot be behind I2P.
Backend routeOf(const std::string& method, const std::string& path)
{
    if (method == "POST" && path == bazarish::tunnel::kTunnelPath) {
        return Backend::eMessaging;
    }
    if (method == "GET"
        && (path == bazarish::tunnel::kServerCardPath || path == "/v1/messaging/reseed")) {
        return Backend::eMessaging;
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
    route.backend = routeOf(request.method, pathOf(target));
    route.target = target;
    switch (route.backend) {
    case Backend::eMessaging:
        route.host = options.messagingHost;
        route.port = options.messagingPort;
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
        load_.record(nowSeconds());
        const std::optional<Route> route = resolveRoute(options_, request);
        if (!route.has_value()) {
            return notFound();
        }
        // The request is in flight until the backend answers and the reply goes
        // out; the guard rides along with the coroutine below.
        const auto inFlight = std::make_shared<Load::InFlight>(load_);
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
                forwarded = std::move(forwarded), respond, inFlight]() -> boost::asio::awaitable<void> {
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
            // The health report plus what this facade is carrying: three counts
            // and a gauge, sampled now, kept nowhere.
            const Load::Sample sample = load_.sample(nowSeconds());
            nlohmann::json report = nlohmann::json::parse(
                health::reportJson("facade", options_.version, startedAt_, nowSeconds()));
            report["requestsLastMinute"] = sample.lastMinute;
            report["requestsLastHour"] = sample.lastHour;
            report["requestsLastDay"] = sample.lastDay;
            report["requestsTotal"] = sample.total;
            report["inFlight"] = sample.inFlight;
            return {200, "application/json", {}, report.dump()};
        });

    // The facade's own configuration, on the ops socket for the same reason
    // /healthz is: the public socket must not admit that a facade is here.
    const auto operatorRejection
        = [this](const bazarish::http::Request& request)
        -> std::optional<bazarish::http::Response> {
        try {
            bazarish::auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(),
                request.method, request.path,
                bazarish::Bytes(request.body.begin(), request.body.end()),
                options_.operatorFingerprints);
            return std::nullopt;
        } catch (const std::exception& error) {
            bazarish::log::debug("ops call refused: {}", error.what());
            return bazarish::http::Response{403, "application/json", {},
                R"({"error":{"message":"operator authentication required"}})"};
        }
    };

    const auto refuse = [](const int status, const std::string& message) {
        return bazarish::http::Response{status, "application/json", {},
            nlohmann::json{{"error", {{"message", message}}}}.dump()};
    };

    ops_->get("/settings",
        [this, operatorRejection, refuse](
            const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            if (!options_.settings) {
                return refuse(503, "this facade was started without a config file to write to");
            }
            const FacadeSettings::Values values = options_.settings->get();
            return {200, "application/json", {},
                nlohmann::json{
                    {"logLevel", values.logLevel},
                    {"basePath", values.basePath},
                    {"messaging", {{"host", values.messagingHost},
                                      {"port", values.messagingPort}}},
                    {"account", {{"host", values.accountHost}, {"port", values.accountPort}}},
                    {"listen", {{"host", values.listenHost}, {"port", values.listenPort}}},
                    {"opsListen", {{"host", values.opsHost}, {"port", values.opsPort}}},
                    {"i2pEnabled", values.i2pEnabled},
                    {"i2pDestinations", values.i2pDestinations},
                    {"i2pPrivacy", values.i2pPrivacy},
                    {"i2pTunnelQuantity", values.i2pTunnelQuantity},
                    {"stateDirectory", options_.stateDirectory},
                    {"version", options_.version},
                    {"canRestart", static_cast<bool>(options_.requestRestart)},
                }
                    .dump()};
        });

    ops_->put("/settings",
        [this, operatorRejection, refuse](
            const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            if (!options_.settings) {
                return refuse(503, "this facade was started without a config file to write to");
            }
            FacadeSettings::Values values = options_.settings->get();
            try {
                const nlohmann::json body = nlohmann::json::parse(request.body);
                if (body.contains("logLevel")) {
                    const std::string level = body.at("logLevel").get<std::string>();
                    if (!bazarish::log::levelFromString(level).has_value()) {
                        throw std::invalid_argument("not a log level: " + level);
                    }
                    values.logLevel = level;
                }
                if (body.contains("basePath")) {
                    const std::string path = body.at("basePath").get<std::string>();
                    // The one field here that is a secret. An empty one is only
                    // legitimate when a fronting proxy owns it, and that is a
                    // decision made in the config file, not in a browser.
                    if (path.empty() || !isValidBasePath(path)) {
                        throw std::invalid_argument(
                            "a base path looks like /8f1818f3/0966179fb196: one or more"
                            " slash-separated segments of letters, digits, '-' or '_'");
                    }
                    values.basePath = path;
                }
                const auto readEndpoint = [&body](const std::string& key, std::string& host,
                                              int& port) {
                    if (!body.contains(key)) {
                        return;
                    }
                    const nlohmann::json& endpoint = body.at(key);
                    const std::string wantedHost = endpoint.value("host", host);
                    const int wantedPort = endpoint.value("port", port);
                    if (wantedHost.empty()) {
                        throw std::invalid_argument("a " + key + " address needs a host");
                    }
                    if (wantedPort < kMinPort || wantedPort > kMaxPort) {
                        throw std::invalid_argument("a port is between "
                            + std::to_string(kMinPort) + " and " + std::to_string(kMaxPort));
                    }
                    host = wantedHost;
                    port = wantedPort;
                };
                readEndpoint("messaging", values.messagingHost, values.messagingPort);
                readEndpoint("account", values.accountHost, values.accountPort);
                readEndpoint("listen", values.listenHost, values.listenPort);
                readEndpoint("opsListen", values.opsHost, values.opsPort);
                if (body.contains("i2pEnabled")) {
                    values.i2pEnabled = body.at("i2pEnabled").get<bool>();
                }
                if (body.contains("i2pDestinations")) {
                    const int count = body.at("i2pDestinations").get<int>();
                    if (count < 1 || count > kMaxI2pDestinations) {
                        throw std::invalid_argument("a facade carries between 1 and "
                            + std::to_string(kMaxI2pDestinations) + " destinations");
                    }
                    values.i2pDestinations = count;
                }
                if (body.contains("i2pPrivacy")) {
                    const std::string named = body.at("i2pPrivacy").get<std::string>();
                    if (!bazarish::i2p::privacyFromString(named).has_value()) {
                        throw std::invalid_argument("not a privacy level: " + named);
                    }
                    values.i2pPrivacy = named;
                }
                if (body.contains("i2pTunnelQuantity")) {
                    const int quantity = body.at("i2pTunnelQuantity").get<int>();
                    if (quantity < 1 || quantity > bazarish::i2p::kMaxTunnelQuantity) {
                        throw std::invalid_argument("a destination carries between 1 and "
                            + std::to_string(bazarish::i2p::kMaxTunnelQuantity) + " tunnels");
                    }
                    values.i2pTunnelQuantity = quantity;
                }
            } catch (const nlohmann::json::exception& error) {
                return refuse(400, error.what());
            } catch (const std::invalid_argument& error) {
                return refuse(400, error.what());
            }

            const std::string levelBefore = options_.settings->get().logLevel;
            try {
                options_.settings->set(values);
            } catch (const std::exception& error) {
                return refuse(500, error.what());
            }
            if (values.logLevel != levelBefore) {
                if (const std::optional<bazarish::log::Level> level
                    = bazarish::log::levelFromString(values.logLevel);
                    level.has_value()) {
                    bazarish::log::setLevel(*level);
                }
            }
            return {200, "application/json", {},
                nlohmann::json{{"logLevel", values.logLevel}}.dump()};
        });

    ops_->post("/restart",
        [this, operatorRejection, refuse](
            const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            if (!options_.requestRestart) {
                return refuse(503,
                    "this facade cannot restart itself: it was started without a supervisor");
            }
            bazarish::log::info("restarting at the operator's request");
            options_.requestRestart();
            return {200, "application/json", {}, R"({"restarting":true})"};
        });
}

}  // namespace bazarish::facade
