// Bazarish project (c) 2026
#include "Facade.hpp"
#include "FacadeAddress.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Tunnel.hpp>
#include <bazarish/Bytes.hpp>
#include <Health.hpp>

#include <bazarish/HttpClient.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/ConfigFile.hpp>
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

constexpr int kUpstreamTimeoutSeconds = 60;
constexpr int kFrontReadSlackSeconds = 30;

bool startsWith(const std::string& text, const std::string& prefix)
{
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

using bazarish::nowSeconds;

std::string pathOf(const std::string& target)
{
    return target.substr(0, target.find('?'));
}

bool isForwarded(const std::string& method, const std::string& path)
{
    return (method == "POST" && path == bazarish::tunnel::kTunnelPath)
        || (method == "GET" && path == bazarish::tunnel::kServerCardPath);
}

std::optional<std::string> forwardedTarget(
    const bazarish::facade::FacadeOptions& options, const bazarish::http::Request& request)
{
    if (!startsWith(request.target, options.basePath)) {
        return std::nullopt;
    }
    const std::string target = request.target.substr(options.basePath.size());
    if (!isForwarded(request.method, pathOf(target))) {
        return std::nullopt;
    }
    return target;
}

bazarish::http::Response notFound()
{
    return {404, "", {}, ""};
}

bazarish::http::Response refusal(const int status, const std::string& message)
{
    return {status, "application/json", {},
        nlohmann::json{{"error", {{"message", message}}}}.dump()};
}

bazarish::http::Response gatewayFailure()
{
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

int Facade::bind(const std::string& host, const int port)
{
    bazarish::http::Server::Options options;
    options.host = host;
    options.port = port;
    options.readTimeout = std::chrono::seconds(kUpstreamTimeoutSeconds + kFrontReadSlackSeconds);
    http_ = std::make_unique<bazarish::http::Server>(options);
    setupRoutes(*http_);
    try {
        return http_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("facade cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

int Facade::bindDirect(const std::string& host, const int port)
{
    bazarish::http::Server::Options options;
    options.host = host;
    options.port = port;
    options.readTimeout = std::chrono::seconds(kUpstreamTimeoutSeconds + kFrontReadSlackSeconds);
    options.certificate = options_.tlsCertificate;
    options.key = options_.tlsKey;
    direct_ = std::make_unique<bazarish::http::Server>(options);
    setupRoutes(*direct_);
    try {
        return direct_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

int Facade::bindOps(const std::string& host, const int port)
{
    bazarish::http::Server::Options options;
    options.host = host;
    options.port = port;
    options.threads = 1;
    options.certificate = options_.tlsCertificate;
    options.key = options_.tlsKey;
    options.clientPins = options_.opsClientPins;
    ops_ = std::make_unique<bazarish::http::Server>(options);
    setupOpsRoutes();
    try {
        return ops_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("facade ops cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

void Facade::wait()
{
    stopGate_.wait();
}

void Facade::stop()
{
    stopGate_.stop();
    if (http_) {
        http_->stop();
    }
    if (direct_) {
        direct_->stop();
    }
    if (ops_) {
        ops_->stop();
    }
}

void Facade::setupRoutes(bazarish::http::Server& server)
{
    const auto handler = [this, &server](const bazarish::http::Request& request,
                             bazarish::http::Responder respond)
        -> std::optional<bazarish::http::Response> {
        load_.record(nowSeconds());
        const std::optional<std::string> target = forwardedTarget(options_, request);
        if (!target.has_value()) {
            return notFound();
        }
        const auto inFlight = std::make_shared<Load::InFlight>(load_);
        bazarish::http::ClientRequest forwarded;
        forwarded.method = request.method;
        forwarded.target = *target;
        forwarded.headers = request.headers;
        forwarded.body = request.body;
        for (const char* const hop : {"host", "connection", "keep-alive", "proxy-connection",
                 "transfer-encoding", "content-length", "upgrade", "te", "trailer"}) {
            forwarded.headers.erase(hop);
        }

        boost::asio::co_spawn(
            server.executor(),
            [executor = server.executor(), host = options_.messagingHost,
                port = options_.messagingPort, pin = options_.messagingPin,
                forwarded = std::move(forwarded), respond,
                inFlight]() -> boost::asio::awaitable<void> {
                bazarish::http::ClientOptions upstreamOptions;
                upstreamOptions.tls = true;
                upstreamOptions.pin = pin;
                upstreamOptions.connectTimeout = std::chrono::seconds(kUpstreamTimeoutSeconds);
                upstreamOptions.readTimeout = std::chrono::seconds(kUpstreamTimeoutSeconds);
                upstreamOptions.writeTimeout = std::chrono::seconds(kUpstreamTimeoutSeconds);
                const bazarish::http::Response upstream = co_await bazarish::http::fetch(
                    executor, host, port, forwarded, upstreamOptions);
                respond(upstream.status == 0 ? gatewayFailure() : upstream);
            },
            boost::asio::detached);
        return std::nullopt;
    };

    for (const char* const method : {"GET", "POST", "PUT", "DELETE"}) {
        server.routeAsync(method, "(.*)", handler);
    }
}

void Facade::setupOpsRoutes()
{
    const auto operatorOnly = [this](auto handler) {
        return [this, handler](
                   const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused
                = bazarish::http::operatorRefusal(request, nowSeconds(),
                    options_.operatorFingerprints, operatorReplays_);
                refused.has_value()) {
                return *refused;
            }
            try {
                return handler(request);
            } catch (const nlohmann::json::exception& error) {
                return refusal(400, error.what());
            } catch (const std::invalid_argument& error) {
                return refusal(400, error.what());
            }
        };
    };

    ops_->get("/healthz", operatorOnly([this](const bazarish::http::Request&) {
        const Load::Sample sample = load_.sample(nowSeconds());
        nlohmann::json report = nlohmann::json::parse(
            health::reportJson("facade", options_.version, startedAt_, nowSeconds()));
        report["requestsLastMinute"] = sample.lastMinute;
        report["requestsLastHour"] = sample.lastHour;
        report["requestsLastDay"] = sample.lastDay;
        report["requestsTotal"] = sample.total;
        report["inFlight"] = sample.inFlight;
        return bazarish::http::Response{200, "application/json", {}, report.dump()};
    }));

    ops_->get("/settings", operatorOnly([this](const bazarish::http::Request&) {
        if (!options_.settings) {
            return refusal(503, "this facade was started without a config file to write to");
        }
        const FacadeSettings::Values values = options_.settings->get();
        return bazarish::http::Response{200, "application/json", {},
            nlohmann::json{
                {"logLevel", values.logLevel},
                {"url", options_.url},
                {"messaging", {{"host", values.messagingHost}, {"port", values.messagingPort}}},
                {"listen", {{"host", values.listenHost}, {"port", values.listenPort}}},
                {"opsListen", {{"host", values.opsHost}, {"port", values.opsPort}}},
                {"directListen", {{"host", values.directHost}, {"port", values.directPort}}},
                {"i2pPrivacy", values.i2pPrivacy},
                {"i2pTunnelQuantity", values.i2pTunnelQuantity},
                {"i2pTunnelQuantityMax", bazarish::i2p::kMaxTunnelQuantity},
                {"stateDirectory", options_.stateDirectory},
                {"version", options_.version},
            }
                .dump()};
    }));

    ops_->put("/settings", operatorOnly([this](const bazarish::http::Request& request) {
        if (!options_.settings) {
            return refusal(503, "this facade was started without a config file to write to");
        }
        FacadeSettings::Values values = options_.settings->get();
        const nlohmann::json body = nlohmann::json::parse(request.body);
        if (body.contains("logLevel")) {
            const std::string level = body.at("logLevel").get<std::string>();
            if (!bazarish::log::levelFromString(level).has_value()) {
                throw std::invalid_argument("not a log level: " + level);
            }
            values.logLevel = level;
        }
        readEndpointInto(body, "messaging", values.messagingHost, values.messagingPort);
        readEndpointInto(body, "listen", values.listenHost, values.listenPort);
        readEndpointInto(body, "opsListen", values.opsHost, values.opsPort);
        readEndpointInto(body, "directListen", values.directHost, values.directPort);
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

        const std::string levelBefore = options_.settings->get().logLevel;
        try {
            options_.settings->set(values);
        } catch (const std::exception& error) {
            return refusal(500, error.what());
        }
        if (values.logLevel != levelBefore) {
            if (const std::optional<bazarish::log::Level> level
                = bazarish::log::levelFromString(values.logLevel);
                level.has_value()) {
                bazarish::log::setLevel(*level);
            }
        }
        return bazarish::http::Response{200, "application/json", {},
            nlohmann::json{{"logLevel", values.logLevel}}.dump()};
    }));

    ops_->post("/new-address", operatorOnly([this](const bazarish::http::Request&) {
        if (!options_.requestRestart) {
            return refusal(
                503, "this facade cannot restart itself: it was started without a supervisor");
        }
        const FacadeAddress minted = mintAddress(options_.stateDirectory);
        bazarish::log::info("new address minted, restarting to publish it: {}", minted.url());
        options_.requestRestart();
        return bazarish::http::Response{200, "application/json", {},
            nlohmann::json{{"url", minted.url()}, {"previousUrl", options_.url},
                {"restarting", true}}
                .dump()};
    }));

    ops_->post("/restart", operatorOnly([this](const bazarish::http::Request&) {
        if (!options_.requestRestart) {
            return refusal(
                503, "this facade cannot restart itself: it was started without a supervisor");
        }
        bazarish::log::info("restarting at the operator's request");
        options_.requestRestart();
        return bazarish::http::Response{200, "application/json", {}, R"({"restarting":true})"};
    }));
}

}  // namespace bazarish::facade
