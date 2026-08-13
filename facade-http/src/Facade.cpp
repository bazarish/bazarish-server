// Bazarish project (c) 2026
#include "Facade.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Health.hpp>

#include <httplib/httplib.h>

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
bazarish::auth::Headers collectAuthHeaders(const httplib::Request& request)
{
    bazarish::auth::Headers headers;
    for (const char* const name : {bazarish::auth::kHeaderKeys, bazarish::auth::kHeaderTimestamp,
             bazarish::auth::kHeaderSignatureClassical, bazarish::auth::kHeaderSignaturePq}) {
        if (request.has_header(name)) {
            headers[name] = request.get_header_value(name);
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
std::optional<Route> resolveRoute(const bazarish::facade::FacadeOptions& options,
    const httplib::Request& request, httplib::Response& response)
{
    std::string target = request.target;
    if (!options.basePath.empty()) {
        if (!startsWith(target, options.basePath)) {
            response.status = 404;
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
        response.status = 404;
        return std::nullopt;
    }
    return route;
}

// Copies the response from a backend result onto the client response.
void copyResponse(const httplib::Result& upstream, httplib::Response& response)
{
    if (!upstream) {
        // Backend unreachable: the facade is a dumb pipe, so this is a
        // gateway failure, not a protocol error.
        response.status = 502;
        response.set_content("{\"error\":{\"code\":\"FACADE_UPSTREAM\",\"message\":"
                             "\"backend unreachable\"}}",
            "application/json");
        return;
    }
    response.status = upstream->status;
    std::string contentType = "application/octet-stream";
    if (upstream->has_header("Content-Type")) {
        contentType = upstream->get_header_value("Content-Type");
    }
    response.set_content(upstream->body, contentType);
}

}  // namespace

Facade::Facade(FacadeOptions options)
    : options_(std::move(options))
    , http_(std::make_unique<httplib::Server>())
    , ops_(std::make_unique<httplib::Server>())
    , startedAt_(nowSeconds())
{
    setupRoutes();
    setupOpsRoutes();
}

Facade::~Facade() = default;

bool Facade::listen(const std::string& host, const int port)
{
    return http_->listen(host, port);
}

int Facade::bindToAnyPort(const std::string& host)
{
    return http_->bind_to_any_port(host);
}

bool Facade::listenAfterBind()
{
    return http_->listen_after_bind();
}

bool Facade::bindOps(const std::string& host, const int port)
{
    return ops_->bind_to_port(host, port);
}

int Facade::bindOpsToAnyPort(const std::string& host)
{
    return ops_->bind_to_any_port(host);
}

bool Facade::listenOpsAfterBind()
{
    return ops_->listen_after_bind();
}

void Facade::stop()
{
    http_->stop();
    ops_->stop();
}

void Facade::setupRoutes()
{
    // Buffered catch-all for the methods whose bodies are small (or empty):
    // strip the secret base path, route by prefix and relay verbatim.
    const auto handler = [this](const httplib::Request& request, httplib::Response& response) {
        const std::optional<Route> route = resolveRoute(options_, request, response);
        if (!route.has_value()) {
            return;  // 404 already set
        }
        httplib::Client client(route->host, route->port);
        client.set_keep_alive(false);

        httplib::Request forwarded;
        forwarded.method = request.method;
        forwarded.path = route->target;
        forwarded.headers = request.headers;
        forwarded.body = request.body;
        // Drop the inbound Host header; the client sets its own.
        forwarded.headers.erase("Host");

        httplib::Result upstream = client.send(forwarded);
        copyResponse(upstream, response);
    };

    // Register the catch-all for the methods the API uses. Nothing streams
    // through the facade any more: the only large payload there ever was - a file
    // upload - now goes directly between clients.
    http_->Get(".*", handler);
    http_->Post(".*", handler);
    http_->Delete(".*", handler);
    http_->Put(".*", handler);
}

void Facade::setupOpsRoutes()
{
    // Operator-signed liveness for the admin panel, answered locally and served
    // on the ops socket only: on the public one it would identify the host as a
    // facade to anyone who does not know the secret base path.
    ops_->Get("/healthz", [this](const httplib::Request& request, httplib::Response& response) {
        try {
            bazarish::auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(),
                request.method, request.path, bazarish::Bytes(),
                options_.operatorFingerprints);
        } catch (const std::exception&) {
            response.status = 403;
            response.set_content(
                "{\"error\":{\"message\":\"operator authentication required\"}}",
                "application/json");
            return;
        }
        response.set_content(
            health::reportJson("facade", options_.version, startedAt_, nowSeconds()),
            "application/json");
    });
}

}  // namespace bazarish::facade
