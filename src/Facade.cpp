// Bazarish project (c) 2026
#include "Facade.hpp"

#include <httplib/httplib.h>

#include <string>

namespace bazarish::facade {

namespace {

// Backends a request can be routed to.
enum class Backend {
    kNone,
    kMessaging,
    kAccount,
};

bool startsWith(const std::string& text, const std::string& prefix)
{
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

// The path portion of a request target, without the query string.
std::string pathOf(const std::string& target)
{
    return target.substr(0, target.find('?'));
}

Backend routeOf(const std::string& path)
{
    if (startsWith(path, "/v1/messaging/") || startsWith(path, "/v1/content")) {
        return Backend::kMessaging;
    }
    if (startsWith(path, "/v1/account/")) {
        return Backend::kAccount;
    }
    return Backend::kNone;
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
{
    setupRoutes();
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

void Facade::stop()
{
    http_->stop();
}

void Facade::setupRoutes()
{
    // A single catch-all forwards every method transparently. The handler
    // strips the secret base path, routes by prefix and relays the request
    // verbatim (method, headers, body, query) to the chosen backend.
    const auto handler = [this](const httplib::Request& request, httplib::Response& response) {
        std::string target = request.target;
        if (!options_.basePath.empty()) {
            if (!startsWith(target, options_.basePath)) {
                response.status = 404;
                return;
            }
            target = target.substr(options_.basePath.size());
        }

        const Backend backend = routeOf(pathOf(target));
        if (backend == Backend::kNone) {
            response.status = 404;
            return;
        }

        const bool messaging = backend == Backend::kMessaging;
        httplib::Client client(messaging ? options_.messagingHost : options_.accountHost,
            messaging ? options_.messagingPort : options_.accountPort);
        client.set_keep_alive(false);

        httplib::Request forwarded;
        forwarded.method = request.method;
        forwarded.path = target;
        forwarded.headers = request.headers;
        forwarded.body = request.body;
        // Drop the inbound Host header; the client sets its own.
        forwarded.headers.erase("Host");

        httplib::Result upstream = client.send(forwarded);
        copyResponse(upstream, response);
    };

    // Register the catch-all for the methods the API uses.
    http_->Get(".*", handler);
    http_->Post(".*", handler);
    http_->Delete(".*", handler);
    http_->Put(".*", handler);
}

}  // namespace bazarish::facade
