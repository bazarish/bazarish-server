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
    eBlobStorage,
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
    // Only the blob upload endpoint is public. The operator quota endpoint
    // (/v1/storage/quota) and the I2P-only download paths (/b/*) are never
    // forwarded to the clearnet facade.
    if (startsWith(path, "/v1/storage/blob")) {
        return Backend::eBlobStorage;
    }
    return Backend::eNone;
}

// Monotonic counter giving each streamed upload a unique spool filename.
std::atomic<std::uint64_t> g_spoolCounter{0};

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
    case Backend::eBlobStorage:
        route.host = options.blobStorageHost;
        route.port = options.blobStoragePort;
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
    , startedAt_(nowSeconds())
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

    // PUT carries the large blob upload, so it is streamed: the body is read
    // through a content reader and relayed without the facade ever holding the
    // whole blob in memory. The blob upload is spooled to a temp file and then
    // streamed on to the backend through a content provider; any other PUT
    // (small) is buffered and forwarded like the catch-all.
    const auto putHandler = [this](const httplib::Request& request, httplib::Response& response,
                                const httplib::ContentReader& reader) {
        const std::optional<Route> route = resolveRoute(options_, request, response);
        if (!route.has_value()) {
            return;  // 404 already set
        }
        httplib::Client client(route->host, route->port);
        client.set_keep_alive(false);

        // Forward the inbound headers minus the ones the client regenerates for
        // the upstream request (host and the framing headers a content provider
        // sets itself).
        httplib::Headers forwardHeaders;
        for (const auto& [key, value] : request.headers) {
            if (key == "Host" || key == "Content-Length" || key == "Transfer-Encoding") {
                continue;
            }
            forwardHeaders.emplace(key, value);
        }
        std::string contentType = "application/octet-stream";
        if (request.has_header("Content-Type")) {
            contentType = request.get_header_value("Content-Type");
        }

        if (route->backend != Backend::eBlobStorage) {
            // Small body: buffer and forward like the catch-all.
            std::string body;
            reader([&body](const char* const data, const std::size_t length) {
                body.append(data, length);
                return true;
            });
            httplib::Request forwarded;
            forwarded.method = request.method;
            forwarded.path = route->target;
            forwarded.headers = forwardHeaders;
            forwarded.body = std::move(body);
            httplib::Result upstream = client.send(forwarded);
            copyResponse(upstream, response);
            return;
        }

        // Spool the blob to a temp file on the facade so it is never held whole in
        // memory, then stream it on to the backend.
        const std::filesystem::path tempPath = std::filesystem::temp_directory_path()
            / ("bazarish-facade-" + std::to_string(g_spoolCounter.fetch_add(1)) + ".part");
        std::uint64_t size = 0;
        try {
            std::ofstream out(tempPath, std::ios::binary | std::ios::trunc);
            if (!out) {
                throw std::runtime_error("cannot open facade spool file");
            }
            reader([&out, &size](const char* const data, const std::size_t length) {
                out.write(data, static_cast<std::streamsize>(length));
                if (!out) {
                    return false;
                }
                size += length;
                return true;
            });
            out.flush();
            if (!out) {
                throw std::runtime_error("writing facade spool file failed");
            }
        } catch (const std::exception&) {
            std::error_code ec;
            std::filesystem::remove(tempPath, ec);
            response.status = 502;
            response.set_content("{\"error\":{\"code\":\"FACADE_UPSTREAM\",\"message\":"
                                 "\"facade spool failed\"}}",
                "application/json");
            return;
        }

        const auto file = std::make_shared<std::ifstream>(tempPath, std::ios::binary);
        if (!file || !*file) {
            std::error_code ec;
            std::filesystem::remove(tempPath, ec);
            response.status = 502;
            response.set_content("{\"error\":{\"code\":\"FACADE_UPSTREAM\",\"message\":"
                                 "\"facade spool reopen failed\"}}",
                "application/json");
            return;
        }
        const httplib::ContentProvider provider
            = [file](const std::size_t offset, const std::size_t want, httplib::DataSink& sink) {
                  file->clear();
                  file->seekg(static_cast<std::streamoff>(offset));
                  std::array<char, 64 * 1024> buffer;
                  std::size_t remaining = want;
                  while (remaining > 0) {
                      const std::streamsize chunk = static_cast<std::streamsize>(
                          std::min<std::size_t>(remaining, buffer.size()));
                      file->read(buffer.data(), chunk);
                      const std::streamsize got = file->gcount();
                      if (got <= 0) {
                          break;
                      }
                      if (!sink.write(buffer.data(), static_cast<std::size_t>(got))) {
                          return false;
                      }
                      remaining -= static_cast<std::size_t>(got);
                  }
                  return true;
              };
        httplib::Result upstream = client.Put(
            route->target, forwardHeaders, static_cast<std::size_t>(size), provider, contentType);
        copyResponse(upstream, response);
        std::error_code ec;
        std::filesystem::remove(tempPath, ec);
    };

    // Authenticated liveness for the admin panel, answered locally (never
    // forwarded). Registered before the catch-all so it wins the match. Gated by
    // an operator secret, so it leaks nothing to an unauthenticated caller and
    // ignores the secret base path (it lives on the private ops socket).
    http_->Get("/healthz", [this](const httplib::Request& request, httplib::Response& response) {
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

    // Register the catch-all for the methods the API uses; PUT is streamed.
    http_->Get(".*", handler);
    http_->Post(".*", handler);
    http_->Delete(".*", handler);
    http_->Put(".*", putHandler);
}

}  // namespace bazarish::facade
