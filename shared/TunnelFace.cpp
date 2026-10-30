// Bazarish project (c) 2026
#include "TunnelFace.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Padding.hpp>
#include <bazarish/Tunnel.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <utility>

namespace bazarish::server {

namespace {

constexpr std::size_t kRefusalNoiseBytes = 64;
constexpr const char* kInternalPrefix = "/internal/";

std::string lowered(std::string name)
{
    std::transform(name.begin(), name.end(), name.begin(),
        [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return name;
}

Bytes bodyBytes(const http::Request& request)
{
    return Bytes(request.body.begin(), request.body.end());
}

http::Response errorResponse(const int status, const ErrorCode code, const std::string& message)
{
    return {status, "application/json", {}, makeErrorEnvelope(code, message).dump()};
}

bool namesTunnel(const std::string& path)
{
    return path == tunnel::kTunnelPath || path == tunnel::kNodeTunnelPath;
}

}  // namespace

TunnelFace::TunnelFace(std::shared_ptr<Key> sealingKey)
    : sealingKey_(std::move(sealingKey))
{
}

void TunnelFace::serve(
    const http::Request& request, http::Server& routes, http::Responder respond)
{
    const Bytes frame(request.body.begin(), request.body.end());
    const auto refuse = [respond]() {
        http::Response response;
        response.contentType = "application/octet-stream";
        const Bytes noise = padToLadder(randomBytes(kRefusalNoiseBytes));
        response.body = std::string(noise.begin(), noise.end());
        respond(std::move(response));
    };
    const auto sealed = [respond](const Bytes& body) {
        http::Response response;
        response.contentType = "application/octet-stream";
        response.body = std::string(body.begin(), body.end());
        respond(std::move(response));
    };

    if (tunnel::isHello(frame)) {
        if (!sealingKey_) {
            refuse();
            return;
        }
        try {
            const tunnel::Hello hello = tunnel::openHello(frame, *sealingKey_);
            const std::string user = auth::verifyRequest(hello.signature, nowSeconds(),
                tunnel::kHelloMethod, tunnel::kHelloPath, hello.secret, replays_);
            std::int64_t expiresUnix = 0;
            const std::string id = sessions_.open(user, hello.secret, nowSeconds(), &expiresUnix);
            sessions_.setTunnelKey(id, tunnel::deriveTunnelKey(hello.secret, id));
            sealed(tunnel::sealWelcome({expiresUnix}, Key::fromPublicDer(hello.replyKeyDer)));
        } catch (const std::exception& error) {
            log::debug("a tunnel did not open: {}", error.what());
            refuse();
        }
        return;
    }

    std::string handle;
    std::optional<SessionStore::Session> session;
    try {
        handle = tunnel::handleOf(frame);
        session = sessions_.findByHandle(handle, nowSeconds());
    } catch (const std::exception& error) {
        log::debug("tunnel frame not addressed to any tunnel: {}", error.what());
        refuse();
        return;
    }
    if (!session.has_value() || session->tunnelKey.empty()) {
        log::debug("tunnel frame names a tunnel this server does not hold");
        refuse();
        return;
    }
    http::Request carried;
    try {
        const tunnel::Request inner
            = tunnel::decodeRequest(tunnel::open(frame, session->tunnelKey));
        carried.method = inner.method;
        carried.path = inner.path;
        carried.target = inner.query.empty() ? inner.path : inner.path + "?" + inner.query;
        carried.body = std::string(inner.body.begin(), inner.body.end());
        for (const auto& [name, value] : inner.headers) {
            carried.headers[lowered(name)] = value;
        }
        if (!inner.contentType.empty()) {
            carried.headers["content-type"] = inner.contentType;
        }
    } catch (const std::exception& error) {
        log::debug("tunnel frame did not open: {}", error.what());
        refuse();
        return;
    }
    if (namesTunnel(carried.path)) {
        log::debug("a tunnel frame carried another tunnel frame");
        refuse();
        return;
    }
    if (carried.path.rfind(kInternalPrefix, 0) == 0) {
        log::debug("a tunnel frame named an internal path: {}", carried.path);
        refuse();
        return;
    }
    const Bytes tunnelKey = session->tunnelKey;
    routes.dispatch(carried,
        [respond = std::move(respond), handle, tunnelKey](http::Response answer) {
            tunnel::Response inner;
            inner.status = answer.status;
            inner.contentType = answer.contentType;
            inner.body = Bytes(answer.body.begin(), answer.body.end());
            const Bytes body = tunnel::carry(handle, tunnelKey, tunnel::encodeResponse(inner));
            http::Response outer;
            outer.contentType = "application/octet-stream";
            outer.body = std::string(body.begin(), body.end());
            respond(std::move(outer));
        });
}

std::optional<http::Response> TunnelFace::authenticate(
    const http::Request& request, std::string* const outUser)
{
    const auth::Headers authHeaders = http::collectAuthHeaders(request);
    const std::string clientId = request.header("X-Bazarish-Client");
    if (auth::hasSessionHeaders(authHeaders)) {
        const std::string handle = authHeaders.at(auth::kHeaderSession);
        const std::optional<SessionStore::Session> session
            = sessions_.findByHandle(handle, nowSeconds());
        if (!session.has_value()) {
            return errorResponse(401, ErrorCode::eSessionInvalid, "unknown or expired session");
        }
        try {
            const std::uint64_t seq = auth::verifyMac(authHeaders, session->key, nowSeconds(),
                request.method, request.path, bodyBytes(request), clientId);
            if (!sessions_.acceptSeq(handle, seq, nowSeconds())) {
                return errorResponse(401, ErrorCode::eSessionInvalid, "sequence replayed");
            }
        } catch (const std::exception& error) {
            return errorResponse(401, ErrorCode::eSessionInvalid, error.what());
        }
        *outUser = session->user;
        return std::nullopt;
    }
    try {
        *outUser = auth::verifyRequest(authHeaders, nowSeconds(), request.method, request.path,
            bodyBytes(request), replays_, clientId);
    } catch (const std::exception& error) {
        return errorResponse(401, ErrorCode::eRequestFailed, error.what());
    }
    return std::nullopt;
}

}  // namespace bazarish::server
