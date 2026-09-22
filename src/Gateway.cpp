// Bazarish project (c) 2026
#include "Gateway.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/Log.hpp>

#include <utility>

namespace bazarish::gateway {

namespace {

// Below this a decoy answers as a page, above it as a picture. A host serves
// both, and one size of answer for everything is a pattern of its own.
constexpr std::size_t kDecoyPageBytes = 32 * 1024;

// The listener carries WebSocket messages a frame at a time, and a frame has a
// cap of its own.
constexpr std::size_t kSocketMessageBytes = kMaxFrameBytes;

std::size_t drawBetween(const std::size_t low, const std::size_t high)
{
    if (high <= low) {
        return low;
    }
    const Bytes draw = randomBytes(sizeof(std::uint64_t));
    std::uint64_t value = 0;
    for (const unsigned char byte : draw) {
        value = (value << 8) | byte;
    }
    return low + static_cast<std::size_t>(value % (high - low + 1));
}

}  // namespace

Gateway::Gateway(Settings settings, i2p::Router& router)
    : settings_(std::move(settings))
    , router_(router)
    , server_([&]() {
        http::Server::Options options;
        options.host = settings_.listenHost;
        options.port = settings_.listenPort;
        return options;
    }())
{
}

Gateway::~Gateway()
{
    stop();
}

http::Response Gateway::notFound() const
{
    http::Response response;
    response.status = 404;
    response.contentType = "text/html";
    response.headers["Server"] = settings_.serverName;
    response.body = settings_.notFoundBody;
    return response;
}

bool Gateway::admitted(const http::Request& request) const
{
    if (request.path != settings_.basePath) {
        return false;
    }
    return service::constantTimeEqual(request.header(kTokenHeader), settings_.token);
}

http::Response Gateway::decoy() const
{
    const std::size_t size = drawBetween(settings_.decoyMinBytes, settings_.decoyMaxBytes);
    const Bytes noise = randomBytes(size);
    http::Response response;
    response.status = 200;
    response.contentType = size < kDecoyPageBytes ? "text/html" : "image/jpeg";
    response.headers["Server"] = settings_.serverName;
    response.body.assign(noise.begin(), noise.end());
    return response;
}

int Gateway::start()
{
    http::SocketRoutes routes;
    routes.subprotocol = kSubprotocol;
    routes.maxMessageBytes = kSocketMessageBytes;
    routes.idleTimeout = kKeepalive + kPongTimeout;
    routes.admit = [this](const http::Request& request) -> std::optional<http::Response> {
        if (!admitted(request)) {
            return notFound();
        }
        return std::nullopt;
    };
    routes.opened
        = [this](const http::SocketPtr& socket, const http::Request& request) {
              socketOpened(socket, request);
          };
    routes.message = [this](const http::SocketPtr& socket,
                         const std::vector<unsigned char>& message) {
        socketMessage(socket, message);
    };
    routes.closed = [this](const http::SocketPtr& socket) { socketClosed(socket); };
    server_.upgrade(settings_.basePath, std::move(routes));

    // A decoy is an ordinary request to the same place under the same token.
    // Everything else, at any path and by any method, is the one 404.
    const http::Handler answer = [this](const http::Request& request) {
        return admitted(request) ? decoy() : notFound();
    };
    for (const char* method : {"GET", "POST", "PUT", "DELETE", "HEAD"}) {
        server_.route(method, "(.*)", answer);
    }
    return server_.start();
}

void Gateway::stop()
{
    server_.stop();
}

int Gateway::port() const
{
    return server_.port();
}

void Gateway::socketOpened(const http::SocketPtr& socket, const http::Request& request)
{
    const std::int64_t now = nowSeconds();
    const std::string cookie = request.header(kSessionHeader);
    bool full = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        sessions_.sweep(now);
        Connection connection;
        if (!cookie.empty()) {
            connection.session = sessions_.find(cookie, now);
            connection.resumed = connection.session != nullptr;
        }
        if (connection.session == nullptr) {
            // A cookie that names nothing is not an error. The client is told
            // in one field that everything it had is gone, and treats it as a
            // router that restarted.
            connection.session = sessions_.open(now);
        }
        if (connection.session->full()) {
            full = true;
        } else {
            connection.session->addSocket();
            connections_.emplace(socket.get(), connection);
        }
    }
    if (full) {
        fail(socket, 0, Fault::eRefused, "this session holds as many sockets as it may");
        socket->close();
    }
}

void Gateway::socketClosed(const http::SocketPtr& socket)
{
    const std::int64_t now = nowSeconds();
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = connections_.find(socket.get());
    if (found == connections_.end()) {
        return;
    }
    found->second.session->removeSocket(now);
    connections_.erase(found);
}

void Gateway::fail(const http::SocketPtr& socket, const std::uint32_t ref, const Fault fault,
    const std::string& why)
{
    const nlohmann::json body = {{"code", faultName(fault)}, {"message", why}};
    socket->send(encodeJson(FrameType::eError, ref, body));
}

void Gateway::socketMessage(
    const http::SocketPtr& socket, const std::vector<unsigned char>& message)
{
    try {
        onFrame(socket, decode(message.data(), message.size()));
    } catch (const ProtocolError& error) {
        // A gateway that ignores what it does not understand is a gateway that
        // silently does half of what was asked.
        fail(socket, 0, error.fault(), error.what());
        socket->close();
    } catch (const std::exception& error) {
        bazarish::log::warn("gateway: a frame ended badly: {}", error.what());
        fail(socket, 0, Fault::eInternal, "the gateway failed at this");
        socket->close();
    }
}

void Gateway::onFrame(const http::SocketPtr& socket, const Frame& frame)
{
    if (frame.type == FrameType::eHello) {
        onHello(socket, frame);
        return;
    }
    fail(socket, frame.ref, Fault::eUnsupported,
        std::string(frameTypeName(frame.type)) + " is not served yet");
}

void Gateway::onHello(const http::SocketPtr& socket, const Frame& frame)
{
    const nlohmann::json body = bodyJson(frame);
    const int version = body.value("version", 0);
    if (version != kProtocolVersion) {
        // One version, so there is nothing to negotiate.
        fail(socket, frame.ref, Fault::eVersion, "this gateway speaks version 1");
        socket->close();
        return;
    }

    Connection connection;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = connections_.find(socket.get());
        if (found == connections_.end()) {
            return;
        }
        if (found->second.greeted) {
            fail(socket, frame.ref, Fault::eBadFrame, "this socket has already said hello");
            socket->close();
            return;
        }
        found->second.greeted = true;
        connection = found->second;
    }

    const nlohmann::json ready = {
        {"version", kProtocolVersion},
        {"i2pd", i2p::routerVersion()},
        {"capabilities",
            {{"routerCounters", true}, {"destinationCounters", true}, {"netDbSample", false},
                {"proxy", false}, {"offlineKeys", false}}},
        {"session", connection.session->cookie()},
        {"resumed", connection.resumed},
        {"endpoints", nlohmann::json::array()},
        {"streams", nlohmann::json::array()},
        {"lost", nlohmann::json::array()},
    };
    socket->send(encodeJson(FrameType::eReady, frame.ref, ready));
}

}  // namespace bazarish::gateway
