// Bazarish project (c) 2026
#include "Gateway.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Health.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/Log.hpp>

#include <algorithm>
#include <set>
#include <thread>
#include <utility>
#include <vector>

namespace bazarish::gateway {

namespace {

// Below this a decoy answers as a page, above it as a picture. A host serves
// both, and one size of answer for everything is a pattern of its own.
constexpr std::size_t kDecoyPageBytes = 32 * 1024;

// The listener carries WebSocket messages a frame at a time, and a frame has a
// cap of its own.
constexpr std::size_t kSocketMessageBytes = kMaxFrameBytes;

// How long a control socket that has just said hello is held back from sending
// anything of its own. The resume it is waiting for is the client's next frame,
// so this is only the backstop for a client that sends none - one that had
// nothing to resume, or that went quiet between the two.
constexpr std::chrono::seconds kReplayGrace{5};

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
    , sessions_(settings_.sessionTtlSeconds)
    , startedAt_(nowSeconds())
{
}

Gateway::~Gateway()
{
    stop();
}

std::size_t Gateway::sockets() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return connections_.size();
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
    if (request.path != settings_.basePath && request.path != healthPath()) {
        return false;
    }
    return service::constantTimeEqual(request.header(kTokenHeader), settings_.token);
}

std::string Gateway::healthPath() const
{
    return settings_.basePath + "/healthz";
}

http::Response Gateway::health(const http::Request& request) const
{
    try {
        auth::authorizeRequest(http::collectAuthHeaders(request), nowSeconds(), request.method,
            request.path, Bytes(), settings_.operators);
    } catch (const std::exception& error) {
        bazarish::log::debug("gateway: health refused: {}", error.what());
        return {403, "application/json", {},
            R"({"error":{"message":"operator authentication required"}})"};
    }
    // What only this gateway can report: how many sessions it is holding, what
    // they hold, and how much it has had to turn away.
    std::size_t sessions = 0;
    std::size_t endpoints = 0;
    std::size_t streams = 0;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        std::set<const Session*> seen;
        for (const auto& [socket, connection] : connections_) {
            (void)socket;
            if (!seen.insert(connection.session.get()).second) {
                continue;
            }
            ++sessions;
            endpoints += connection.session->endpoints.size();
            streams += connection.session->streams.size();
        }
    }
    const nlohmann::json extras = {
        {"sessions", sessions},
        {"destinations", endpoints},
        {"streams", streams},
        {"sockets", sockets()},
        {"rejoins", rejoins()},
        {"refused", refusals()},
        {"dials", dials()},
        {"i2pd", i2p::routerVersion()},
    };
    return {200, "application/json", {},
        health::reportJson("gateway", kVersion, startedAt_, nowSeconds(), extras.dump())};
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
        if (!admitted(request)) {
            return notFound();
        }
        return request.path == healthPath() ? health(request) : decoy();
    };
    for (const char* method : {"GET", "POST", "PUT", "DELETE", "HEAD"}) {
        server_.route(method, "(.*)", answer);
    }
    const int bound = server_.start();
    running_.store(true);
    status_ = std::thread([this]() { statusLoop(); });
    return bound;
}

void Gateway::stop()
{
    if (running_.exchange(false) && status_.joinable()) {
        status_.join();
    }
    // Every session goes, and with it every destination and every thread it
    // holds. Without this a daemon on its way out leaves workers running
    // against the sessions, the sockets and the lock it is about to destroy.
    std::vector<std::shared_ptr<Session>> held;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        held = sessions_.drain();
    }
    for (const std::shared_ptr<Session>& session : held) {
        retire(session);
    }
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
    std::vector<std::shared_ptr<Session>> swept;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        swept = sessions_.sweep(now);
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
        if (connection.resumed) {
            ++rejoins_;
        }
        if (connection.session->full()) {
            full = true;
        } else {
            connection.session->addSocket();
            connections_.emplace(socket.get(), connection);
        }
    }
    for (const std::shared_ptr<Session>& gone : swept) {
        retire(gone);
    }
    if (full) {
        fail(socket, 0, Fault::eRefused, "this session holds as many sockets as it may");
        socket->close();
    }
}

void Gateway::retire(const std::shared_ptr<Session>& session)
{
    std::vector<std::shared_ptr<EndpointEntry>> endpoints;
    std::vector<std::shared_ptr<StreamEntry>> streams;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, endpoint] : session->endpoints) {
            (void)id;
            published_.erase(endpoint->host);
            // Under the lock a worker takes to hand over a caller, so what it
            // has is either in the streams below or given up on.
            endpoint->running.store(false);
            endpoints.push_back(endpoint);
        }
        for (const auto& [id, stream] : session->streams) {
            (void)id;
            streams.push_back(stream);
        }
        session->endpoints.clear();
        session->streams.clear();
    }
    for (const std::shared_ptr<StreamEntry>& stream : streams) {
        orphan(stream);
        stream->running.store(false);
        if (stream->stream) {
            stream->stream->close();
        }
        if (stream->reader.joinable()) {
            stream->reader.join();
        }
    }
    for (const std::shared_ptr<EndpointEntry>& endpoint : endpoints) {
        if (endpoint->endpoint) {
            endpoint->endpoint->stop();
        }
        if (endpoint->worker.joinable()) {
            endpoint->worker.join();
        }
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
    const std::shared_ptr<Session> session = found->second.session;
    if (session->control == socket) {
        session->control.reset();
    }
    for (auto& [id, endpoint] : session->endpoints) {
        (void)id;
        if (endpoint->socket == socket) {
            endpoint->socket.reset();
        }
    }
    for (auto& [id, stream] : session->streams) {
        (void)id;
        if (stream->socket == socket) {
            // A stream falls back to the main socket until the client attaches
            // a new one: a transfer slowed by sharing a queue is better than a
            // transfer stopped.
            stream->socket.reset();
        }
    }
    session->removeSocket(now);
    connections_.erase(found);
}

void Gateway::fail(const http::SocketPtr& socket, const std::uint32_t ref, const Fault fault,
    const std::string& why)
{
    ++refused_;
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

std::shared_ptr<Session> Gateway::sessionFor(const http::Socket* const socket) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = connections_.find(socket);
    return found == connections_.end() ? nullptr : found->second.session;
}

http::SocketPtr Gateway::outletFor(const Session& session, const StreamEntry& stream)
{
    if (stream.socket) {
        return stream.socket;
    }
    const auto found = session.endpoints.find(stream.endpoint);
    if (found != session.endpoints.end() && found->second->socket) {
        return found->second->socket;
    }
    if (session.replayDue > std::chrono::steady_clock::now()) {
        // The control socket is new and still owes this stream its replay.
        // What is waiting stays waiting; the pump that follows the resume
        // takes it out behind the bytes it belongs after.
        return nullptr;
    }
    return session.control;
}

http::SocketPtr Gateway::answerOn(const Session& session, const http::SocketPtr& asked)
{
    if (asked != nullptr && asked->open()) {
        return asked;
    }
    // A dial holds its whole deadline, which is long enough for the socket that
    // asked to be replaced under it, and an answer written to a dead socket is
    // a question the client has to ask again.
    return session.control;
}

void Gateway::replayDone(const std::shared_ptr<Session>& session)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (session->replayDue == std::chrono::steady_clock::time_point{}) {
            return;
        }
        session->replayDue = {};
    }
    afterReplay(session);
}

void Gateway::afterReplay(const std::shared_ptr<Session>& session)
{
    std::vector<std::shared_ptr<StreamEntry>> held;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, entry] : session->streams) {
            (void)id;
            held.push_back(entry);
        }
    }
    // What could not go out while the replay was owed goes out now.
    for (const std::shared_ptr<StreamEntry>& entry : held) {
        pump(session, entry);
        // And what the client is owed is said again. A credit is the whole count
        // consumed so far, so repeating it costs one frame - and the socket that
        // went may have taken the only credit this stream will ever have: a
        // sender whose window is full sends nothing, so nothing moves, so
        // nothing credits it again. That is a transfer stopped for good.
        const std::lock_guard<std::mutex> lock(mutex_);
        if (const http::SocketPtr out = outletFor(*session, *entry)) {
            out->send(encodeCredit(entry->id, entry->book.consumedTotal()));
        }
    }
}

void Gateway::onFrame(const http::SocketPtr& socket, const Frame& frame)
{
    if (frame.type == FrameType::eHello) {
        onHello(socket, frame);
        return;
    }
    const std::shared_ptr<Session> session = sessionFor(socket.get());
    if (session == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "this socket belongs to no session");
        socket->close();
        return;
    }
    // A request the client sent and never saw answered is re-sent with the same
    // reference. Identifiers are never reused, so the reference is an
    // idempotency key, and the repeat gets the answer it already earned rather
    // than a second endpoint. Only a request can repeat: data carries no answer.
    if (frame.type == FrameType::eEndpointCreate || frame.type == FrameType::eStreamOpen) {
        if (const Bytes* const already = session->answered(frame.ref); already != nullptr) {
            socket->send(*already);
            return;
        }
    }
    // A data frame belongs on the socket its flow rides. One that works by
    // accident is one that stops working under load, which is exactly when the
    // lane was supposed to matter.
    if (const http::SocketPtr lane = laneFor(*session, frame);
        lane != nullptr && lane != socket) {
        fail(socket, frame.ref, Fault::eWrongLane, "that flow does not ride this socket");
        return;
    }
    if (frame.type != FrameType::eResume) {
        // The client is talking about something else, so the resume it might
        // have sent is not coming.
        replayDone(session);
    }
    switch (frame.type) {
        case FrameType::eAttach: onAttach(socket, frame); return;
        case FrameType::eResume: onResume(session, socket, frame); return;
        case FrameType::eEndpointCreate: onEndpointCreate(session, socket, frame); return;
        case FrameType::eEndpointStop: onEndpointStop(session, socket, frame); return;
        case FrameType::eStreamOpen: onStreamOpen(session, socket, frame); return;
        case FrameType::eStreamData: onStreamData(session, socket, frame); return;
        case FrameType::eStreamCredit: onStreamCredit(session, socket, frame); return;
        case FrameType::eStreamClose:
        case FrameType::eStreamReset: onStreamEnd(session, frame); return;
        case FrameType::eRawSend: onRawSend(session, socket, frame); return;
        default: break;
    }
    fail(socket, frame.ref, Fault::eBadFrame,
        std::string(frameTypeName(frame.type)) + " is not a frame a client sends");
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
    http::SocketPtr replaced;
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
        // A socket that has not noticed it is dead must not be able to hold a
        // phone out of its own session.
        replaced = connection.session->control;
        connection.session->control = socket;
        // A rejoining client is owed whatever it did not confirm receiving, and
        // that goes out when its resume names the counts. Until then this
        // socket carries nothing new of its own.
        connection.session->replayDue = connection.session->streams.empty()
            ? std::chrono::steady_clock::time_point{}
            : std::chrono::steady_clock::now() + kReplayGrace;
    }

    // What is still standing. A client reconciles by absence: anything of its
    // own that these lists do not name is gone, whatever the reason.
    nlohmann::json endpoints = nlohmann::json::array();
    nlohmann::json streams = nlohmann::json::array();
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, endpoint] : connection.session->endpoints) {
            endpoints.push_back({{"id", id}, {"kind", endpoint->raw ? "raw" : "stream"},
                {"ready", endpoint->ready}, {"host", endpoint->host},
                {"tunnelsIn", endpoint->inboundTunnels},
                {"tunnelsOut", endpoint->outboundTunnels}, {"leaseSets", endpoint->leaseSets}});
        }
        for (const auto& [id, stream] : connection.session->streams) {
            streams.push_back({{"id", id}, {"endpoint", stream->endpoint},
                {"received", stream->book.received()},
                {"finished", stream->book.finishedSending()}});
        }
    }

    if (replaced && replaced != socket) {
        replaced->close();
    }

    const nlohmann::json ready = {
        {"version", kProtocolVersion},
        {"i2pd", i2p::routerVersion()},
        {"capabilities",
            {{"routerCounters", false}, {"destinationCounters", true}, {"netDbSample", false},
                {"proxy", false}, {"offlineKeys", false}}},
        {"session", connection.session->cookie()},
        {"resumed", connection.resumed},
        {"endpoints", endpoints},
        {"streams", streams},
    };
    socket->send(encodeJson(FrameType::eReady, frame.ref, ready));
}


namespace {

// How long a worker waits before looking again at whether it is still wanted,
// and at whether the window has room.
constexpr std::chrono::seconds kAcceptWait{1};
constexpr std::chrono::milliseconds kDatagramWait{200};
constexpr std::chrono::milliseconds kWindowWait{10};

std::shared_ptr<EndpointEntry> endpointOf(const Session& session, const std::uint32_t id)
{
    const auto found = session.endpoints.find(id);
    if (found == session.endpoints.end() || found->second->endpoint == nullptr) {
        // The identifier is taken from the moment it is asked for, but until the
        // engine has minted the destination there is nothing behind it. A frame
        // that names it now is a frame ahead of the answer it is waiting for.
        return nullptr;
    }
    return found->second;
}

std::shared_ptr<StreamEntry> streamOf(const Session& session, const std::uint32_t id)
{
    const auto found = session.streams.find(id);
    return found == session.streams.end() ? nullptr : found->second;
}

}  // namespace

http::SocketPtr Gateway::laneFor(const Session& session, const Frame& frame) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    switch (frame.type) {
        case FrameType::eStreamData:
        case FrameType::eStreamCredit:
        case FrameType::eStreamClose:
        case FrameType::eStreamReset: {
            const std::shared_ptr<StreamEntry> entry = streamOf(session, frame.ref);
            return entry == nullptr ? nullptr : outletFor(session, *entry);
        }
        case FrameType::eRawSend: {
            const std::shared_ptr<EndpointEntry> entry = endpointOf(session, frame.ref);
            return entry == nullptr ? nullptr : entry->socket;
        }
        default:
            return nullptr;
    }
}

std::shared_ptr<EndpointEntry> Gateway::localFor(
    const std::string& host, std::shared_ptr<Session>& owner) const
{
    const auto found = published_.find(host);
    if (found == published_.end()) {
        return nullptr;
    }
    owner = found->second.session.lock();
    const std::shared_ptr<EndpointEntry> entry = found->second.endpoint.lock();
    if (owner == nullptr || entry == nullptr) {
        return nullptr;
    }
    return entry;
}

void Gateway::onEndpointCreate(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    const nlohmann::json body = bodyJson(frame);
    const std::string kind = body.value("kind", std::string());
    if (kind != "stream" && kind != "raw") {
        fail(socket, frame.ref, Fault::eBadFrame, "a destination is for streams or for raw");
        return;
    }
    const std::optional<i2p::Privacy> privacy
        = i2p::privacyFromString(body.value("privacy", std::string("max")));
    if (!privacy.has_value()) {
        fail(socket, frame.ref, Fault::eBadFrame, "that is not a privacy level");
        return;
    }

    // The client sends no key and holds none: it says what the destination is
    // for, and the engine here mints, builds and publishes it.
    i2p::EndpointConfig config;
    config.traffic = kind == "raw" ? i2p::Traffic::eRaw : i2p::Traffic::eStream;
    config.privacy = privacy.value();
    const int asked = static_cast<int>(body.value("tunnels", i2p::kDefaultTunnelQuantity));
    config.tunnelQuantity = std::clamp(asked, 1, i2p::kMaxTunnelQuantity);
    config.published = body.value("published", true);
    config.realtime = body.value("realtime", false);
    // Not what the destination is for, which the client did not say: only what
    // it is, which travelled anyway.
    config.label = kind;

    std::shared_ptr<EndpointEntry> entry;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (session->endpoints.count(frame.ref) > 0) {
            // The same question again, asked while the destination was still
            // being built and there was no answer yet to repeat. Identifiers
            // are never reused, so the create already running answers it.
            return;
        }
        entry = std::make_shared<EndpointEntry>();
        entry->id = frame.ref;
        entry->raw = kind == "raw";
        entry->published = config.published;
        entry->realtime = config.realtime;
        session->endpoints.emplace(entry->id, entry);
    }
    entry->endpoint = router_.createEndpoint(config);
    entry->host = entry->endpoint->routingHost();
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (entry->published) {
            published_[entry->host] = Local{session, entry};
        }
        const Bytes answer
            = encodeJson(FrameType::eOk, frame.ref, {{"host", entry->host}, {"kind", kind}});
        session->remember(frame.ref, answer);
        if (const http::SocketPtr out = answerOn(*session, socket)) {
            out->send(answer);
        }
    }

    if (entry->raw) {
        entry->worker = std::thread([this, session, entry]() { datagramLoop(session, entry); });
    } else if (entry->published) {
        entry->worker = std::thread([this, session, entry]() { acceptLoop(session, entry); });
    }
}

void Gateway::onEndpointStop(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    std::shared_ptr<EndpointEntry> entry;
    std::vector<std::shared_ptr<StreamEntry>> orphans;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = endpointOf(*session, frame.ref);
        if (entry == nullptr) {
            fail(socket, frame.ref, Fault::eNoEndpoint, "no such destination on this session");
            return;
        }
        // Said under the lock the accept worker takes to hand over a caller:
        // either it got there first and is in the list below, or it sees this
        // and gives up on what it had.
        entry->running.store(false);
        session->endpoints.erase(frame.ref);
        published_.erase(entry->host);
        for (auto at = session->streams.begin(); at != session->streams.end();) {
            if (at->second->endpoint == frame.ref) {
                orphans.push_back(at->second);
                at = session->streams.erase(at);
            } else {
                ++at;
            }
        }
    }
    // A stopped destination is finished with, and so is everything on it.
    entry->endpoint->stop();
    for (const std::shared_ptr<StreamEntry>& stranded : orphans) {
        orphan(stranded);
        stranded->running.store(false);
        if (stranded->stream) {
            stranded->stream->close();
        }
        if (stranded->reader.joinable()) {
            stranded->reader.join();
        }
    }
    if (entry->worker.joinable()) {
        entry->worker.join();
    }
    socket->send(encode(FrameType::eOk, frame.ref));
}

void Gateway::onRawSend(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
    const Frame& frame)
{
    const RawSend sent = decodeRawSend(frame);
    std::shared_ptr<EndpointEntry> from;
    std::shared_ptr<Session> peerSession;
    std::shared_ptr<EndpointEntry> peer;
    http::SocketPtr peerLane;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        from = endpointOf(*session, frame.ref);
        if (from == nullptr) {
            fail(socket, frame.ref, Fault::eNoEndpoint, "no such destination on this session");
            return;
        }
        if (!from->raw) {
            // The mirror of what a dial from a raw destination gets: the two
            // kinds are exclusive, and this one has no datagram half.
            fail(socket, frame.ref, Fault::eUnsupported, "that destination carries streams");
            return;
        }
        peer = localFor(sent.host, peerSession);
        if (peer != nullptr && !peer->raw) {
            peer = nullptr;
        }
        if (peer != nullptr) {
            // Read here, where it is written: a lane can close while a datagram
            // is being written onto it.
            peerLane = peer->socket;
        }
    }
    if (peer != nullptr) {
        // Both ends are this gateway's own. Two friends on one machine were
        // sending audio out through their own tunnels, across the network and
        // back in through the other's, to reach a destination in the same
        // process.
        if (peerLane) {
            peerLane->send(encode(FrameType::eRawRecv, peer->id, sent.payload));
        }
        return;
    }
    from->endpoint->sendRawDatagram(sent.host, sent.payload.data(), sent.payload.size());
}

void Gateway::datagramLoop(
    const std::shared_ptr<Session>& session, const std::shared_ptr<EndpointEntry>& entry)
{
    while (entry->running.load()) {
        std::vector<std::uint8_t> payload;
        try {
            payload = entry->endpoint->receiveRawDatagram(kDatagramWait);
        } catch (const std::exception&) {
            break;
        }
        if (payload.empty()) {
            continue;
        }
        if (payload.size() > kMaxBodyBytes) {
            // The router drops what it cannot carry and says nothing, and so
            // does this: a throw here ends the thread and the daemon with it.
            continue;
        }
        // A datagram for an endpoint whose socket is not attached is dropped.
        // Audio that arrives late has already been played past, and putting it
        // behind a file to arrive later still helps nobody.
        http::SocketPtr out;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            out = entry->socket;
        }
        if (!out) {
            continue;
        }
        out->send(encode(FrameType::eRawRecv, entry->id, Bytes(payload.begin(), payload.end())));
    }
    (void)session;
}

void Gateway::onStreamOpen(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    const nlohmann::json body = bodyJson(frame);
    const std::uint32_t endpointId = body.value("endpoint", 0U);
    const std::string host = body.value("host", std::string());
    const std::chrono::seconds deadline(body.value("deadline", 0));
    if (host.empty() || deadline.count() <= 0) {
        fail(socket, frame.ref, Fault::eBadFrame, "a dial names a host and a deadline");
        return;
    }
    std::shared_ptr<EndpointEntry> from;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        from = endpointOf(*session, endpointId);
        if (from == nullptr) {
            fail(socket, frame.ref, Fault::eNoEndpoint, "no such destination on this session");
            return;
        }
        if (from->raw) {
            fail(socket, frame.ref, Fault::eUnsupported, "that destination carries datagrams");
            return;
        }
        if (streamOf(*session, frame.ref) != nullptr) {
            fail(socket, frame.ref, Fault::eBadFrame, "that identifier is already a stream");
            return;
        }
        if (session->dialling.count(frame.ref) > 0) {
            // The same question again, its socket having died before the answer
            // came. The dial already running answers it; a second one would be
            // a second stream wearing the same identifier.
            return;
        }
        session->dialling.insert(frame.ref);
    }
    // Both ends this gateway's own is not a dial at all. It knows which
    // destination is which - it minted both - so sending the bytes out through
    // two tunnel sets to arrive back in the same process would be work done to
    // get where it started.
    std::shared_ptr<Session> owner;
    std::shared_ptr<EndpointEntry> to;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        to = localFor(host, owner);
        if (to != nullptr && to->raw) {
            to = nullptr;
        }
    }
    if (to != nullptr && meetLocally(session, from, frame.ref, owner, to, socket)) {
        const std::lock_guard<std::mutex> lock(mutex_);
        session->dialling.erase(frame.ref);
        return;
    }

    // The dial blocks, and it may hold the deadline the caller gave it, so it
    // does not run on the socket's thread.
    ++dials_;
    std::thread([this, session, from, ref = frame.ref, host, deadline, socket]() {
        dial(session, from, ref, host, deadline, socket);
    }).detach();
}

void Gateway::dial(const std::shared_ptr<Session>& session,
    const std::shared_ptr<EndpointEntry>& from, const std::uint32_t stream, std::string host,
    const std::chrono::seconds deadline, const http::SocketPtr& answerTo)
{
    const auto until = std::chrono::steady_clock::now() + deadline;
    std::unique_ptr<i2p::Stream> opened;
    while (std::chrono::steady_clock::now() < until && from->running.load()) {
        const auto left = std::chrono::duration_cast<std::chrono::seconds>(
            until - std::chrono::steady_clock::now());
        try {
            opened = from->endpoint->connect(host, std::max(left, std::chrono::seconds(1)));
        } catch (const std::exception&) {
            opened.reset();
        }
        if (opened != nullptr) {
            break;
        }
        // A LeaseSet that is not in the netDb yet is a reason to try again, not
        // a reason to fail.
        std::this_thread::sleep_for(kDialRetryDelay);
    }
    if (opened == nullptr) {
        const Bytes answer = encodeJson(
            FrameType::eStreamReset, stream, {{"code", faultName(Fault::eUnreachable)}});
        http::SocketPtr out;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            session->dialling.erase(stream);
            session->remember(stream, answer);
            out = answerOn(*session, answerTo);
        }
        if (out) {
            out->send(answer);
        }
        return;
    }

    std::shared_ptr<StreamEntry> entry = std::make_shared<StreamEntry>();
    entry->id = stream;
    entry->endpoint = from->id;
    entry->stream = std::move(opened);
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        session->dialling.erase(stream);
        session->streams.emplace(stream, entry);
        const Bytes answer = encode(FrameType::eStreamOpened, stream);
        session->remember(stream, answer);
        if (const http::SocketPtr out = answerOn(*session, answerTo)) {
            out->send(answer);
        }
    }
    entry->reader = std::thread([this, session, entry]() { readLoop(session, entry); });
}

bool Gateway::meetLocally(const std::shared_ptr<Session>& session,
    const std::shared_ptr<EndpointEntry>& from, const std::uint32_t stream,
    const std::shared_ptr<Session>& owner, const std::shared_ptr<EndpointEntry>& to,
    const http::SocketPtr& answerTo)
{
    auto here = std::make_shared<StreamEntry>();
    auto there = std::make_shared<StreamEntry>();
    here->id = stream;
    here->endpoint = from->id;
    there->endpoint = to->id;
    here->peer = there;
    here->peerSession = owner;
    there->peer = here;
    there->peerSession = session;

    http::SocketPtr control;
    http::SocketPtr back;
    Bytes answer;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        control = owner->control;
        if (!control) {
            // The other side has no socket to be told on. Let the dial go out
            // over I2P instead of failing it: a client whose control socket is
            // between lives is still reachable at its address.
            return false;
        }
        // The gateway allocates the odd half of the space for a caller it
        // announces, here as everywhere.
        there->id = owner->ids().next();
        session->streams.emplace(here->id, here);
        owner->streams.emplace(there->id, there);
        answer = encode(FrameType::eStreamOpened, stream);
        session->remember(stream, answer);
        back = answerOn(*session, answerTo);
    }
    if (back) {
        back->send(answer);
    }
    // The caller's destination, which the gateway can name because it minted it.
    control->send(encodeJson(FrameType::eStreamInbound, there->id,
        {{"endpoint", to->id}, {"peer", from->endpoint->publicBase64()}}));
    return true;
}

void Gateway::pump(
    const std::shared_ptr<Session>& session, const std::shared_ptr<StreamEntry>& entry)
{
    // Everything here goes out under the one lock, because two pumps can run at
    // once - one driven by data arriving, one by a credit - and what orders
    // their frames is this lock and nothing else. A credit that overtakes a
    // larger one is a credit that says less than the last one, and a data frame
    // that overtakes another is a corrupted stream.
    const std::lock_guard<std::mutex> lock(mutex_);
    const http::SocketPtr out = outletFor(*session, *entry);
    if (!out) {
        return;
    }
    std::size_t moved = 0;
    while (!entry->waiting.empty()) {
        const std::size_t piece
            = std::min({entry->book.room(), kMaxBodyBytes, entry->waiting.size()});
        if (piece == 0) {
            break;
        }
        entry->book.wrote(entry->waiting.data(), piece);
        out->send(encode(FrameType::eStreamData, entry->id, entry->waiting.data(), piece));
        entry->waiting.erase(
            entry->waiting.begin(), entry->waiting.begin() + static_cast<std::ptrdiff_t>(piece));
        moved += piece;
    }
    if (entry->waiting.empty() && entry->endAfterDrain) {
        entry->endAfterDrain = false;
        entry->book.finishSending();
        out->send(encode(FrameType::eStreamClose, entry->id));
    }
    // What left this side is what the other side may now be told it is rid of.
    // Crediting it any earlier would be crediting a queue.
    const std::shared_ptr<StreamEntry> other = entry->peer.lock();
    const std::shared_ptr<Session> theirs = entry->peerSession.lock();
    if (moved > 0 && other != nullptr && theirs != nullptr) {
        other->book.consumed(moved);
        const http::SocketPtr back = outletFor(*theirs, *other);
        if (back) {
            back->send(encodeCredit(other->id, other->book.consumedTotal()));
        }
    }
}

void Gateway::acceptLoop(
    const std::shared_ptr<Session>& session, const std::shared_ptr<EndpointEntry>& entry)
{
    while (entry->running.load()) {
        std::string peer;
        std::unique_ptr<i2p::Stream> caller;
        try {
            caller = entry->endpoint->accept(peer, kAcceptWait);
        } catch (const std::exception&) {
            break;
        }
        if (caller == nullptr) {
            continue;
        }
        std::shared_ptr<StreamEntry> inbound = std::make_shared<StreamEntry>();
        inbound->endpoint = entry->id;
        inbound->stream = std::move(caller);
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (!entry->running.load()) {
                break;  // stopped while this caller was being taken in
            }
            // The gateway allocates the odd half of the space, and only here.
            inbound->id = session->ids().next();
            session->streams.emplace(inbound->id, inbound);
        }
        // A caller nobody is told about is a caller whose far side waits on
        // nothing until its own deadline runs out. The announcement waits for
        // somewhere to go exactly as a stream's bytes do: the client replaces
        // its control socket on purpose, and the gap is seconds.
        http::SocketPtr control;
        while (entry->running.load()) {
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                control = session->control;
            }
            if (control) {
                break;
            }
            std::this_thread::sleep_for(kWindowWait);
        }
        if (!control) {
            // The destination is finished with, and so is the caller it took.
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                session->streams.erase(inbound->id);
            }
            inbound->stream->close();
            break;
        }
        control->send(encodeJson(FrameType::eStreamInbound, inbound->id,
            {{"endpoint", entry->id}, {"peer", peer}}));
        inbound->reader = std::thread([this, session, inbound]() { readLoop(session, inbound); });
    }
}

void Gateway::readLoop(
    const std::shared_ptr<Session>& session, const std::shared_ptr<StreamEntry>& entry)
{
    std::vector<unsigned char> buffer(kMaxBodyBytes);
    while (entry->running.load()) {
        // Never read more than the window the client granted: a gateway that
        // read on regardless would be holding a file in memory for a phone that
        // is not reading it.
        const std::size_t room = std::min(entry->book.room(), buffer.size());
        if (room == 0) {
            std::this_thread::sleep_for(kWindowWait);
            continue;
        }
        std::size_t got = 0;
        try {
            got = entry->stream->readSome(buffer.data(), room);
        } catch (const std::exception&) {
            break;
        }
        if (got == 0) {
            break;
        }
        const http::SocketPtr out = outletFor(*session, *entry);
        if (!out) {
            std::this_thread::sleep_for(kWindowWait);
            continue;
        }
        entry->book.wrote(buffer.data(), got);
        out->send(encode(FrameType::eStreamData, entry->id, buffer.data(), got));
    }
    // The end goes out the same way the bytes did, and with the same patience:
    // said best-effort, it was lost whenever the control socket happened to be
    // between lives - and a client that is never told its stream ended waits out
    // its own read deadline and then writes into a stream this gateway no longer
    // has. The drain path already knows how to hold an end until there is
    // somewhere to put it.
    if (entry->running.load()) {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            entry->endAfterDrain = true;
        }
        pump(session, entry);
    }
}

void Gateway::onStreamData(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    std::shared_ptr<StreamEntry> entry;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = streamOf(*session, frame.ref);
    }
    if (entry == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "no such stream on this session");
        return;
    }
    entry->book.tookIn(frame.body.size());

    const std::shared_ptr<StreamEntry> peer = entry->peer.lock();
    const std::shared_ptr<Session> theirs = entry->peerSession.lock();
    if (peer != nullptr && theirs != nullptr) {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            peer->waiting.insert(peer->waiting.end(), frame.body.begin(), frame.body.end());
        }
        // The credit for these bytes comes from the far side's window, not from
        // this one: they have not left until its client has room for them.
        pump(theirs, peer);
        return;
    }

    if (!entry->stream) {
        // The pair this belonged to is gone, and there is no network leg under
        // it to fall back to.
        fail(socket, frame.ref, Fault::eClosed, "that stream's far side has gone");
        return;
    }
    entry->stream->writeAll(frame.body.data(), frame.body.size());
    // The I2P stream has them, which is what leaving this side's hands means.
    entry->book.consumed(frame.body.size());
    const http::SocketPtr out = outletFor(*session, *entry);
    if (out) {
        out->send(encodeCredit(entry->id, entry->book.consumedTotal()));
    }
}

void Gateway::onStreamCredit(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    std::shared_ptr<StreamEntry> entry;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = streamOf(*session, frame.ref);
    }
    if (entry == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "no such stream on this session");
        return;
    }
    entry->book.peerCredited(decodeCredit(frame));
    // Room here is room for what the other side is waiting to send.
    if (!entry->peer.expired()) {
        pump(session, entry);
    }
}

void Gateway::onStreamEnd(const std::shared_ptr<Session>& session, const Frame& frame)
{
    std::shared_ptr<StreamEntry> entry;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = streamOf(*session, frame.ref);
        if (entry != nullptr) {
            session->streams.erase(frame.ref);
        }
    }
    if (entry == nullptr) {
        // Not a fault: the gateway retires a stream the moment its far side
        // ends, and the client says the same thing about it a moment later. A
        // dial that never landed reads the same way - the client closes a
        // stream that was never opened. Refusing either would count a refusal
        // against a client that did nothing wrong.
        return;
    }
    entry->book.peerFinished();

    const std::shared_ptr<StreamEntry> peer = entry->peer.lock();
    const std::shared_ptr<Session> theirs = entry->peerSession.lock();
    if (peer != nullptr && theirs != nullptr) {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            peer->endAfterDrain = true;
            peer->peer.reset();
        }
        // What is still waiting goes first: an end that overtakes the bytes it
        // ends is a truncated file.
        pump(theirs, peer);
        return;
    }
    teardown(session, entry, Fault::eClosed);
}

void Gateway::orphan(const std::shared_ptr<StreamEntry>& entry)
{
    const std::shared_ptr<StreamEntry> peer = entry->peer.lock();
    const std::shared_ptr<Session> theirs = entry->peerSession.lock();
    if (peer == nullptr || theirs == nullptr) {
        return;
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        peer->endAfterDrain = true;
        peer->peer.reset();
    }
    pump(theirs, peer);
}

void Gateway::teardown(const std::shared_ptr<Session>&,
    const std::shared_ptr<StreamEntry>& entry, const Fault)
{
    entry->running.store(false);
    if (entry->stream) {
        entry->stream->close();
    }
    if (entry->reader.joinable()) {
        entry->reader.join();
    }
}

void Gateway::onResume(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    const nlohmann::json body = bodyJson(frame);
    const auto found = body.find("streams");
    if (found == body.end() || !found->is_array()) {
        fail(socket, frame.ref, Fault::eBadFrame, "a resume names the streams it is resuming");
        return;
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        // Lifted before the replay goes out, not after: the gate is there to
        // hold everything else behind these frames, and asking outletFor while
        // it is up refuses the very frames it is waiting for - the replay was
        // dropped on the floor and the bytes lost with the socket were never
        // seen again.
        session->replayDue = {};
    }
    for (const nlohmann::json& said : *found) {
        const std::uint32_t id = said.value("id", 0U);
        std::shared_ptr<StreamEntry> entry;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            entry = streamOf(*session, id);
        }
        if (entry == nullptr) {
            continue;  // gone since; the client learns that from the lists
        }
        // Everything the client did not confirm receiving goes out again, in
        // order, before any new data on this stream.
        const Bytes again = entry->book.replay(said.value("received", std::uint64_t{0}));
        const std::lock_guard<std::mutex> lock(mutex_);
        const http::SocketPtr out = outletFor(*session, *entry);
        if (!out) {
            continue;
        }
        for (std::size_t at = 0; at < again.size(); at += kMaxBodyBytes) {
            const std::size_t piece = std::min(kMaxBodyBytes, again.size() - at);
            out->send(encode(FrameType::eStreamData, id, again.data() + at, piece));
        }
    }
    // What waited for the replay goes out behind it.
    afterReplay(session);
}

void Gateway::onAttach(const http::SocketPtr& socket, const Frame& frame)
{
    const nlohmann::json body = bodyJson(frame);
    const std::shared_ptr<Session> session = sessionFor(socket.get());
    if (session == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "this socket belongs to no session");
        socket->close();
        return;
    }
    const std::uint64_t received = body.value("received", std::uint64_t{0});

    std::shared_ptr<EndpointEntry> endpoint;
    std::shared_ptr<StreamEntry> stream;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        connections_[socket.get()].flow = frame.ref;
        endpoint = endpointOf(*session, frame.ref);
        stream = streamOf(*session, frame.ref);
        if (endpoint != nullptr) {
            endpoint->socket = socket;
        } else if (stream != nullptr) {
            stream->socket = socket;
        }
    }
    if (endpoint != nullptr) {
        // Datagrams are not replayed: they are best effort by construction.
        socket->send(encodeJson(FrameType::eOk, frame.ref, nlohmann::json::object()));
        return;
    }
    if (stream == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "no such flow on this session");
        return;
    }
    socket->send(encodeJson(FrameType::eOk, frame.ref,
        {{"received", stream->book.received()}, {"finished", stream->book.finishedSending()}}));
    const Bytes again = stream->book.replay(received);
    for (std::size_t at = 0; at < again.size(); at += kMaxBodyBytes) {
        const std::size_t piece = std::min(kMaxBodyBytes, again.size() - at);
        socket->send(encode(FrameType::eStreamData, stream->id, again.data() + at, piece));
    }
}

void Gateway::statusLoop()
{
    while (running_.load()) {
        std::this_thread::sleep_for(kStatusPeriod);
        if (!running_.load()) {
            break;
        }
        // A session past its term is swept here rather than only when the next
        // client happens to connect: a gateway whose one client has gone would
        // otherwise hold its tunnels up for as long as nobody else arrived.
        std::vector<std::shared_ptr<Session>> swept;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            swept = sessions_.sweep(nowSeconds());
        }
        for (const std::shared_ptr<Session>& gone : swept) {
            retire(gone);
        }

        // Only what a client shows: its own destinations. What this router
        // knows of the network is this machine's, and everyone else's who uses
        // it, so it is not sent.
        std::vector<i2p::LocalDestination> local;
        try {
            local = router_.localDestinations();
        } catch (const std::exception&) {
            continue;
        }

        std::vector<std::pair<http::SocketPtr, Bytes>> outgoing;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            std::set<const Session*> seen;
            for (const auto& [socket, connection] : connections_) {
                (void)socket;
                const std::shared_ptr<Session>& session = connection.session;
                if (!session->control || !seen.insert(session.get()).second) {
                    continue;
                }
                for (const auto& [id, entry] : session->endpoints) {
                    bool ready = false;
                    int in = 0;
                    int out = 0;
                    int leases = 0;
                    for (const i2p::LocalDestination& destination : local) {
                        if (destination.host == entry->host) {
                            ready = destination.ready;
                            in = destination.inboundTunnels;
                            out = destination.outboundTunnels;
                            leases = destination.remoteLeaseSets;
                            break;
                        }
                    }
                    if (ready == entry->ready && in == entry->inboundTunnels
                        && out == entry->outboundTunnels && leases == entry->leaseSets) {
                        continue;
                    }
                    entry->ready = ready;
                    entry->inboundTunnels = in;
                    entry->outboundTunnels = out;
                    entry->leaseSets = leases;
                    outgoing.emplace_back(session->control,
                        encodeJson(FrameType::eEndpointStatus, id,
                            {{"ready", ready}, {"host", entry->host}, {"tunnelsIn", in},
                                {"tunnelsOut", out}, {"leaseSets", leases}}));
                }
            }
        }
        for (const auto& [socket, frame] : outgoing) {
            socket->send(frame);
        }
    }
}

}  // namespace bazarish::gateway
