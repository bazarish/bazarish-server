// Bazarish project (c) 2026
#include "Gateway.hpp"

#include <bazarish/Clock.hpp>
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

http::SocketPtr Gateway::outlet(const Session& session, const http::SocketPtr& own)
{
    return own ? own : session.control;
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
    switch (frame.type) {
        case FrameType::eAttach: onAttach(socket, frame); return;
        case FrameType::eEndpointCreate: onEndpointCreate(session, socket, frame); return;
        case FrameType::eEndpointStop: onEndpointStop(session, socket, frame); return;
        case FrameType::eStreamOpen: onStreamOpen(session, socket, frame); return;
        case FrameType::eStreamData: onStreamData(session, socket, frame); return;
        case FrameType::eStreamCredit: onStreamCredit(session, socket, frame); return;
        case FrameType::eStreamClose:
        case FrameType::eStreamReset: onStreamEnd(session, socket, frame); return;
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
        connection.session->control = socket;
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


namespace {

// How long a worker waits before looking again at whether it is still wanted,
// and at whether the window has room.
constexpr std::chrono::seconds kAcceptWait{1};
constexpr std::chrono::milliseconds kDatagramWait{200};
constexpr std::chrono::milliseconds kWindowWait{10};

std::shared_ptr<EndpointEntry> endpointOf(const Session& session, const std::uint32_t id)
{
    const auto found = session.endpoints.find(id);
    return found == session.endpoints.end() ? nullptr : found->second;
}

std::shared_ptr<StreamEntry> streamOf(const Session& session, const std::uint32_t id)
{
    const auto found = session.streams.find(id);
    return found == session.streams.end() ? nullptr : found->second;
}

}  // namespace

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
    // for, and the gateway mints, builds and publishes it.
    i2p::EndpointConfig config{router_.generateKeys()};
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
        if (endpointOf(*session, frame.ref) != nullptr) {
            fail(socket, frame.ref, Fault::eBadFrame, "that identifier is already a destination");
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
        socket->send(answer);
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
    entry->running.store(false);
    entry->endpoint->stop();
    for (const std::shared_ptr<StreamEntry>& orphan : orphans) {
        orphan->running.store(false);
        if (orphan->stream) {
            orphan->stream->close();
        }
        if (orphan->reader.joinable()) {
            orphan->reader.join();
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
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        from = endpointOf(*session, frame.ref);
        if (from == nullptr) {
            fail(socket, frame.ref, Fault::eNoEndpoint, "no such destination on this session");
            return;
        }
        peer = localFor(sent.host, peerSession);
        if (peer != nullptr && !peer->raw) {
            peer = nullptr;
        }
    }
    if (peer != nullptr) {
        // Both ends are this gateway's own. Two friends on one machine were
        // sending audio out through their own tunnels, across the network and
        // back in through the other's, to reach a destination in the same
        // process.
        if (peer->socket) {
            peer->socket->send(encode(FrameType::eRawRecv, peer->id, sent.payload));
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
        // A datagram for an endpoint whose socket is not attached is dropped.
        // Audio that arrives late has already been played past, and putting it
        // behind a file to arrive later still helps nobody.
        const http::SocketPtr out = entry->socket;
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
    }
    // The dial blocks, and it may hold the deadline the caller gave it, so it
    // does not run on the socket's thread.
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
        session->remember(stream, answer);
        answerTo->send(answer);
        return;
    }

    std::shared_ptr<StreamEntry> entry = std::make_shared<StreamEntry>();
    entry->id = stream;
    entry->endpoint = from->id;
    entry->stream = std::move(opened);
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        session->streams.emplace(stream, entry);
        const Bytes answer = encode(FrameType::eStreamOpened, stream);
        session->remember(stream, answer);
        answerTo->send(answer);
    }
    entry->reader = std::thread([this, session, entry]() { readLoop(session, entry); });
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
        http::SocketPtr control;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            // The gateway allocates the odd half of the space, and only here.
            inbound->id = session->ids().next();
            session->streams.emplace(inbound->id, inbound);
            control = session->control;
        }
        if (!control) {
            continue;
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
        const http::SocketPtr out = outlet(*session, entry->socket);
        if (!out) {
            std::this_thread::sleep_for(kWindowWait);
            continue;
        }
        entry->book.wrote(buffer.data(), got);
        out->send(encode(FrameType::eStreamData, entry->id, buffer.data(), got));
    }
    const http::SocketPtr out = outlet(*session, entry->socket);
    if (out && entry->running.load()) {
        entry->book.finishSending();
        out->send(encode(FrameType::eStreamClose, entry->id));
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
    entry->stream->writeAll(frame.body.data(), frame.body.size());
    // The I2P stream has them, which is what leaving this side's hands means.
    entry->book.consumed(frame.body.size());
    const http::SocketPtr out = outlet(*session, entry->socket);
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
}

void Gateway::onStreamEnd(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
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
        fail(socket, frame.ref, Fault::eUnknownId, "no such stream on this session");
        return;
    }
    entry->book.peerFinished();
    teardown(session, entry, Fault::eClosed);
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
        std::vector<i2p::LocalDestination> local;
        int known = 0;
        int floodfills = 0;
        int inbound = 0;
        int outbound = 0;
        try {
            local = router_.localDestinations();
            known = router_.knownRouters();
            floodfills = router_.floodfills();
            inbound = router_.inboundTunnels();
            outbound = router_.outboundTunnels();
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
                outgoing.emplace_back(session->control,
                    encodeJson(FrameType::eRouterStatus, 0,
                        {{"known", known}, {"floodfills", floodfills}, {"in", inbound},
                            {"out", outbound}}));
            }
        }
        for (const auto& [socket, frame] : outgoing) {
            socket->send(frame);
        }
    }
}

}  // namespace bazarish::gateway
