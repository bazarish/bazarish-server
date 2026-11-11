// Bazarish project (c) 2026
#include "Gateway.hpp"

#include <FleetRoutes.hpp>
#include <Health.hpp>
#include <OpsSettings.hpp>
#include <StateIdentity.hpp>

#include <BuildVersion.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Tls.hpp>

#include <algorithm>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace bazarish::gateway {

namespace {

constexpr std::size_t kDecoyPageBytes = 32 * 1024;


constexpr std::chrono::seconds kReplayGrace{5};
// A closed address's lease set is still found this long: i2pd's TUNNEL_EXPIRATION_TIMEOUT.
constexpr std::chrono::seconds kGoneHereMemory{660};

constexpr i2p::Privacy kCallPrivacy = i2p::Privacy::eMinimal;

constexpr std::chrono::seconds kServerHandshake{10};
constexpr std::size_t kMaxServedListBytes = 16 * 1024 * 1024;

http::Response opsRefusal(const int status, const std::string& message)
{
    return {status, "application/json", {}, nlohmann::json{{"error", {{"message", message}}}}.dump()};
}

Settings writtenSettings(const std::filesystem::path& configPath)
{
    return Settings::from(ConfigView(ConfigFile(configPath).read()));
}

nlohmann::json editable(const Settings& written, const std::string& fingerprint)
{
    nlohmann::json direct = nlohmann::json::array();
    for (const DirectRoute& route : written.direct) {
        direct.push_back(
            {{"dest", route.dest}, {"host", route.host}, {"port", route.port}, {"pin", route.pin}});
    }
    return {
        {"logLevel", std::string(log::levelName(written.logLevel))},
        {"i2pPrivacy", std::string(i2p::privacyName(written.tunnelPrivacy))},
        {"callPrivacy", std::string(i2p::privacyName(kCallPrivacy))},
        {"streamPool", written.streamPool},
        {"callPool", written.callPool},
        {"watchPool", written.watchPool},
        {"poolMax", kMaxPoolDepth},
        {"direct", direct},
        {"server", written.server.has_value()
                ? nlohmann::json{{"host", written.server->host}, {"port", written.server->port},
                    {"pin", written.server->pin}}
                : nlohmann::json(nullptr)},
        {"publicAddress", written.publicAddress},
        {"link", clientLink(written, fingerprint)},
        {"stateDirectory", written.stateDir.string()},
        {"version", kBuildVersion},
    };
}

constexpr std::size_t kLeaseSetKeyBytes = 32;
constexpr std::int64_t kDelegationAskLeadSeconds = 600;
constexpr std::int64_t kDelegationAskEverySeconds = 60;

Bytes fromI2pBase64(const std::string& text)
{
    return fromBase64(i2pToStandardBase64(text));
}

i2p::Keys delegationIn(const nlohmann::json& text)
{
    i2p::Keys keys = i2p::Keys::fromBlob(fromI2pBase64(text.get<std::string>()));
    i2p::requireUsableDelegation(keys, nowSeconds());
    return keys;
}

Bytes leaseSetKey(const nlohmann::json& text)
{
    Bytes raw = fromI2pBase64(text.get<std::string>());
    if (raw.size() != kLeaseSetKeyBytes) {
        throw std::invalid_argument("a lease-set key is 32 bytes");
    }
    return raw;
}

void readLeaseSetAuth(const nlohmann::json& body, i2p::EndpointConfig& config)
{
    if (body.contains("keys")) {
        const nlohmann::json& readers = body.at("readers");
        if (!readers.is_array() || readers.empty()) {
            throw std::invalid_argument("a destination of a key of its own names its readers");
        }
        if (readers.size() > i2p::kMaxLeaseSetReaders) {
            throw std::invalid_argument("a lease set names at most "
                + std::to_string(i2p::kMaxLeaseSetReaders) + " readers");
        }
        if (!config.published) {
            throw std::invalid_argument("a destination of a key of its own is published");
        }
        config.keys = delegationIn(body.at("keys"));
        for (const nlohmann::json& reader : readers) {
            config.leaseSetReaders.push_back(leaseSetKey(reader));
        }
    } else if (body.contains("readers")) {
        throw std::invalid_argument("readers belong to a destination of a key of its own");
    }
    if (body.contains("readerKey")) {
        config.leaseSetReaderKey = leaseSetKey(body.at("readerKey"));
    }
}

}  // namespace

Gateway::Gateway(Settings settings, i2p::Router& router, OpsControl control)
    : settings_(std::move(settings))
    , control_(std::move(control))
    , router_(router)
    , identity_(server::loadOrCreateIdentity(settings_.stateDir))
    , sealing_(server::loadOrCreateSealingKey(settings_.stateDir))
    , card_(gateway::issueCard(identity_, sealing_))
    , cover_(identity_.fingerprint())
    , server_([&]() {
        http::Server::Options options;
        options.host = settings_.listenHost;
        options.port = settings_.listenPort;
        return options;
    }())
    , sessions_(settings_.sessionTtlSeconds)
    , direct_(settings_.direct)
    , serverLink_(settings_.server)
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
    return service::constantTimeEqual(request.path, settings_.basePath);
}

std::optional<http::Response> Gateway::operatorRefusal(const http::Request& request) const
{
    return http::operatorRefusal(request, nowSeconds(), settings_.operators, operatorReplays_);
}

http::Response Gateway::health(const http::Request& request) const
{
    if (const std::optional<http::Response> refused = operatorRefusal(request);
        refused.has_value()) {
        return *refused;
    }
    std::size_t sessions = 0;
    std::size_t endpoints = 0;
    std::size_t streams = 0;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        std::set<std::shared_ptr<Session>> seen;
        for (const auto& [socket, connection] : connections_) {
            (void)socket;
            if (!seen.insert(connection.session).second) {
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
        health::reportJson("gateway", kBuildVersion, startedAt_, nowSeconds(), extras.dump())};
}

http::Response Gateway::settingsShown(const http::Request& request) const
{
    if (const std::optional<http::Response> refused = operatorRefusal(request);
        refused.has_value()) {
        return *refused;
    }
    if (control_.configPath.empty()) {
        return opsRefusal(503, "this gateway was started without a config file to write to");
    }
    return {200, "application/json", {}, editable(
        writtenSettings(control_.configPath), identity_.fingerprint()).dump()};
}

http::Response Gateway::settingsChanged(const http::Request& request)
{
    if (const std::optional<http::Response> refused = operatorRefusal(request);
        refused.has_value()) {
        return *refused;
    }
    if (control_.configPath.empty()) {
        return opsRefusal(503, "this gateway was started without a config file to write to");
    }
    std::vector<std::pair<std::vector<std::string>, nlohmann::json>> writes;
    std::optional<std::vector<DirectRoute>> direct;
    std::optional<std::optional<ServerLink>> link;
    std::optional<log::Level> logLevel;
    try {
        const nlohmann::json body = bazarish::parseJson(request.body);
        if (body.contains("logLevel")) {
            const std::string named = server::logLevelIn(body, {});
            logLevel = log::levelFromString(named);
            writes.push_back({{"logLevel"}, named});
        }
        if (body.contains("i2pPrivacy")) {
            writes.push_back({{"i2p", "privacy"}, server::privacyIn(body, {})});
        }
        for (const char* const pool : {"stream", "call", "watch"}) {
            const std::string key = std::string(pool) + "Pool";
            if (!body.contains(key)) {
                continue;
            }
            const int depth = body.at(key).get<int>();
            if (depth < 0 || depth > static_cast<int>(kMaxPoolDepth)) {
                throw std::invalid_argument(
                    "a pool holds between 0 and " + std::to_string(kMaxPoolDepth) + " destinations");
            }
            writes.push_back({{"pools", pool}, depth});
        }
        if (body.contains("publicAddress")) {
            const std::string address
                = publicAddressFrom(body.at("publicAddress").get<std::string>());
            writes.push_back({{"publicAddress"}, address});
        }
        if (body.contains("direct")) {
            direct = directRoutesFrom(body.at("direct"));
            writes.push_back({{"direct"}, body.at("direct")});
        }
        if (body.contains("server")) {
            link = serverLinkFrom(body.at("server"));
            writes.push_back({{"server"}, body.at("server")});
        }
    } catch (const std::exception& error) {
        return opsRefusal(400, error.what());
    }

    ConfigFile file(control_.configPath);
    for (const auto& [keys, value] : writes) {
        file.set(keys, value);
    }
    if (direct.has_value()) {
        {
            const std::lock_guard<std::mutex> lock(directMutex_);
            direct_ = std::move(*direct);
            bazarish::log::info("{} direct route(s) now", direct_.size());
        }
        dropUnrouted();
    }
    if (link.has_value()) {
        setServerLink(std::move(*link));
    }
    if (logLevel.has_value()) {
        log::setLevel(*logLevel);
    }
    return {200, "application/json", {}, editable(
        writtenSettings(control_.configPath), identity_.fingerprint()).dump()};
}

http::Response Gateway::restart(const http::Request& request)
{
    if (const std::optional<http::Response> refused = operatorRefusal(request);
        refused.has_value()) {
        return *refused;
    }
    if (!control_.requestRestart) {
        return opsRefusal(503, "this gateway cannot restart itself: it was started without a"
                               " supervisor");
    }
    bazarish::log::info("restarting at the operator's request");
    control_.requestRestart();
    return {200, "application/json", {}, R"({"restarting":true})"};
}

http::Response Gateway::decoy() const
{
    const std::size_t size = static_cast<std::size_t>(
        randomBetween(settings_.decoyMinBytes, settings_.decoyMaxBytes));
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
    routes.maxMessageBytes = gateway::kMaxRecordBytes;
    routes.idleTimeout = kKeepalive + kPongTimeout;
    routes.admit = [this](const http::Request& request) -> std::optional<http::Response> {
        if (!admitted(request)) {
            return notFound();
        }
        return std::nullopt;
    };
    routes.opened = [this](const http::SocketPtr& raw, const http::Request&) { rawOpened(raw); };
    routes.message
        = [this](const http::SocketPtr& raw, const std::vector<unsigned char>& message) {
              rawMessage(raw, message);
          };
    routes.closed = [this](const http::SocketPtr& raw) { rawClosed(raw); };
    server_.upgrade(settings_.basePath, std::move(routes));

    const http::Handler answer = [this](const http::Request& request) {
        if (!admitted(request)) {
            return notFound();
        }
        return decoy();
    };
    server_.route(http::kAnyMethod, "*", answer);
    streamPool_ = std::make_unique<DestinationPool>(
        router_, shapeOf(false, false, false), settings_.streamPool);
    callPool_ = std::make_unique<DestinationPool>(
        router_, shapeOf(true, true, true), settings_.callPool);
    watchPool_ = std::make_unique<DestinationPool>(router_, shapeOf(true, true, false),
        settings_.watchPool, DestinationPool::Use::eWatching);
    bindOps();
    const int bound = server_.start();
    bazarish::log::info("its fingerprint, which a link carries: {}", identity_.fingerprint());
    running_.store(true);
    status_ = std::thread([this]() { statusLoop(); });
    link_ = std::thread([this]() { linkLoop(); });
    return bound;
}

void Gateway::bindOps()
{
    if (settings_.opsPort == 0) {
        return;
    }
    const tls::Credential credential = tls::selfSigned(settings_.stateDir);
    http::Server::Options options;
    options.host = settings_.opsHost;
    options.port = settings_.opsPort;
    options.threads = 1;
    options.certificate = credential.certificate.string();
    options.key = credential.key.string();
    options.clientPins = settings_.opsClients;
    ops_ = std::make_unique<http::Server>(options);
    ops_->get("/healthz", [this](const http::Request& request) { return health(request); });
    ops_->get(fleet::kOpsSettings,
        [this](const http::Request& request) { return settingsShown(request); });
    ops_->put(fleet::kOpsSettings,
        [this](const http::Request& request) { return settingsChanged(request); });
    ops_->post(fleet::kOpsRestart, [this](const http::Request& request) { return restart(request); });
    logFeed_ = std::make_unique<server::LogFeed>(*ops_, fleet::kOpsLogs, control_.logRing,
        [this](const http::Request& request) { return operatorRefusal(request); });
    ops_->start();
    bazarish::log::info("ops listening on {}:{}, key {}", settings_.opsHost, settings_.opsPort,
        credential.pin);
}

void Gateway::stop()
{
    const bool wasRunning = running_.exchange(false);
    {
        const std::lock_guard<std::mutex> lock(dialMutex_);
    }
    dialDone_.notify_all();
    if (wasRunning && status_.joinable()) {
        status_.join();
    }
    {
        const std::lock_guard<std::mutex> lock(linkMutex_);
        if (watch_) {
            watch_->close();
        }
    }
    linkChanged_.notify_all();
    if (link_.joinable()) {
        link_.join();
    }
    std::vector<std::shared_ptr<Session>> held;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        held = sessions_.drain();
    }
    for (const std::shared_ptr<Session>& session : held) {
        retire(session);
    }
    reapDials(true);
    if (streamPool_) {
        streamPool_->stop();
    }
    if (watchPool_) {
        watchPool_->stop();
    }
    if (callPool_) {
        callPool_->stop();
    }
    server_.stop();
    if (ops_) {
        ops_->stop();
    }
}

int Gateway::port() const
{
    return server_.port();
}

std::size_t Gateway::pooled() const
{
    return (streamPool_ ? streamPool_->held() : 0) + (callPool_ ? callPool_->held() : 0)
        + (watchPool_ ? watchPool_->held() : 0);
}

i2p::EndpointConfig Gateway::shapeOf(const bool raw, const bool published, const bool realtime) const
{
    i2p::EndpointConfig config;
    const bool call = raw && realtime;
    config.traffic = raw ? i2p::Traffic::eRaw : i2p::Traffic::eStream;
    config.privacy = call ? kCallPrivacy : settings_.tunnelPrivacy;
    config.tunnelQuantity = call ? i2p::kCallTunnelQuantity : i2p::kDefaultTunnelQuantity;
    config.published = published;
    config.realtime = realtime;
    config.label = raw ? "raw" : "stream";
    return config;
}

std::shared_ptr<i2p::Endpoint> Gateway::endpointFor(const i2p::EndpointConfig& config)
{
    for (const std::reference_wrapper<DestinationPool> pool :
        {std::ref(*streamPool_), std::ref(*callPool_), std::ref(*watchPool_)}) {
        if (pool.get().fits(config)) {
            return pool.get().take(config);
        }
    }
    return router_.createEndpoint(config);
}

void Gateway::rawOpened(const http::SocketPtr& raw)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        openings_[raw] = 0;
    }
    const Bytes card = cover_.seal(gateway::padded(card_));
    raw->send(std::vector<unsigned char>(card.begin(), card.end()));
}

void Gateway::rawMessage(const http::SocketPtr& raw, const std::vector<unsigned char>& message)
{
    std::shared_ptr<gateway::ChannelSocket> channel;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = channels_.find(raw);
        if (found != channels_.end()) {
            channel = found->second;
        }
    }
    if (channel == nullptr) {
        handshake(raw, Bytes(message.begin(), message.end()));
        return;
    }
    const std::optional<Bytes> opened = channel->openRecord(Bytes(message.begin(), message.end()));
    if (!opened.has_value()) {
        bazarish::log::debug("a record that does not open; the socket is closed");
        raw->close();
        return;
    }
    socketMessage(channel, std::vector<unsigned char>(opened->begin(), opened->end()));
}

void Gateway::rawClosed(const http::SocketPtr& raw)
{
    std::shared_ptr<gateway::ChannelSocket> channel;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        openings_.erase(raw);
        const auto found = channels_.find(raw);
        if (found != channels_.end()) {
            channel = found->second;
            channels_.erase(found);
        }
    }
    if (channel != nullptr) {
        socketClosed(channel);
    }
}

void Gateway::handshake(const http::SocketPtr& raw, const Bytes& message)
{
    const std::int64_t now = nowSeconds();
    const Bytes ticket = gateway::ticketOf(message);
    std::shared_ptr<Session> held;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        held = sessions_.holding(ticket, now);
    }
    if (held != nullptr) {
        const std::shared_ptr<gateway::Records> records
            = std::make_shared<gateway::Records>(held->key, ticket, gateway::Side::eGateway);
        const std::optional<Bytes> opened = records->open(gateway::joinRecordOf(message));
        bool spent = false;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            spent = opened.has_value() && !held->retired && held->tickets.erase(std::string(ticket.begin(), ticket.end())) > 0;
        }
        if (spent) {
            const Bytes joined = gateway::makeJoined(*records);
            raw->send(std::vector<unsigned char>(joined.begin(), joined.end()));
            establish(raw, records, held, /*resumed=*/true);
            return;
        }
    }
    if (const std::optional<Key> client = gateway::openHello(cover_, message, sealing_)) {
        gateway::Welcome welcome;
        welcome.sessionKey = randomBytes(gateway::kSessionKeyBytes);
        welcome.salt = randomBytes(gateway::kTicketBytes);
        std::shared_ptr<Session> fresh;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            fresh = sessions_.open(now);
            fresh->key = welcome.sessionKey;
            welcome.tickets = fresh->issueTickets(gateway::kTicketsHeld);
        }
        const Bytes answer = gateway::makeWelcome(cover_, welcome, *client, identity_);
        raw->send(std::vector<unsigned char>(answer.begin(), answer.end()));
        establish(raw,
            std::make_shared<gateway::Records>(
                welcome.sessionKey, welcome.salt, gateway::Side::eGateway),
            fresh, /*resumed=*/false);
        return;
    }
    bool again = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = openings_.find(raw);
        again = found != openings_.end() && found->second++ == 0;
    }
    if (!again) {
        ++refused_;
        raw->close();
        return;
    }
    const Bytes refused = gateway::refusedJoin();
    raw->send(std::vector<unsigned char>(refused.begin(), refused.end()));
}

void Gateway::establish(const http::SocketPtr& raw, std::shared_ptr<gateway::Records> records,
    const std::shared_ptr<Session>& session, const bool resumed)
{
    const std::shared_ptr<gateway::ChannelSocket> channel
        = std::make_shared<gateway::ChannelSocket>(raw, std::move(records));
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        openings_.erase(raw);
        channels_[raw] = channel;
    }
    bindSession(channel, session, resumed);
}

void Gateway::bindSession(
    const http::SocketPtr& socket, const std::shared_ptr<Session>& session, const bool resumed)
{
    const std::int64_t now = nowSeconds();
    bool full = false;
    std::vector<std::shared_ptr<Session>> swept;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        swept = sessions_.sweep(now);
        Connection connection;
        connection.session = session;
        connection.resumed = resumed;
        if (resumed) {
            ++rejoins_;
        }
        if (session->full()) {
            full = true;
        } else {
            session->addSocket();
            connections_.emplace(socket, connection);
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

void Gateway::topUpTickets(const std::shared_ptr<Session>& session, const http::SocketPtr& socket)
{
    nlohmann::json tickets = nlohmann::json::array();
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const std::size_t held = session->tickets.size();
        if (held >= gateway::kTicketsHeld) {
            return;
        }
        for (const Bytes& ticket : session->issueTickets(gateway::kTicketsHeld - held)) {
            tickets.push_back(toBase64(ticket));
        }
    }
    socket->send(encodeJson(FrameType::eTickets, 0, {{"tickets", tickets}}));
}

void Gateway::retire(const std::shared_ptr<Session>& session)
{
    std::vector<std::shared_ptr<EndpointEntry>> endpoints;
    std::vector<std::shared_ptr<StreamEntry>> streams;
    bool publishedGone = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, endpoint] : session->endpoints) {
            (void)id;
            publishedGone = publishedGone || endpoint->published;
            unpublishLocked(*endpoint);
            endpoint->running.store(false);
            endpoints.push_back(endpoint);
        }
        flowChanged_.notify_all();
        for (const auto& [id, stream] : session->streams) {
            (void)id;
            streams.push_back(stream);
        }
        session->endpoints.clear();
        session->streams.clear();
        session->retired = true;
    }
    for (const std::shared_ptr<StreamEntry>& stream : streams) {
        orphan(stream);
        stream->running.store(false);
        wakeFlows();
        if (stream->stream) {
            stream->stream->close();
        }
        joinTaken(stream->reader);
    }
    for (const std::shared_ptr<EndpointEntry>& endpoint : endpoints) {
        if (endpoint->endpoint) {
            endpoint->endpoint->stop();
        }
        joinTaken(endpoint->worker);
    }
    if (publishedGone) {
        dropUnrouted();
    }
}

void Gateway::socketClosed(const http::SocketPtr& socket)
{
    const std::int64_t now = nowSeconds();
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = connections_.find(socket);
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
        onFrame(socket, decode(message));
    } catch (const ProtocolError& error) {
        fail(socket, 0, error.fault(), error.what());
        socket->close();
    } catch (const std::exception& error) {
        bazarish::log::warn("a frame ended badly: {}", error.what());
        fail(socket, 0, Fault::eInternal, "the gateway failed at this");
        socket->close();
    }
}

std::shared_ptr<Session> Gateway::sessionFor(const http::SocketPtr& socket) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = connections_.find(socket);
    return found == connections_.end() ? nullptr : found->second.session;
}

http::SocketPtr Gateway::outletFor(const Session& session, const StreamEntry& stream)
{
    const auto found = session.endpoints.find(stream.endpoint);
    if (found != session.endpoints.end() && found->second->socket) {
        return found->second->socket;
    }
    if (session.replayDue > std::chrono::steady_clock::now()) {
        return nullptr;
    }
    return session.control;
}

http::SocketPtr Gateway::answerOn(const Session& session, const http::SocketPtr& asked)
{
    if (asked != nullptr && asked->open()) {
        return asked;
    }
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
    for (const std::shared_ptr<StreamEntry>& entry : held) {
        pump(session, entry);
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
    const std::shared_ptr<Session> session = sessionFor(socket);
    if (session == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "this socket belongs to no session");
        socket->close();
        return;
    }
    if (frame.type == FrameType::eEndpointCreate || frame.type == FrameType::eStreamOpen) {
        std::optional<Bytes> already;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            already = session->answered(frame.ref);
        }
        if (already.has_value()) {
            socket->send(*already);
            return;
        }
    }
    if (const http::SocketPtr lane = laneFor(*session, frame);
        lane != nullptr && lane != socket) {
        fail(socket, frame.ref, Fault::eWrongLane, "that flow does not ride this socket");
        return;
    }
    if (frame.type != FrameType::eResume) {
        replayDone(session);
    }
    switch (frame.type) {
        case FrameType::eAttach: onAttach(socket, frame); return;
        case FrameType::eResume: onResume(session, socket, frame); return;
        case FrameType::eEndpointCreate: onEndpointCreate(session, socket, frame); return;
        case FrameType::eEndpointStop: onEndpointStop(session, socket, frame); return;
        case FrameType::eEndpointDelegate: onEndpointDelegate(session, socket, frame); return;
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
        fail(socket, frame.ref, Fault::eVersion,
            "this gateway speaks version " + std::to_string(kProtocolVersion));
        socket->close();
        return;
    }

    Connection connection;
    http::SocketPtr replaced;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = connections_.find(socket);
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
        replaced = connection.session->control;
        connection.session->control = socket;
        flowChanged_.notify_all();
        connection.session->replayDue = connection.session->streams.empty()
            ? std::chrono::steady_clock::time_point{}
            : std::chrono::steady_clock::now() + kReplayGrace;
    }

    nlohmann::json endpoints = nlohmann::json::array();
    nlohmann::json streams = nlohmann::json::array();
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, endpoint] : connection.session->endpoints) {
            endpoints.push_back({{"id", id}, {"kind", endpoint->raw ? "raw" : "stream"},
                {"ready", endpoint->ready}, {"host", endpoint->host},
                {"tunnelsIn", endpoint->inboundTunnels},
                {"tunnelsOut", endpoint->outboundTunnels}, {"leaseSets", endpoint->leaseSets},
                {"localRoute", endpoint->localRoute.load()}});
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
                {"proxy", false}, {"offlineKeys", false}, {"warmPool", true}}},
        {"resumed", connection.resumed},
        {"endpoints", endpoints},
        {"streams", streams},
    };
    topUpTickets(connection.session, socket);
    socket->send(encodeJson(FrameType::eReady, frame.ref, ready));
}

namespace {

constexpr std::chrono::seconds kAcceptWait{1};
constexpr std::chrono::milliseconds kDatagramWait{200};

std::shared_ptr<EndpointEntry> endpointOf(const Session& session, const std::uint32_t id)
{
    const auto found = session.endpoints.find(id);
    if (found == session.endpoints.end() || !found->second->made) {
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

void Gateway::unpublishLocked(const EndpointEntry& entry)
{
    if (published_.erase(entry.host) > 0 && entry.identity.empty()) {
        goneHere_[entry.host] = std::chrono::steady_clock::now() + kGoneHereMemory;
    }
}

bool Gateway::goneHereLocked(const std::string& host)
{
    const auto now = std::chrono::steady_clock::now();
    std::erase_if(goneHere_, [now](const auto& gone) { return gone.second <= now; });
    return goneHere_.count(host) > 0;
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
    i2p::EndpointConfig config = shapeOf(
        kind == "raw", body.value("published", true), body.value("realtime", false));
    try {
        readLeaseSetAuth(body, config);
    } catch (const std::exception& error) {
        fail(socket, frame.ref, Fault::eBadFrame, error.what());
        return;
    }
    const std::string target = body.value("target", std::string());

    std::shared_ptr<EndpointEntry> entry;
    bool routable = false;
    bool local = false;
    std::size_t servedHere = 0;
    bool full = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (session->endpoints.count(frame.ref) > 0) {
            return;
        }
        full = session->retired || session->endpoints.size() >= kMaxEndpointsPerSession;
    }
    if (full) {
        fail(socket, frame.ref, Fault::eRefused,
            "this session holds as many destinations as it may");
        return;
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = std::make_shared<EndpointEntry>();
        entry->id = frame.ref;
        entry->raw = kind == "raw";
        entry->published = config.published;
        entry->realtime = config.realtime;
        entry->readersOnly = !config.leaseSetReaders.empty();
        entry->readers = config.leaseSetReaders;
        if (!config.leaseSetReaderKey.empty()) {
            entry->readerPublic = Key::fromRawX25519Private(config.leaseSetReaderKey).rawPublic();
        }
        if (config.keys.has_value()) {
            entry->identity = config.keys->publicBase64();
            entry->delegationExpires = config.keys->transientExpires();
        }
        routable = !entry->raw && !entry->published && !target.empty();
        local = routable && reachesLocallyLocked(target);
        if (routable && !local) {
            const std::lock_guard<std::mutex> listed(linkMutex_);
            servedHere = served_.size();
        }
        session->endpoints.emplace(entry->id, entry);
    }
    if (routable && !local) {
        bazarish::log::info(
            "a destination for {} goes into I2P, not routed here; the server lists {}",
            target, servedHere);
    }
    std::shared_ptr<i2p::Endpoint> endpoint;
    std::string publicBase64;
    if (local) {
        publicBase64 = i2p::Keys::generate().publicBase64();
    } else {
        try {
            endpoint = endpointFor(config);
            publicBase64 = endpoint->publicBase64();
        } catch (const std::exception& error) {
            bazarish::log::warn("a destination was not made: {}", error.what());
            const Bytes refusal = encodeJson(FrameType::eError, frame.ref,
                {{"code", faultName(Fault::eRefused)}, {"message", error.what()}});
            ++refused_;
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                session->endpoints.erase(frame.ref);
                session->remember(frame.ref, refusal);
            }
            socket->send(refusal);
            return;
        }
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry->endpoint = endpoint;
        entry->publicBase64 = publicBase64;
        entry->host = endpoint ? endpoint->routingHost() : i2p::routingHost(publicBase64);
        if (local) {
            entry->target = target;
            entry->localRoute.store(true);
        }
        entry->made = true;
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

    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!entry->running.load()) {
            return;
        }
        try {
            if (entry->raw) {
                entry->worker
                    = std::thread([this, entry]() { datagramLoop(entry); });
            } else if (entry->published) {
                entry->worker
                    = std::thread([this, session, entry]() { acceptLoop(session, entry); });
            }
            return;
        } catch (const std::system_error& error) {
            bazarish::log::warn("no thread for a destination: {}", error.what());
            unpublishLocked(*entry);
            entry->running.store(false);
            session->endpoints.erase(entry->id);
        }
    }
    if (entry->endpoint) {
        entry->endpoint->stop();
    }
    if (const http::SocketPtr out = answerOn(*session, socket)) {
        out->send(encode(FrameType::eEndpointLost, entry->id));
    }
}

void Gateway::onEndpointDelegate(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    std::optional<i2p::Keys> keys;
    try {
        keys = delegationIn(bodyJson(frame).at("keys"));
    } catch (const std::exception& error) {
        fail(socket, frame.ref, Fault::eBadFrame, error.what());
        return;
    }
    std::shared_ptr<EndpointEntry> entry;
    std::shared_ptr<i2p::Endpoint> endpoint;
    std::int64_t held = 0;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = endpointOf(*session, frame.ref);
        if (entry != nullptr) {
            held = entry->delegationExpires;
            endpoint = entry->endpoint;
        }
    }
    if (entry == nullptr || held == 0 || endpoint == nullptr) {
        fail(socket, frame.ref, Fault::eNoEndpoint, "no presence address by that id on this session");
        return;
    }
    if (keys->publicBase64() != entry->identity) {
        fail(socket, frame.ref, Fault::eBadFrame, "a delegation for another address");
        return;
    }
    if (keys->transientExpires() <= held) {
        fail(socket, frame.ref, Fault::eBadFrame, "a delegation that ends no later than the one held");
        return;
    }
    endpoint->refreshOfflineSignature(*keys);
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry->delegationExpires = keys->transientExpires();
        entry->delegationAskedAt = 0;
    }
    socket->send(encode(FrameType::eOk, frame.ref));
}

void Gateway::lapseDelegations(const std::int64_t now)
{
    std::vector<std::pair<std::shared_ptr<Session>, std::uint32_t>> lapsed;
    std::vector<std::pair<http::SocketPtr, Bytes>> asks;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const std::shared_ptr<Session>& session : sessions_.all()) {
            for (const auto& [id, entry] : session->endpoints) {
                const std::int64_t expires = entry->delegationExpires;
                if (expires == 0) {
                    continue;
                }
                if (i2p::delegationLapsed(expires, now)) {
                    lapsed.emplace_back(session, id);
                } else if (now >= expires - kDelegationAskLeadSeconds && session->control
                    && now - entry->delegationAskedAt >= kDelegationAskEverySeconds) {
                    entry->delegationAskedAt = now;
                    asks.emplace_back(session->control,
                        encodeJson(FrameType::eEndpointRenew, id, {{"expires", expires}}));
                }
            }
        }
    }
    for (const auto& [socket, frame] : asks) {
        socket->send(frame);
    }
    for (const auto& [session, id] : lapsed) {
        if (!stopAsLost(session, id)) {
            continue;
        }
        bazarish::log::info("a presence address outlived its delegation and was stopped");
    }
}

void Gateway::onEndpointStop(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    const std::shared_ptr<EndpointEntry> entry = stopEndpoint(session, frame.ref);
    if (entry == nullptr) {
        fail(socket, frame.ref, Fault::eNoEndpoint, "no such destination on this session");
        return;
    }
    socket->send(encode(FrameType::eOk, frame.ref));
    if (entry->published) {
        dropUnrouted();
    }
}

std::shared_ptr<EndpointEntry> Gateway::stopEndpoint(
    const std::shared_ptr<Session>& session, const std::uint32_t id)
{
    std::shared_ptr<EndpointEntry> entry;
    std::vector<std::shared_ptr<StreamEntry>> orphans;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = endpointOf(*session, id);
        if (entry == nullptr) {
            return nullptr;
        }
        entry->running.store(false);
        flowChanged_.notify_all();
        session->endpoints.erase(id);
        unpublishLocked(*entry);
        for (auto at = session->streams.begin(); at != session->streams.end();) {
            if (at->second->endpoint == id) {
                orphans.push_back(at->second);
                at = session->streams.erase(at);
            } else {
                ++at;
            }
        }
    }
    if (entry->endpoint) {
        entry->endpoint->stop();
    }
    for (const std::shared_ptr<StreamEntry>& stranded : orphans) {
        orphan(stranded);
        stranded->running.store(false);
        wakeFlows();
        if (stranded->stream) {
            stranded->stream->close();
        }
        joinTaken(stranded->reader);
    }
    joinTaken(entry->worker);
    return entry;
}

bool Gateway::stopAsLost(const std::shared_ptr<Session>& session, const std::uint32_t id)
{
    if (stopEndpoint(session, id) == nullptr) {
        return false;
    }
    http::SocketPtr control;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        control = session->control;
    }
    if (control) {
        control->send(encodeJson(FrameType::eEndpointLost, id, nlohmann::json::object()));
    }
    return true;
}

void Gateway::sendInPieces(http::Socket& socket, const std::uint32_t id, const Bytes& data)
{
    for (std::size_t at = 0; at < data.size(); at += kMaxBodyBytes) {
        const std::size_t piece = std::min(kMaxBodyBytes, data.size() - at);
        socket.send(encode(FrameType::eStreamData, id, ByteView(data).subspan(at, piece)));
    }
}

void Gateway::onRawSend(const std::shared_ptr<Session>& session, const http::SocketPtr& socket,
    const Frame& frame)
{
    const RawSend sent = decodeRawSend(frame);
    std::shared_ptr<EndpointEntry> from;
    std::shared_ptr<Session> peerSession;
    std::shared_ptr<EndpointEntry> peer;
    http::SocketPtr peerLane;
    bool gone = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        from = endpointOf(*session, frame.ref);
        if (from == nullptr) {
            fail(socket, frame.ref, Fault::eNoEndpoint, "no such destination on this session");
            return;
        }
        if (!from->raw) {
            fail(socket, frame.ref, Fault::eUnsupported, "that destination carries streams");
            return;
        }
        peer = localFor(sent.host, peerSession);
        if (peer != nullptr && (!peer->raw || !readsLeaseSetOf(*from, *peer))) {
            peer = nullptr;
        }
        if (peer != nullptr) {
            peerLane = peer->socket;
        }
        gone = peer == nullptr && goneHereLocked(sent.host);
    }
    if (gone) {
        return;
    }
    if (peer != nullptr) {
        from->localRoute.store(true);
        peer->localRoute.store(true);
        if (peerLane) {
            peerLane->send(encode(FrameType::eRawRecv, peer->id, sent.payload));
        }
        return;
    }
    from->endpoint->sendRawDatagram(sent.host, sent.payload);
}

void Gateway::datagramLoop(const std::shared_ptr<EndpointEntry>& entry)
{
    while (entry->running.load()) {
        std::vector<std::uint8_t> payload;
        try {
            payload = entry->endpoint->receiveRawDatagram(kDatagramWait);
        } catch (const std::exception& error) {
            bazarish::log::debug("datagrams stopped: {}", error.what());
            break;
        }
        if (payload.empty()) {
            continue;
        }
        if (payload.size() > kMaxBodyBytes) {
            continue;
        }
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
}

void Gateway::onStreamOpen(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    const nlohmann::json body = bodyJson(frame);
    const std::uint32_t endpointId = body.value("endpoint", 0U);
    const std::string host = body.value("host", std::string());
    const std::chrono::seconds deadline(body.value("deadline", 0));
    if (host.empty() || deadline.count() <= 0 || deadline > kMaxDialDeadline) {
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
        if (!from->target.empty() && host != from->target) {
            fail(socket, frame.ref, Fault::eRefused, "this destination dials only its target");
            return;
        }
        if (streamOf(*session, frame.ref) != nullptr) {
            fail(socket, frame.ref, Fault::eBadFrame, "that identifier is already a stream");
            return;
        }
        if (session->dialling.count(frame.ref) > 0) {
            return;
        }
        if (session->retired || session->dialling.size() >= kMaxDialsPerSession
            || session->streams.size() >= kMaxStreamsPerSession) {
            fail(socket, frame.ref, Fault::eRefused, "this session has as many streams as it may");
            return;
        }
        session->dialling.insert(frame.ref);
    }
    std::shared_ptr<Session> owner;
    std::shared_ptr<EndpointEntry> to;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        to = localFor(host, owner);
        if (to != nullptr && to->raw) {
            to = nullptr;
        }
        if (to == nullptr && goneHereLocked(host)) {
            session->dialling.erase(frame.ref);
            fail(socket, frame.ref, Fault::eUnreachable, "that destination closed on this gateway");
            return;
        }
    }
    if (to != nullptr && meetLocally(session, from, frame.ref, owner, to, socket)) {
        const std::lock_guard<std::mutex> lock(mutex_);
        session->dialling.erase(frame.ref);
        return;
    }

    reapDials(false);
    try {
        const std::shared_ptr<std::atomic<bool>> done = std::make_shared<std::atomic<bool>>(false);
        std::thread dialling([this, session, from, ref = frame.ref, host, deadline, socket, done]() {
            dial(session, from, ref, host, deadline, socket);
            done->store(true);
        });
        {
            const std::lock_guard<std::mutex> lock(dialMutex_);
            dialThreads_.push_back(DialThread{std::move(dialling), done});
        }
        ++dials_;
    } catch (const std::system_error& error) {
        bazarish::log::warn("no thread for a dial: {}", error.what());
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            session->dialling.erase(frame.ref);
        }
        fail(socket, frame.ref, Fault::eRefused, "the gateway has no room for another dial");
    }
}

void Gateway::reapDials(const bool all)
{
    std::list<DialThread> finished;
    {
        const std::lock_guard<std::mutex> lock(dialMutex_);
        for (auto it = dialThreads_.begin(); it != dialThreads_.end();) {
            if (all || it->done->load()) {
                finished.splice(finished.end(), dialThreads_, it++);
            } else {
                ++it;
            }
        }
    }
    for (DialThread& dial : finished) {
        dial.thread.join();
    }
}

std::optional<DirectRoute> Gateway::directFor(const std::string& host) const
{
    const std::lock_guard<std::mutex> lock(directMutex_);
    for (const DirectRoute& route : direct_) {
        if (route.dest == host) {
            return route;
        }
    }
    return std::nullopt;
}

void Gateway::dial(const std::shared_ptr<Session>& session,
    const std::shared_ptr<EndpointEntry>& from, const std::uint32_t stream, std::string host,
    const std::chrono::seconds deadline, const http::SocketPtr& answerTo)
{
    const auto until = std::chrono::steady_clock::now() + deadline;
    const std::optional<DirectRoute> route = directFor(host);
    const std::optional<std::pair<ServerLink, tls::Credential>> server
        = route.has_value() ? std::nullopt : serverFor(host);
    const bool bypass = route.has_value() || server.has_value();
    std::unique_ptr<Conduit> opened;
    while (std::chrono::steady_clock::now() < until && from->running.load() && running_.load()
        && (bypass || from->endpoint != nullptr)) {
        const auto left = std::max(std::chrono::duration_cast<std::chrono::seconds>(
                                       until - std::chrono::steady_clock::now()),
            std::chrono::seconds(1));
        try {
            if (route.has_value()) {
                opened = overTls(*route, left);
            } else if (server.has_value()) {
                opened
                    = overServer(server->first, server->second, host, from->publicBase64, left);
            } else {
                opened = overI2p(from->endpoint->connect(host, left));
            }
        } catch (const std::exception& error) {
            bazarish::log::debug("a dial did not open: {}", error.what());
            opened.reset();
        }
        if (opened != nullptr) {
            break;
        }
        std::unique_lock<std::mutex> lock(dialMutex_);
        dialDone_.wait_for(lock, kDialRetryDelay, [this]() { return !running_.load(); });
    }
    if (opened == nullptr) {
        const Bytes answer = encodeJson(
            FrameType::eStreamReset, stream, {{"code", faultName(Fault::eUnreachable)}});
        http::SocketPtr out;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            session->dialling.erase(stream);
            session->abandoned.erase(stream);
            session->remember(stream, answer);
            out = answerOn(*session, answerTo);
        }
        if (out) {
            out->send(answer);
        }
        return;
    }

    if (bypass) {
        from->localRoute.store(true);
    }
    std::shared_ptr<StreamEntry> entry = std::make_shared<StreamEntry>();
    entry->id = stream;
    entry->endpoint = from->id;
    entry->stream = std::move(opened);
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        session->dialling.erase(stream);
        if (session->retired || session->abandoned.erase(stream) > 0) {
            entry->stream->close();
            return;
        }
        session->streams.emplace(stream, entry);
        const Bytes answer = encode(FrameType::eStreamOpened, stream);
        session->remember(stream, answer);
        if (const http::SocketPtr out = answerOn(*session, answerTo)) {
            out->send(answer);
        }
    }
    bool reading = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        reading = !entry->running.load() || startReaderLocked(session, entry);
    }
    if (!reading) {
        endWithoutReader(session, entry, answerTo);
    }
}

bool Gateway::startReaderLocked(
    const std::shared_ptr<Session>& session, const std::shared_ptr<StreamEntry>& entry)
{
    try {
        entry->reader = std::thread([this, session, entry]() { readLoop(session, entry); });
        return true;
    } catch (const std::system_error& error) {
        bazarish::log::warn("no thread for a stream: {}", error.what());
        session->streams.erase(entry->id);
        return false;
    }
}

void Gateway::endWithoutReader(const std::shared_ptr<Session>& session,
    const std::shared_ptr<StreamEntry>& entry, const http::SocketPtr& answerTo)
{
    entry->running.store(false);
    entry->stream->close();
    http::SocketPtr out;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        out = answerOn(*session, answerTo);
    }
    if (out) {
        out->send(encodeJson(
            FrameType::eStreamReset, entry->id, {{"code", faultName(Fault::eRefused)}}));
    }
}

// The check an encrypted lease set makes in I2P: only a holder of a reader's secret gets in.
bool Gateway::readsLeaseSetOf(const EndpointEntry& from, const EndpointEntry& to)
{
    const auto reader = std::find(to.readers.begin(), to.readers.end(), from.readerPublic);
    return !to.readersOnly || (!from.readerPublic.empty() && reader != to.readers.end());
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
            return false;
        }
        there->id = owner->ids().next();
        session->streams.emplace(here->id, here);
        owner->streams.emplace(there->id, there);
        answer = encode(FrameType::eStreamOpened, stream);
        session->remember(stream, answer);
        back = answerOn(*session, answerTo);
    }
    from->localRoute.store(true);
    to->localRoute.store(true);
    if (back) {
        back->send(answer);
    }
    control->send(encodeJson(FrameType::eStreamInbound, there->id,
        {{"endpoint", to->id}, {"peer", from->publicBase64}}));
    return true;
}

void Gateway::pump(
    const std::shared_ptr<Session>& session, const std::shared_ptr<StreamEntry>& entry)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    flowChanged_.notify_all();
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
        const ByteView chunk = ByteView(entry->waiting).first(piece);
        entry->book.wrote(chunk);
        out->send(encode(FrameType::eStreamData, entry->id, chunk));
        entry->waiting.erase(
            entry->waiting.begin(), entry->waiting.begin() + static_cast<std::ptrdiff_t>(piece));
        moved += piece;
    }
    if (entry->waiting.empty() && entry->endAfterDrain) {
        entry->endAfterDrain = false;
        entry->book.finishSending();
        out->send(encode(FrameType::eStreamClose, entry->id));
    }
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
        } catch (const std::exception& error) {
            bazarish::log::debug("accepting stopped: {}", error.what());
            break;
        }
        if (caller == nullptr) {
            continue;
        }
        std::shared_ptr<StreamEntry> inbound = std::make_shared<StreamEntry>();
        inbound->endpoint = entry->id;
        inbound->stream = overI2p(std::move(caller));
        bool full = false;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (!entry->running.load() || session->retired) {
                break;
            }
            full = session->streams.size() >= kMaxStreamsPerSession;
            if (!full) {
                inbound->id = session->ids().next();
                session->streams.emplace(inbound->id, inbound);
            }
        }
        if (full) {
            bazarish::log::info("an inbound stream refused: the session is full");
            inbound->stream->close();
            continue;
        }
        http::SocketPtr control;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            flowChanged_.wait(lock,
                [&]() { return !entry->running.load() || session->control != nullptr; });
            control = session->control;
        }
        if (!control) {
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                session->streams.erase(inbound->id);
            }
            inbound->stream->close();
            break;
        }
        control->send(encodeJson(FrameType::eStreamInbound, inbound->id,
            {{"endpoint", entry->id}, {"peer", peer}}));
        bool reading = false;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            reading = !inbound->running.load() || startReaderLocked(session, inbound);
        }
        if (!reading) {
            endWithoutReader(session, inbound, control);
        }
    }
}

void Gateway::readLoop(
    const std::shared_ptr<Session>& session, const std::shared_ptr<StreamEntry>& entry)
{
    std::vector<unsigned char> buffer(kMaxBodyBytes);
    while (entry->running.load()) {
        std::size_t room = 0;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            const std::size_t open = entry->book.room();
            room = open > entry->waiting.size()
                ? std::min(open - entry->waiting.size(), buffer.size())
                : 0;
        }
        if (room == 0) {
            pump(session, entry);
            std::unique_lock<std::mutex> lock(mutex_);
            flowChanged_.wait(lock, [&]() {
                return !entry->running.load() || entry->book.room() > entry->waiting.size();
            });
            continue;
        }
        std::size_t got = 0;
        try {
            got = entry->stream->readSome(ByteBuffer(buffer).first(room));
        } catch (const std::exception& error) {
            bazarish::log::debug("a stream stopped reading: {}", error.what());
            break;
        }
        if (got == 0) {
            break;
        }
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            entry->waiting.insert(entry->waiting.end(), buffer.begin(),
                buffer.begin() + static_cast<std::ptrdiff_t>(got));
        }
        pump(session, entry);
    }
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
    std::shared_ptr<StreamEntry> peer;
    std::shared_ptr<Session> theirs;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = streamOf(*session, frame.ref);
        if (entry != nullptr) {
            peer = entry->peer.lock();
            theirs = entry->peerSession.lock();
        }
    }
    if (entry == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "no such stream on this session");
        return;
    }
    entry->book.tookIn(frame.body.size());

    if (peer != nullptr && theirs != nullptr) {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            peer->waiting.insert(peer->waiting.end(), frame.body.begin(), frame.body.end());
        }
        pump(theirs, peer);
        return;
    }

    if (!entry->stream) {
        fail(socket, frame.ref, Fault::eClosed, "that stream's far side has gone");
        return;
    }
    entry->stream->writeAll(frame.body);
    entry->book.consumed(frame.body.size());
    http::SocketPtr out;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        out = outletFor(*session, *entry);
    }
    if (out) {
        out->send(encodeCredit(entry->id, entry->book.consumedTotal()));
    }
}

void Gateway::onStreamCredit(const std::shared_ptr<Session>& session,
    const http::SocketPtr& socket, const Frame& frame)
{
    std::shared_ptr<StreamEntry> entry;
    bool paired = false;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = streamOf(*session, frame.ref);
        paired = entry != nullptr && !entry->peer.expired();
    }
    if (entry == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "no such stream on this session");
        return;
    }
    entry->book.peerCredited(decodeCredit(frame));
    if (paired) {
        pump(session, entry);
    } else {
        wakeFlows();
    }
}

void Gateway::onStreamEnd(const std::shared_ptr<Session>& session, const Frame& frame)
{
    std::shared_ptr<StreamEntry> entry;
    std::shared_ptr<StreamEntry> peer;
    std::shared_ptr<Session> theirs;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        entry = streamOf(*session, frame.ref);
        if (entry == nullptr && session->dialling.count(frame.ref) > 0) {
            session->abandoned.insert(frame.ref);
        }
        if (entry != nullptr) {
            session->streams.erase(frame.ref);
            peer = entry->peer.lock();
            theirs = entry->peerSession.lock();
            if (peer != nullptr && theirs != nullptr) {
                peer->endAfterDrain = true;
                peer->peer.reset();
            }
        }
    }
    if (entry == nullptr) {
        return;
    }
    if (peer != nullptr && theirs != nullptr) {
        pump(theirs, peer);
        return;
    }
    teardown(entry);
}

void Gateway::joinTaken(std::thread& slot)
{
    std::thread taken;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        taken = std::move(slot);
    }
    if (taken.joinable()) {
        taken.join();
    }
}

void Gateway::orphan(const std::shared_ptr<StreamEntry>& entry)
{
    std::shared_ptr<StreamEntry> peer;
    std::shared_ptr<Session> theirs;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        peer = entry->peer.lock();
        theirs = entry->peerSession.lock();
        if (peer == nullptr || theirs == nullptr) {
            return;
        }
        peer->endAfterDrain = true;
        peer->peer.reset();
    }
    pump(theirs, peer);
}

// For a change made outside mutex_: taking it orders the change before any waiter's check.
void Gateway::wakeFlows()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
    }
    flowChanged_.notify_all();
}

void Gateway::teardown(const std::shared_ptr<StreamEntry>& entry)
{
    entry->running.store(false);
    wakeFlows();
    if (entry->stream) {
        entry->stream->close();
    }
    joinTaken(entry->reader);
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
            continue;
        }
        const Bytes again = entry->book.replay(said.value("received", std::uint64_t{0}));
        const std::lock_guard<std::mutex> lock(mutex_);
        const http::SocketPtr out = outletFor(*session, *entry);
        if (!out) {
            continue;
        }
        sendInPieces(*out, id, again);
    }
    afterReplay(session);
}

void Gateway::onAttach(const http::SocketPtr& socket, const Frame& frame)
{
    const std::shared_ptr<Session> session = sessionFor(socket);
    if (session == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "this socket belongs to no session");
        socket->close();
        return;
    }
    std::shared_ptr<EndpointEntry> endpoint;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        endpoint = endpointOf(*session, frame.ref);
        if (endpoint != nullptr) {
            endpoint->socket = socket;
        }
    }
    topUpTickets(session, socket);
    if (endpoint == nullptr) {
        fail(socket, frame.ref, Fault::eUnknownId, "no such destination on this session");
        return;
    }
    socket->send(encodeJson(FrameType::eOk, frame.ref, nlohmann::json::object()));
}

void Gateway::statusLoop()
{
    while (running_.load()) {
        std::this_thread::sleep_for(kStatusPeriod);
        if (!running_.load()) {
            break;
        }
        std::vector<std::shared_ptr<Session>> swept;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            swept = sessions_.sweep(nowSeconds());
        }
        for (const std::shared_ptr<Session>& gone : swept) {
            retire(gone);
        }
        lapseDelegations(nowSeconds());

        std::vector<i2p::LocalDestination> local;
        try {
            local = router_.localDestinations();
        } catch (const std::exception& error) {
            bazarish::log::warn("the router's destinations could not be read: {}",
                error.what());
            continue;
        }

        std::vector<std::pair<http::SocketPtr, Bytes>> outgoing;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            std::set<std::shared_ptr<Session>> seen;
            for (const auto& [socket, connection] : connections_) {
                (void)socket;
                const std::shared_ptr<Session>& session = connection.session;
                if (!session->control || !seen.insert(session).second) {
                    continue;
                }
                for (const auto& [id, entry] : session->endpoints) {
                    bool ready = false;
                    int in = 0;
                    int out = 0;
                    int leases = 0;
                    if (entry->endpoint == nullptr) {
                        ready = entry->made;
                    }
                    for (const i2p::LocalDestination& destination : local) {
                        if (entry->endpoint != nullptr && destination.host == entry->host) {
                            ready = destination.ready;
                            in = destination.inboundTunnels;
                            out = destination.outboundTunnels;
                            leases = destination.remoteLeaseSets;
                            break;
                        }
                    }
                    const bool localRoute = entry->localRoute.load();
                    if (ready == entry->ready && in == entry->inboundTunnels
                        && out == entry->outboundTunnels && leases == entry->leaseSets
                        && localRoute == entry->reportedLocalRoute) {
                        continue;
                    }
                    entry->ready = ready;
                    entry->inboundTunnels = in;
                    entry->outboundTunnels = out;
                    entry->leaseSets = leases;
                    entry->reportedLocalRoute = localRoute;
                    outgoing.emplace_back(session->control,
                        encodeJson(FrameType::eEndpointStatus, id,
                            {{"ready", ready}, {"host", entry->host}, {"tunnelsIn", in},
                                {"tunnelsOut", out}, {"leaseSets", leases},
                                {"localRoute", localRoute}}));
                }
            }
        }
        for (const auto& [socket, frame] : outgoing) {
            socket->send(frame);
        }
    }
}

void Gateway::setServerLink(std::optional<ServerLink> link)
{
    std::shared_ptr<server::TlsPipe> watching;
    {
        const std::lock_guard<std::mutex> lock(linkMutex_);
        if (serverLink_ == link) {
            return;
        }
        serverLink_ = std::move(link);
        watching = watch_;
    }
    if (watching) {
        watching->close();
    }
    linkChanged_.notify_all();
}

std::optional<std::pair<ServerLink, tls::Credential>> Gateway::serverFor(
    const std::string& host) const
{
    const std::lock_guard<std::mutex> lock(linkMutex_);
    if (!serverLink_.has_value() || !own_.has_value() || served_.count(host) == 0) {
        return std::nullopt;
    }
    return std::make_pair(*serverLink_, *own_);
}

bool Gateway::reachesLocallyLocked(const std::string& host) const
{
    const auto found = published_.find(host);
    if (found != published_.end()) {
        const std::shared_ptr<EndpointEntry> entry = found->second.endpoint.lock();
        if (entry != nullptr && !entry->raw) {
            return true;
        }
    }
    if (directFor(host).has_value()) {
        return true;
    }
    const std::lock_guard<std::mutex> lock(linkMutex_);
    return served_.count(host) > 0;
}

void Gateway::dropUnrouted()
{
    std::vector<std::pair<std::shared_ptr<Session>, std::uint32_t>> stranded;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const std::shared_ptr<Session>& session : sessions_.all()) {
            for (const auto& [id, entry] : session->endpoints) {
                if (!entry->target.empty() && !reachesLocallyLocked(entry->target)) {
                    stranded.emplace_back(session, id);
                }
            }
        }
    }
    for (const auto& [session, id] : stranded) {
        if (!stopAsLost(session, id)) {
            continue;
        }
        bazarish::log::info("a destination lost its route and was stopped");
    }
}

void Gateway::linkLoop()
{
    std::string lastFailure;
    while (running_.load()) {
        ServerLink link;
        tls::Credential own;
        {
            std::unique_lock<std::mutex> lock(linkMutex_);
            linkChanged_.wait(
                lock, [this]() { return !running_.load() || serverLink_.has_value(); });
            if (!running_.load()) {
                return;
            }
            if (!own_.has_value()) {
                own_ = tls::selfSigned(settings_.stateDir);
            }
            link = *serverLink_;
            own = *own_;
        }
        try {
            const std::shared_ptr<server::TlsPipe> pipe
                = server::TlsPipe::dial(link.host, link.port, link.pin, kServerHandshake, own);
            {
                const std::lock_guard<std::mutex> lock(linkMutex_);
                watch_ = pipe;
                if (!running_.load() || serverLink_ != link) {
                    pipe->close();
                }
            }
            const std::string ask = nlohmann::json({{"watch", true}}).dump() + "\n";
            pipe->writeAll(viewOf(ask));
            bazarish::log::info("linked to the server at {}:{}", link.host, link.port);
            lastFailure.clear();
            for (;;) {
                const nlohmann::json listed
                    = bazarish::parseJson(pipe->readLine(kMaxServedListBytes));
                std::set<std::string> served;
                for (const nlohmann::json& dest : listed.at("dests")) {
                    served.insert(dest.get<std::string>());
                }
                const std::size_t count = served.size();
                {
                    const std::lock_guard<std::mutex> lock(linkMutex_);
                    served_ = std::move(served);
                }
                bazarish::log::info("the server serves {} destination(s)", count);
                dropUnrouted();
            }
        } catch (const std::exception& error) {
            if (running_.load() && lastFailure != error.what()) {
                lastFailure = error.what();
                bazarish::log::warn("the server link: {}", lastFailure);
            }
        }
        {
            const std::lock_guard<std::mutex> lock(linkMutex_);
            served_.clear();
            watch_.reset();
        }
        dropUnrouted();
        std::unique_lock<std::mutex> lock(linkMutex_);
        linkChanged_.wait_for(lock, kDialRetryDelay, [this]() { return !running_.load(); });
    }
}

}  // namespace bazarish::gateway
