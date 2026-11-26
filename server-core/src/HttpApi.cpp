// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include <ServiceRoutes.hpp>
#include <Health.hpp>
#include <OpsGate.hpp>
#include <OpsSettings.hpp>

#include "EventGate.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/HeldWait.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpResponses.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Pass.hpp>
#include <bazarish/Tunnel.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr const char* kReseedPath = "/internal/i2pseeds.su3";

using bazarish::Bytes;
using bazarish::ErrorCode;

constexpr std::size_t kReseedRouters = 60;
constexpr std::int64_t kReseedRefreshSeconds = 3600;
constexpr char kHoldKey[] = "hold";
constexpr char kHoldValue[] = "1";
constexpr char kDeferredKey[] = "deferred";
constexpr char kDevicesKey[] = "devices";
constexpr char kDeferredSeparator = ',';
constexpr char kOverviewPath[] = "/v1/messaging/overview";
constexpr char kSinceKey[] = "since";
constexpr char kVersionField[] = "version";

using bazarish::nowSeconds;

using bazarish::http::errorResponse;
using bazarish::http::jsonResponse;

nlohmann::json pendingJson(bazarish::server::DiskStorage& storage, const std::string& user,
    const std::string& clientId)
{
    nlohmann::json items = nlohmann::json::array();
    for (const bazarish::server::DiskStorage::PendingEntry& entry :
        storage.listPending(user, clientId)) {
        items.push_back(
            {{"id", entry.blobId}, {"class", entry.deliveryClass}, {"bytes", entry.bytes}});
    }
    return items;
}

// The ids a device names as held already: they alone do not end its wait.
std::set<std::string> deferredIds(const bazarish::http::Request& request)
{
    std::set<std::string> ids;
    const std::string listed = request.query(kDeferredKey);
    std::string::size_type begin = 0;
    while (begin < listed.size()) {
        const std::string::size_type end
            = std::min(listed.find(kDeferredSeparator, begin), listed.size());
        if (end > begin) {
            ids.insert(listed.substr(begin, end - begin));
        }
        if (ids.size() > bazarish::kMaxDeferredMailItems) {
            throw std::invalid_argument("a wait may name at most "
                + std::to_string(bazarish::kMaxDeferredMailItems) + " held items");
        }
        begin = end + 1;
    }
    return ids;
}

bool holdsNews(const nlohmann::json& pending, const std::set<std::string>& deferred)
{
    for (const nlohmann::json& entry : pending) {
        if (!deferred.contains(entry.at("id").get<std::string>())) {
            return true;
        }
    }
    return false;
}

std::vector<Bytes> passHandles(const nlohmann::json& body)
{
    const nlohmann::json& asked = body.at("passes");
    if (asked.size() > bazarish::kMaxPassesPerRequest) {
        throw std::invalid_argument("too many delivery passes in one request");
    }
    std::vector<Bytes> handles;
    handles.reserve(asked.size());
    for (const nlohmann::json& entry : asked) {
        Bytes handle = bazarish::fromBase64(entry.get<std::string>());
        if (handle.size() != bazarish::kDeliveryPassSize) {
            throw std::invalid_argument("delivery pass handle has wrong size");
        }
        handles.push_back(std::move(handle));
    }
    return handles;
}

}  // namespace

namespace bazarish::server {

HttpApi::HttpApi(DiskStorage& storage, EventGate& eventGate, const HttpApiOptions options)
    : storage_(storage)
    , eventGate_(eventGate)
    , overviewGate_(std::make_shared<EventGate>(EventGate::Missed::eDropped))
    , options_(options)
    , tunnel_(options_.sealingKey, options_.fingerprint)
    , startedAt_(nowSeconds())
{
    if (!options_.accountRevocation || !options_.accountCard) {
        throw std::invalid_argument("the mailbox serves only the accounts its server service knows");
    }
    storage_.watch(overviewChanged());
    storage_.watchDevices([this](const std::string& user) { eventGate_.wakeWaiting(user); });
    janitorThread_ = std::thread([this]() { expiredSweepLoop(); });
}

std::function<void(const std::string& user)> HttpApi::overviewChanged() const
{
    return [gate = overviewGate_](const std::string& user) { gate->notify(user); };
}

nlohmann::json HttpApi::eventsAnswer(const std::string& user, nlohmann::json pending)
{
    return {
        {"pending", std::move(pending)},
        {"usedBytes", storage_.usage(user)},
        {"quotaBytes", storage_.userQuota(user, options_.defaultQuotaBytes)},
        {"devicesVersion", storage_.devicesVersion(user)},
    };
}

nlohmann::json HttpApi::overviewOf(const std::string& user, const std::string& device)
{
    const DestinationAssignment assigned = options_.assignDestination(user);
    nlohmann::json clients = nlohmann::json::array();
    for (const std::string& registered : storage_.listClients(user)) {
        clients.push_back({{"device", registered}, {"current", registered == device},
            {"queue", storage_.listPending(user, registered).size()}});
    }
    nlohmann::json overview = {
        {"dest", assigned.dest},
        {"state", assigned.state},
        {"transientExpires", assigned.transientExpires},
        {"usedBytes", storage_.usage(user)},
        {"quotaBytes", storage_.userQuota(user, options_.defaultQuotaBytes)},
        {"clients", clients},
        {"devicesVersion", storage_.devicesVersion(user)},
    };
    const std::string shown = overview.dump();
    overview[kVersionField] = toHex(sha256(Bytes(shown.begin(), shown.end())));
    return overview;
}

std::optional<bazarish::http::Response> HttpApi::admitted(
    const bazarish::http::Request& request, Caller& caller)
{
    caller = tunnel_.authenticate(request);
    if (caller.refused.has_value()) {
        return caller.refused;
    }
    const std::optional<Revocation> revocation = options_.accountRevocation(caller.user);
    if (!revocation.has_value()) {
        return errorResponse(404, ErrorCode::eAccountUnknown, "this server serves no such account");
    }
    for (const std::string& revoked : revocation->revoked) {
        storage_.dropDevice(caller.user, revoked);
    }
    if (revocation->revokes(caller.device)) {
        return errorResponse(403, ErrorCode::eDeviceRevoked, "this device was revoked");
    }
    return std::nullopt;
}

HttpApi::~HttpApi()
{
    stop();
    if (janitorThread_.joinable()) {
        janitorThread_.join();
    }
}

int HttpApi::bind(const std::string& host, const int port)
{
    bazarish::http::Server::Options options;
    options.host = host;
    options.port = port;
    options.certificate = options_.tlsCertificate;
    options.key = options_.tlsKey;
    http_ = std::make_unique<bazarish::http::Server>(options);
    setupRoutes();
    try {
        return http_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

int HttpApi::bindOps(const std::string& host, const int port)
{
    bazarish::http::Server::Options options;
    options.host = host;
    options.port = port;
    options.threads = 1;
    options.certificate = options_.tlsCertificate;
    options.key = options_.tlsKey;
    if (options_.opsClientPins.empty()) {
        bazarish::log::error("the ops socket on {}:{} names no client pins (opsClients): refused", host, port);
        return 0;
    }
    options.clientPins = options_.opsClientPins;
    ops_ = std::make_unique<bazarish::http::Server>(options);
    setupOpsRoutes();
    try {
        return ops_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

void HttpApi::wait()
{
    stopGate_.wait();
}

void HttpApi::stop()
{
    stopGate_.stop();
    if (http_) {
        http_->stop();
    }
    if (ops_) {
        ops_->stop();
    }
}

std::string HttpApi::reseedArchive()
{
    const std::lock_guard<std::mutex> lock(reseedMutex_);
    const std::int64_t now = nowSeconds();
    if (!reseedSu3_.empty() && now - reseedPackedAt_ < kReseedRefreshSeconds) {
        return reseedSu3_;
    }
    const std::vector<Bytes> routers = options_.reseedSample(kReseedRouters);
    if (routers.empty()) {
        return reseedSu3_;
    }
    const Bytes su3 = bazarish::i2p::packReseedSu3(routers, "bazarish");
    reseedSu3_.assign(su3.begin(), su3.end());
    reseedPackedAt_ = now;
    bazarish::log::info("reseed archive packed: {} routers, {} bytes", routers.size(),
        reseedSu3_.size());
    return reseedSu3_;
}

void HttpApi::expiredSweepLoop()
{
    constexpr std::chrono::seconds kSweepInterval{3600};
    while (!stopGate_.waitFor(kSweepInterval)) {
        try {
            const std::int64_t now = nowSeconds();
            storage_.purgeExpired(now - kMaxDelegationDays * kSecondsPerDay,
                now - kMailRetentionDays * kSecondsPerDay);
        } catch (const std::exception& error) {
            bazarish::log::warn("expiry sweep failed: {}", error.what());
        }
    }
}

void HttpApi::wakeUser(const std::string& user)
{
    eventGate_.notify(user);
}

void HttpApi::setupOpsRoutes()
{
    DiskStorage& store = storage_;
    const auto operatorOnly = [this](bazarish::http::Handler handler) {
        return bazarish::server::operatorOnly(
            options_.operatorFingerprints, replayCache_, std::move(handler));
    };

    ops_->get("/healthz", operatorOnly([this](const bazarish::http::Request&) {
        return bazarish::http::Response{200, "application/json", {},
            health::reportJson(
                "server-core", options_.version, startedAt_, nowSeconds(), std::string())};
    }));

    ops_->get(routes::kMessagingAccount,
        operatorOnly([this, &store](const bazarish::http::Request& request) {
            const std::string user = request.query("user");
            if (user.empty()) {
                return errorResponse(400, ErrorCode::eRequestFailed, "no user named");
            }
            return jsonResponse({
                {"devices", store.listClients(user).size()},
                {"usedBytes", store.usage(user)},
                {"quotaBytes", store.userQuota(user, options_.defaultQuotaBytes)},
            });
        }));

    ops_->del(routes::kMessagingAccount,
        operatorOnly([this, &store](const bazarish::http::Request& request) {
            const std::string user = request.query("user");
            if (user.empty()) {
                return errorResponse(400, ErrorCode::eRequestFailed, "no user named");
            }
            store.forgetUser(user);
            options_.forgetI2pDest(user);
            wakeUser(user);
            bazarish::log::info("mailbox of {} dropped: the account was deleted",
                bazarish::log::redact(user));
            return jsonResponse({{"ok", true}});
        }));

    ops_->get(routes::kMessagingSettings,
        operatorOnly([this](const bazarish::http::Request&) {
            const ServerSettings::Values values = options_.settings->get();
            return jsonResponse({
                {"logLevel", values.logLevel},
                {"i2pLogLevel", values.i2pLogLevel},
                {"i2pPrivacy", values.i2pPrivacy},
                {"listen", {{"host", values.listenHost}, {"port", values.listenPort}}},
                {"serverService", values.serverServiceUrl},
                {"gatewayListen", values.gatewayListenHost.empty()
                        ? nlohmann::json(nullptr)
                        : nlohmann::json{{"host", values.gatewayListenHost},
                            {"port", values.gatewayListenPort}}},
                {"gateways", values.gateways},
                {"stateDirectory", options_.stateDirectory},
                {"fingerprint", options_.fingerprint},
                {"version", options_.version},
            });
        }));

    ops_->put(routes::kMessagingSettings,
        operatorOnly([this](const bazarish::http::Request& request) {
            ServerSettings::Values values = options_.settings->get();
            {
                const nlohmann::json body = bazarish::parseJson(request.body);
                values.logLevel = logLevelIn(body, values.logLevel);
                values.i2pLogLevel = i2pLogLevelIn(body, values.i2pLogLevel);
                values.i2pPrivacy = privacyIn(body, values.i2pPrivacy);
                readEndpointInto(body, "listen", values.listenHost, values.listenPort);
                if (body.contains("serverService")) {
                    values.serverServiceUrl = body.at("serverService").get<std::string>();
                    if (!bazarish::http::parseUrl(values.serverServiceUrl).tls) {
                        return errorResponse(400, ErrorCode::eRequestFailed,
                            "the server service is reached at an https:// URL");
                    }
                }
                readEndpointInto(
                    body, "gatewayListen", values.gatewayListenHost, values.gatewayListenPort);
                if (body.contains("gateways")) {
                    values.gateways = body.at("gateways").get<std::vector<std::string>>();
                }
            }

            const ServerSettings::Values before = options_.settings->get();
            try {
                options_.settings->set(values);
            } catch (const std::exception& error) {
                return errorResponse(500, ErrorCode::eRequestFailed, error.what());
            }
            applyLogLevel(before.logLevel, values.logLevel);
            applyI2pLogLevel(before.i2pLogLevel, values.i2pLogLevel);
            if (values.gateways != before.gateways) {
                options_.gatewaysChanged(values.gateways);
            }
            return jsonResponse({{"ok", true}});
        }));

    logFeed_ = std::make_unique<LogFeed>(*ops_, routes::kMessagingLogs, options_.logRing,
        operatorCheck(options_.operatorFingerprints, replayCache_));

    ops_->post(routes::kMessagingRestart,
        operatorOnly([this](const bazarish::http::Request&) {
            bazarish::log::info("restarting at the operator's request");
            options_.requestRestart();
            return jsonResponse({{"restarting", true}});
        }));

    ops_->get(std::string(kReseedPath),
        operatorOnly([this](const bazarish::http::Request&) -> bazarish::http::Response {
            const std::string archive = reseedArchive();
            if (archive.empty()) {
                return errorResponse(503, ErrorCode::eRequestFailed, "no reseed available");
            }
            return bazarish::http::Response{200, "application/octet-stream", {}, archive};
        }));

    ops_->get(routes::kMessagingStorage, operatorOnly([this](const bazarish::http::Request&) {
        return jsonResponse({{"usedBytes", options_.diskUsage()}});
    }));

    ops_->put(routes::kMessagingCard, operatorOnly([this](const bazarish::http::Request& request) {
        options_.forgetCard(bazarish::parseJson(request.body).at("user").get<std::string>());
        return jsonResponse({{"ok", true}});
    }));

    ops_->put(routes::kMessagingQuota,
        operatorOnly([&store](const bazarish::http::Request& request) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            store.setUserQuota(body.at("user").get<std::string>(),
                body.at("quotaBytes").get<std::uint64_t>());
            return jsonResponse({{"ok", true}});
        }));

    ops_->put(routes::kMessagingI2pDest,
        operatorOnly([this](const bazarish::http::Request& request) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const std::string user = body.at("user").get<std::string>();
            const std::string transient = body.value("transient", std::string());
            if (transient.empty()) {
                options_.forgetI2pDest(user);
                // Its held mail wait answers now: the next ask is refused, and the owner learns why.
                wakeUser(user);
                return jsonResponse({{"dest", ""}});
            }
            const std::string sealingKey = body.value("sealingKey", std::string());
            const std::string signingKey = body.value("signingKey", std::string());
            if (sealingKey.empty() || signingKey.empty()) {
                return errorResponse(400, ErrorCode::eRequestFailed,
                    "a delegation comes with the serving and signing keys of its address");
            }
            const DestinationAssignment served = options_.provisionI2pDest(user, transient,
                body.at("expiresUnix").get<std::int64_t>(), sealingKey, signingKey);
            return jsonResponse({{"dest", served.dest}});
        }));

    ops_->post(routes::kMessagingNodeCard,
        operatorOnly([this](const bazarish::http::Request& request) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const Key sealing
                = Key::fromPublicDer(fromBase64(body.at("sealingKey").get<std::string>()));
            const Bytes card = ServerCard::issue(
                *options_.identity, ServerCard::Service::eServerService, sealing);
            bazarish::log::info("issued the server service its card");
            return jsonResponse({{"card", toBase64(card)}});
        }));
}

void HttpApi::setupRoutes()
{
    http_->get(std::string(bazarish::tunnel::kServerCardPath),
        [this](const bazarish::http::Request&) -> bazarish::http::Response {
            bazarish::http::Response response;
            response.contentType = "application/octet-stream";
            response.body = std::string(
                options_.serverCardDer.begin(), options_.serverCardDer.end());
            return response;
        });

    http_->routeAsync("POST", std::string(bazarish::tunnel::kTunnelPath),
        [this](const bazarish::http::Request& request,
            bazarish::http::Responder respond) -> std::optional<bazarish::http::Response> {
            tunnel_.serve(request, *http_, std::move(respond));
            return std::nullopt;
        });

    const auto authenticated = [this](auto handler) {
        return [this, handler](
                   const bazarish::http::Request& request) -> bazarish::http::Response {
            Caller caller;
            if (const std::optional<bazarish::http::Response> refused = admitted(request, caller);
                refused.has_value()) {
                return *refused;
            }
            try {
                return handler(request, caller);
            } catch (const nlohmann::json::exception& error) {
                return errorResponse(400, ErrorCode::eRequestFailed, error.what());
            } catch (const std::invalid_argument& error) {
                return errorResponse(400, ErrorCode::eRequestFailed, error.what());
            }
        };
    };

    DiskStorage& store = storage_;

    const auto registered = [&store](const Caller& caller) {
        return store.isClientRegistered(caller.user, caller.device);
    };
    const auto clientUnregistered = []() {
        return errorResponse(
            403, ErrorCode::eClientUnregistered, "client ID is not registered for this user");
    };

    http_->getAsync("/v1/messaging/events",
        [this, &store, registered, clientUnregistered](
            const bazarish::http::Request& request,
            bazarish::http::Responder respond) -> std::optional<bazarish::http::Response> {
            Caller caller;
            const std::optional<bazarish::http::Response> refused = admitted(request, caller);
            if (refused.has_value()) {
                return *refused;
            }
            if (!registered(caller)) {
                return clientUnregistered();
            }
            const std::string user = caller.user;
            const std::string clientId = caller.device;
            std::set<std::string> deferred;
            try {
                deferred = deferredIds(request);
            } catch (const std::invalid_argument& error) {
                return errorResponse(400, ErrorCode::eRequestFailed, error.what());
            }
            store.noteAsked(user, clientId, nowSeconds());
            const std::string knownDevices = request.query(kDevicesKey);
            const bool listMoved = !knownDevices.empty()
                && knownDevices != std::to_string(store.devicesVersion(user));
            const nlohmann::json waiting = pendingJson(store, user, clientId);
            if (listMoved || holdsNews(waiting, deferred) || request.query(kHoldKey) != kHoldValue) {
                return jsonResponse(eventsAnswer(user, waiting));
            }
            const std::optional<std::chrono::seconds> hold
                = heldWaitOf(request.query(kHeldWaitKey));
            if (!hold.has_value()) {
                return errorResponse(400, ErrorCode::eRequestFailed, heldWaitRefusal());
            }
            eventGate_.wait(http_->executor(), user, clientId, *hold,
                [this, &store, user, clientId, respond]() {
                    try {
                        respond(jsonResponse(
                            eventsAnswer(user, pendingJson(store, user, clientId))));
                    } catch (const std::exception& error) {
                        bazarish::log::warn("event face: {}", error.what());
                        respond(errorResponse(500, ErrorCode::eRequestFailed, error.what()));
                    }
                });
            try {
                if (holdsNews(pendingJson(store, user, clientId), deferred)
                    || (!knownDevices.empty()
                        && knownDevices != std::to_string(store.devicesVersion(user)))) {
                    eventGate_.notify(user);
                }
            } catch (const std::exception& error) {
                bazarish::log::warn("event face re-check: {}", error.what());
            }
            return std::nullopt;
        });

    http_->post("/v1/messaging/clients",
        authenticated([&store](const bazarish::http::Request& request,
                          const Caller& caller) -> bazarish::http::Response {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const std::string install = body.at("install").get<std::string>();
            const Bytes sealing = fromBase64(body.at("sealing").get<std::string>());
            if (!DeviceCertificate::verify(caller.certDer).sealsWith(sealing)) {
                return errorResponse(400, ErrorCode::eRequestFailed,
                    "the sealing key is not the one this device's certificate names");
            }
            if (store.registerClient(caller.user, caller.device, install, caller.certDer, sealing,
                    nowSeconds())
                == DiskStorage::RegisterResult::eTaken) {
                return errorResponse(409, ErrorCode::eDeviceTaken,
                    "this device is registered from another copy of its keys");
            }
            return jsonResponse({{"ok", true}});
        }));

    http_->get("/v1/messaging/devices",
        authenticated([this, &store, registered, clientUnregistered](const bazarish::http::Request&,
                          const Caller& caller) -> bazarish::http::Response {
            if (!registered(caller)) {
                return clientUnregistered();
            }
            const DiskStorage::DeviceList list = store.deviceList(caller.user);
            const std::optional<Bytes> card = options_.accountCard(caller.user);
            nlohmann::json devices = nlohmann::json::array();
            for (const DiskStorage::DeviceEntry& entry : list.devices) {
                devices.push_back({{"cert", toBase64(entry.certDer)},
                    {"sealing", toBase64(entry.sealingDer)}, {"registered", entry.registered},
                    {"departure", toBase64(entry.departure)}});
            }
            return jsonResponse({{"version", list.version}, {"devices", devices},
                {"card", card.has_value() ? toBase64(*card) : std::string()}});
        }));

    http_->del("/v1/messaging/clients/{id}",
        authenticated([&store](const bazarish::http::Request& request,
                          const Caller& caller) -> bazarish::http::Response {
            if (caller.role != DeviceRole::ePrimary) {
                return errorResponse(403, ErrorCode::eDeviceNotPrimary,
                    "only a primary device clears another device's queue");
            }
            const std::string& device = request.captures.at(0);
            if (device == caller.device) {
                return errorResponse(400, ErrorCode::eRequestFailed,
                    "a device does not clear its own queue");
            }
            store.unregisterClient(caller.user, device);
            return jsonResponse({{"ok", true}});
        }));

    http_->post("/v1/messaging/departure",
        authenticated([&store](const bazarish::http::Request& request,
                          const Caller& caller) -> bazarish::http::Response {
            const Bytes departure
                = fromBase64(bazarish::parseJson(request.body).at("departure").get<std::string>());
            try {
                DeviceDeparture::verify(departure, DeviceCertificate::verify(caller.certDer));
            } catch (const std::exception& error) {
                return errorResponse(400, ErrorCode::eRequestFailed, error.what());
            }
            store.departClient(caller.user, caller.device, departure);
            return jsonResponse({{"ok", true}});
        }));

    http_->get("/v1/messaging/destination",
        authenticated([this](const bazarish::http::Request&, const Caller& caller)
                          -> bazarish::http::Response {
            const std::string& user = caller.user;
            const DestinationAssignment assigned = options_.assignDestination(user);
            return jsonResponse({{"dest", assigned.dest}});
        }));

    http_->getAsync(kOverviewPath,
        [this](const bazarish::http::Request& request,
            bazarish::http::Responder respond) -> std::optional<bazarish::http::Response> {
            Caller caller;
            const std::optional<bazarish::http::Response> refused = admitted(request, caller);
            if (refused.has_value()) {
                return *refused;
            }
            const std::string user = caller.user;
            const std::string device = caller.device;
            const std::string since = request.query(kSinceKey);
            const nlohmann::json current = overviewOf(user, device);
            if (request.query(kHoldKey) != kHoldValue
                || since != current.at(kVersionField).get<std::string>()) {
                overviewGate_->release(user, device);
                return jsonResponse(current);
            }
            const std::optional<std::chrono::seconds> hold
                = heldWaitOf(request.query(kHeldWaitKey));
            if (!hold.has_value()) {
                return errorResponse(400, ErrorCode::eRequestFailed, heldWaitRefusal());
            }
            overviewGate_->wait(
                http_->executor(), user, device, *hold, [this, user, device, respond]() {
                    try {
                        respond(jsonResponse(overviewOf(user, device)));
                    } catch (const std::exception& error) {
                        bazarish::log::warn("overview face: {}", error.what());
                        respond(errorResponse(500, ErrorCode::eRequestFailed, error.what()));
                    }
                });
            if (overviewOf(user, device).at(kVersionField).get<std::string>() != since) {
                overviewGate_->notify(user);
            }
            return std::nullopt;
        });

    http_->post("/v1/messaging/passes",
        authenticated([&store, registered, clientUnregistered](
                          const bazarish::http::Request& request,
                          const Caller& caller) -> bazarish::http::Response {
            if (!registered(caller)) {
                return clientUnregistered();
            }
            const std::string& user = caller.user;
            const std::vector<Bytes> handles
                = passHandles(bazarish::parseJson(request.body));
            if (!store.registerPasses(user, handles, kMaxPassesPerMailbox)) {
                throw std::invalid_argument("this mailbox holds too many delivery passes");
            }
            return jsonResponse({{"ok", true}});
        }));

    http_->post("/v1/messaging/passes/revoke",
        authenticated([&store, registered, clientUnregistered](
                          const bazarish::http::Request& request,
                          const Caller& caller) -> bazarish::http::Response {
            if (!registered(caller)) {
                return clientUnregistered();
            }
            const std::string& user = caller.user;
            const std::size_t dropped
                = store.revokePasses(user, passHandles(bazarish::parseJson(request.body)));
            bazarish::log::info(
                "revoked {} delivery pass(es) for {}", dropped, bazarish::log::redact(user));
            return jsonResponse({{"ok", true}});
        }));

    http_->get("/v1/messaging/pending",
        authenticated([&store, registered, clientUnregistered](const bazarish::http::Request&,
                          const Caller& caller) -> bazarish::http::Response {
            if (!registered(caller)) {
                return clientUnregistered();
            }
            const std::string& user = caller.user;
            const std::string& clientId = caller.device;
            store.noteAsked(user, clientId, nowSeconds());
            return jsonResponse({{"pending", pendingJson(store, user, clientId)}});
        }));

    http_->post("/v1/messaging/fetch",
        authenticated([&store, registered, clientUnregistered](
                          const bazarish::http::Request& request,
                          const Caller& caller) -> bazarish::http::Response {
            if (!registered(caller)) {
                return clientUnregistered();
            }
            const std::string& user = caller.user;
            const std::string& clientId = caller.device;
            const nlohmann::json asked = bazarish::parseJson(request.body).at("ids");
            if (!asked.is_array() || asked.empty()) {
                throw std::invalid_argument("a fetch names the items it takes");
            }
            nlohmann::json items = nlohmann::json::array();
            std::size_t carried = 0;
            for (const nlohmann::json& id : asked) {
                const std::string blobId = id.get<std::string>();
                if (!store.isPendingFor(user, blobId, clientId)) {
                    continue;
                }
                const Bytes data = store.getBlob(user, blobId);
                carried += data.size();
                if (carried > bazarish::kMaxFetchBytes) {
                    throw std::invalid_argument("the items named exceed one fetch");
                }
                items.push_back({{"id", blobId}, {"blob", nlohmann::json::binary(data)}});
            }
            const std::vector<std::uint8_t> answer = nlohmann::json::to_cbor({{"items", items}});
            return {200, "application/cbor", {}, std::string(answer.begin(), answer.end())};
        }));

    http_->post("/v1/messaging/ack",
        authenticated([&store, registered, clientUnregistered](
                          const bazarish::http::Request& request,
                          const Caller& caller) -> bazarish::http::Response {
            if (!registered(caller)) {
                return clientUnregistered();
            }
            const std::string& user = caller.user;
            const std::string& clientId = caller.device;
            const nlohmann::json ids = bazarish::parseJson(request.body).at("ids");
            if (!ids.is_array() || ids.size() > bazarish::kMaxAckIdsPerRequest) {
                throw std::invalid_argument("an ack names at most "
                    + std::to_string(bazarish::kMaxAckIdsPerRequest) + " items");
            }
            for (const nlohmann::json& id : ids) {
                store.ackBlob(user, id.get<std::string>(), clientId);
            }
            return jsonResponse({{"ok", true}});
        }));

    http_->post("/v1/messaging/self",
        authenticated([this, registered, clientUnregistered](
                          const bazarish::http::Request& request,
                          const Caller& caller) -> bazarish::http::Response {
            if (!registered(caller)) {
                return clientUnregistered();
            }
            const std::string& user = caller.user;
            const nlohmann::json body = bazarish::parseJson(request.body);
            const std::string deliveryId = body.at("deliveryId").get<std::string>();
            const std::string to = body.value("to", std::string());
            if (!to.empty() && (to == caller.device || !storage_.isClientRegistered(user, to))) {
                return errorResponse(404, ErrorCode::eClientUnregistered,
                    "a letter to self names another registered device of the account");
            }
            const Bytes payload = fromBase64(body.at("payload").get<std::string>());
            if (payload.size() > bazarish::kMaxMessagePayloadBytes) {
                return errorResponse(413, ErrorCode::eMessageTooLarge,
                    "a message may carry at most "
                        + std::to_string(bazarish::kMaxMessagePayloadBytes) + " bytes");
            }
            if (storage_.hasSeen(user, deliveryId)) {
                return jsonResponse({{"ok", true}});
            }

            const std::uint64_t quota = storage_.userQuota(user, options_.defaultQuotaBytes);
            const DiskStorage::PutResult result = to.empty()
                ? storage_.putSelfBlob(user, deliveryId, payload, quota, nowSeconds(), caller.device)
                : storage_.putAddressedBlob(
                    user, deliveryId, payload, kDeviceDeliveryClass, quota, nowSeconds(), to);
            if (result == DiskStorage::PutResult::eQuotaExceeded) {
                return errorResponse(507, ErrorCode::eStorageFull, "your storage is full");
            }
            if (result == DiskStorage::PutResult::eStored) {
                wakeUser(user);
            }
            return jsonResponse({{"ok", true}});
        }));

}

}  // namespace bazarish::server
