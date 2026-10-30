// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "EventGate.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <Health.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Pass.hpp>
#include <bazarish/Tunnel.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
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

using bazarish::nowSeconds;

bazarish::http::Response errorResponse(
    const int status, const ErrorCode code, const std::string& message)
{
    return {status, "application/json", {}, bazarish::makeErrorEnvelope(code, message).dump()};
}

bazarish::http::Response jsonResponse(const nlohmann::json& body)
{
    return {200, "application/json", {}, body.dump()};
}

nlohmann::json pendingJson(bazarish::server::Storage& storage, const std::string& user,
    const std::string& clientId)
{
    nlohmann::json items = nlohmann::json::array();
    for (const bazarish::server::Storage::PendingEntry& entry :
        storage.listPending(user, clientId)) {
        items.push_back(
            {{"id", entry.blobId}, {"class", entry.deliveryClass}, {"bytes", entry.bytes}});
    }
    return items;
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

HttpApi::HttpApi(Storage& storage, const HttpApiOptions options)
    : storage_(storage)
    , options_(options)
    , tunnel_(options_.sealingKey)
    , startedAt_(nowSeconds())
{
    janitorThread_ = std::thread([this]() { expiredSweepLoop(); });
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
    if (!options_.reseedSample) {
        return {};
    }
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
            storage_.purgeExpired(nowSeconds() - kMaxDelegationDays * kSecondsPerDay);
        } catch (const std::exception& error) {
            bazarish::log::warn("expiry sweep failed: {}", error.what());
        }
    }
}

void HttpApi::wakeUser(const std::string& user)
{
    if (options_.eventGate != nullptr && !user.empty()) {
        options_.eventGate->notify(user);
    }
}

void HttpApi::setupOpsRoutes()
{
    Storage& store = storage_;
    const auto operatorOnly = [this](auto handler) {
        return [this, handler](
                   const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused
                = bazarish::http::operatorRefusal(request, nowSeconds(),
                    options_.operatorFingerprints, replayCache_);
                refused.has_value()) {
                return *refused;
            }
            try {
                return handler(request);
            } catch (const nlohmann::json::exception& error) {
                return errorResponse(400, ErrorCode::eRequestFailed, error.what());
            } catch (const std::invalid_argument& error) {
                return errorResponse(400, ErrorCode::eRequestFailed, error.what());
            }
        };
    };

    ops_->get("/healthz", operatorOnly([this](const bazarish::http::Request&) {
        return bazarish::http::Response{200, "application/json", {},
            health::reportJson(
                "server-core", options_.version, startedAt_, nowSeconds(), std::string())};
    }));

    ops_->get("/v1/messaging/account",
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

    ops_->del("/v1/messaging/account",
        operatorOnly([this, &store](const bazarish::http::Request& request) {
            const std::string user = request.query("user");
            if (user.empty()) {
                return errorResponse(400, ErrorCode::eRequestFailed, "no user named");
            }
            store.forgetUser(user);
            if (options_.forgetI2pDest) {
                options_.forgetI2pDest(user);
            }
            bazarish::log::info("mailbox of {} dropped: the account was deleted",
                bazarish::log::redact(user));
            return jsonResponse({{"ok", true}});
        }));

    ops_->get("/v1/messaging/settings",
        operatorOnly([this](const bazarish::http::Request&) {
            if (!options_.settings) {
                return errorResponse(503, ErrorCode::eRequestFailed,
                    "this server was started without a config file to write to");
            }
            const ServerSettings::Values values = options_.settings->get();
            return jsonResponse({
                {"logLevel", values.logLevel},
                {"i2pLog", values.i2pLog},
                {"i2pPrivacy", values.i2pPrivacy},
                {"i2pTunnelQuantity", values.i2pTunnelQuantity},
                {"i2pTunnelQuantityMax", bazarish::i2p::kMaxTunnelQuantity},
                {"listen", {{"host", values.listenHost}, {"port", values.listenPort}}},
                {"serviceNode", values.serviceNodeUrl},
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

    ops_->put("/v1/messaging/settings",
        operatorOnly([this](const bazarish::http::Request& request) {
            if (!options_.settings) {
                return errorResponse(503, ErrorCode::eRequestFailed,
                    "this server was started without a config file to write to");
            }
            ServerSettings::Values values = options_.settings->get();
            {
                const nlohmann::json body = nlohmann::json::parse(request.body);
                if (body.contains("logLevel")) {
                    const std::string level = body.at("logLevel").get<std::string>();
                    if (!bazarish::log::levelFromString(level).has_value()) {
                        throw std::invalid_argument("not a log level: " + level);
                    }
                    values.logLevel = level;
                }
                if (body.contains("i2pLog")) {
                    values.i2pLog = body.at("i2pLog").get<bool>();
                }
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
                readEndpointInto(body, "listen", values.listenHost, values.listenPort);
                if (body.contains("serviceNode")) {
                    values.serviceNodeUrl = body.at("serviceNode").get<std::string>();
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
            if (values.logLevel != before.logLevel) {
                if (const std::optional<bazarish::log::Level> level
                    = bazarish::log::levelFromString(values.logLevel);
                    level.has_value()) {
                    bazarish::log::setLevel(*level);
                }
            }
            if (values.i2pLog != before.i2pLog) {
                bazarish::i2p::setI2pLogging(values.i2pLog);
            }
            if (values.gateways != before.gateways && options_.gatewaysChanged) {
                options_.gatewaysChanged(values.gateways);
            }
            return jsonResponse({{"logLevel", values.logLevel}, {"i2pLog", values.i2pLog}});
        }));

    ops_->post("/v1/messaging/restart",
        operatorOnly([this](const bazarish::http::Request&) {
            if (!options_.requestRestart) {
                return errorResponse(503, ErrorCode::eRequestFailed,
                    "this server cannot restart itself: it was started without a supervisor");
            }
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

    ops_->get("/v1/messaging/storage", operatorOnly([this](const bazarish::http::Request&) {
        if (!options_.diskUsage) {
            return errorResponse(
                503, ErrorCode::eRequestFailed, "this server cannot measure its storage");
        }
        return jsonResponse({{"usedBytes", options_.diskUsage()}});
    }));

    ops_->put("/v1/messaging/quota",
        operatorOnly([&store](const bazarish::http::Request& request) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            store.setUserQuota(body.at("user").get<std::string>(),
                body.at("quotaBytes").get<std::uint64_t>());
            return jsonResponse({{"ok", true}});
        }));

    ops_->put("/v1/messaging/i2p-dest",
        operatorOnly([this](const bazarish::http::Request& request) {
            if (!options_.provisionI2pDest || !options_.forgetI2pDest) {
                return errorResponse(
                    503, ErrorCode::eRequestFailed, "per-user destinations not available");
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
            const std::string transient = body.value("transient", std::string());
            if (transient.empty()) {
                options_.forgetI2pDest(user);
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

    ops_->post("/v1/messaging/node-card",
        operatorOnly([this](const bazarish::http::Request& request) {
            if (!options_.identity) {
                return errorResponse(503, ErrorCode::eRequestFailed, "no server identity here");
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const Key sealing
                = Key::fromPublicDer(fromBase64(body.at("sealingKey").get<std::string>()));
            const Bytes card = ServerCard::issue(
                *options_.identity, ServerCard::Service::eServiceNode, sealing, nowSeconds());
            bazarish::log::info("issued the service node its card");
            return jsonResponse({{"card", toBase64(card)}});
        }));
}

void HttpApi::setupRoutes()
{
    http_->get(std::string(bazarish::tunnel::kServerCardPath),
        [this](const bazarish::http::Request&) -> bazarish::http::Response {
            if (options_.serverCardDer.empty()) {
                return errorResponse(503, ErrorCode::eRequestFailed, "no card here");
            }
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
            std::string user;
            if (const std::optional<bazarish::http::Response> refused
                = tunnel_.authenticate(request, &user);
                refused.has_value()) {
                return *refused;
            }
            try {
                return handler(request, user);
            } catch (const nlohmann::json::exception& error) {
                return errorResponse(400, ErrorCode::eRequestFailed, error.what());
            } catch (const std::invalid_argument& error) {
                return errorResponse(400, ErrorCode::eRequestFailed, error.what());
            }
        };
    };

    Storage& store = storage_;

    const auto requireClient
        = [&store](const bazarish::http::Request& request, const std::string& user) -> std::string {
        const std::string clientId = request.header("X-Bazarish-Client");
        if (clientId.empty() || !store.isClientRegistered(user, clientId)) {
            return {};
        }
        return clientId;
    };
    const auto clientUnregistered = []() {
        return errorResponse(
            403, ErrorCode::eClientUnregistered, "client ID is not registered for this user");
    };

    if (options_.eventGate != nullptr) {
        EventGate* const gate = options_.eventGate;
        const int maxWait = options_.maxEventWaitSeconds;
        http_->getAsync("/v1/messaging/events",
            [this, &store, requireClient, clientUnregistered, gate, maxWait](
                const bazarish::http::Request& request,
                bazarish::http::Responder respond) -> std::optional<bazarish::http::Response> {
                std::string user;
                const std::optional<bazarish::http::Response> refused
                    = tunnel_.authenticate(request, &user);
                if (refused.has_value()) {
                    return *refused;
                }
                const std::string clientId = requireClient(request, user);
                if (clientId.empty()) {
                    return clientUnregistered();
                }
                const nlohmann::json waiting = pendingJson(store, user, clientId);
                if (!waiting.empty()) {
                    return jsonResponse({{"pending", waiting}});
                }
                int wait = maxWait;
                const std::string asked = request.query("wait");
                if (!asked.empty()) {
                    try {
                        wait = std::clamp(std::stoi(asked), 0, maxWait);
                    } catch (const std::exception& error) {
                        bazarish::log::debug("bad wait '{}': {}", asked, error.what());
                    }
                }
                gate->wait(http_->executor(), user, std::chrono::seconds(wait),
                    [&store, user, clientId, respond]() {
                        nlohmann::json items = nlohmann::json::array();
                        try {
                            items = pendingJson(store, user, clientId);
                        } catch (const std::exception& error) {
                            bazarish::log::warn("event face: {}", error.what());
                        }
                        respond(jsonResponse({{"pending", items}}));
                    });
                try {
                    if (!pendingJson(store, user, clientId).empty()) {
                        gate->notify(user);
                    }
                } catch (const std::exception& error) {
                    bazarish::log::warn("event face re-check: {}", error.what());
                }
                return std::nullopt;
            });
    }

    http_->post("/v1/messaging/clients",
        authenticated([&store](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            store.registerClient(user, body.at("clientId").get<std::string>());
            return jsonResponse({{"ok", true}});
        }));

    http_->get("/v1/messaging/clients",
        authenticated([&store](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const std::string caller = request.header("X-Bazarish-Client");
            nlohmann::json clients = nlohmann::json::array();
            for (const std::string& clientId : store.listClients(user)) {
                clients.push_back({{"clientId", clientId}, {"current", clientId == caller},
                    {"queue", store.listPending(user, clientId).size()}});
            }
            return jsonResponse({{"clients", clients}});
        }));

    http_->del(R"(/v1/messaging/clients/([a-z0-9_-]+))",
        authenticated([&store](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            store.unregisterClient(user, request.captures.at(0));
            return jsonResponse({{"ok", true}});
        }));

    http_->get("/v1/messaging/destination",
        authenticated([this](const bazarish::http::Request&, const std::string& user)
                          -> bazarish::http::Response {
            const DestinationAssignment assigned = options_.assignDestination
                ? options_.assignDestination(user)
                : DestinationAssignment{};
            return jsonResponse({{"dest", assigned.dest}, {"state", assigned.state}});
        }));

    http_->get("/v1/messaging/storage-usage",
        authenticated([this](const bazarish::http::Request&, const std::string& user)
                          -> bazarish::http::Response {
            return jsonResponse({
                    {"usedBytes", storage_.usage(user)},
                    {"quotaBytes", storage_.userQuota(user, options_.defaultQuotaBytes)},
                });
        }));

    http_->post("/v1/messaging/passes",
        authenticated([&store, requireClient, clientUnregistered](
                          const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (requireClient(request, user).empty()) {
                return clientUnregistered();
            }
            const std::vector<Bytes> handles
                = passHandles(nlohmann::json::parse(request.body));
            std::set<std::string> added;
            for (const Bytes& handle : handles) {
                if (!store.hasPass(user, handle)) {
                    added.insert(toHex(handle));
                }
            }
            if (store.passCount(user) + added.size() > kMaxPassesPerMailbox) {
                throw std::invalid_argument("this mailbox holds too many delivery passes");
            }
            store.registerPasses(user, handles);
            return jsonResponse({{"ok", true}, {"held", store.passCount(user)}});
        }));

    http_->post("/v1/messaging/passes/revoke",
        authenticated([&store, requireClient, clientUnregistered](
                          const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (requireClient(request, user).empty()) {
                return clientUnregistered();
            }
            const std::size_t dropped
                = store.revokePasses(user, passHandles(nlohmann::json::parse(request.body)));
            bazarish::log::info(
                "revoked {} delivery pass(es) for {}", dropped, bazarish::log::redact(user));
            return jsonResponse({{"revoked", dropped}});
        }));

    http_->get("/v1/messaging/pending",
        authenticated([&store, requireClient, clientUnregistered](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const std::string clientId = requireClient(request, user);
            if (clientId.empty()) {
                return clientUnregistered();
            }
            return jsonResponse({{"pending", pendingJson(store, user, clientId)}});
        }));

    http_->post("/v1/messaging/fetch",
        authenticated([&store, requireClient, clientUnregistered](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const std::string clientId = requireClient(request, user);
            if (clientId.empty()) {
                return clientUnregistered();
            }
            const nlohmann::json asked = nlohmann::json::parse(request.body).at("ids");
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
        authenticated([&store, requireClient, clientUnregistered](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const std::string clientId = requireClient(request, user);
            if (clientId.empty()) {
                return clientUnregistered();
            }
            const nlohmann::json ids = nlohmann::json::parse(request.body).at("ids");
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
        authenticated([this, requireClient, clientUnregistered](
                          const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const std::string caller = requireClient(request, user);
            if (caller.empty()) {
                return clientUnregistered();
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string deliveryId = body.at("deliveryId").get<std::string>();
            const Bytes payload = fromBase64(body.at("payload").get<std::string>());
            if (payload.size() > bazarish::kMaxMessagePayloadBytes) {
                return errorResponse(413, ErrorCode::eMessageTooLarge,
                    "a message may carry at most "
                        + std::to_string(bazarish::kMaxMessagePayloadBytes) + " bytes");
            }
            if (storage_.listClients(user).size() <= 1) {
                return jsonResponse({{"ok", true}, {"stored", false}});
            }
            if (storage_.hasSeen(user, deliveryId)) {
                return jsonResponse({{"ok", true}, {"stored", true}});
            }

            const Storage::PutResult result = storage_.putBlob(user, deliveryId, payload,
                kDeviceDeliveryClass, storage_.userQuota(user, options_.defaultQuotaBytes),
                nowSeconds(), caller);
            if (result == Storage::PutResult::eQuotaExceeded) {
                return errorResponse(507, ErrorCode::eStorageFull, "your storage is full");
            }
            if (result == Storage::PutResult::eStored) {
                wakeUser(user);
            }
            return jsonResponse({{"ok", true}, {"stored", true}});
        }));

}

}  // namespace bazarish::server
