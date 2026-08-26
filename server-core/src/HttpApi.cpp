// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "EventGate.hpp"

#include <bazarish/Cms.hpp>

#include <bazarish/Log.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Health.hpp>
#include <bazarish/I2pAddress.hpp>

#include <bazarish/HttpServer.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <deque>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using bazarish::Bytes;
using bazarish::ErrorCode;

// How many RouterInfos a private reseed hands out when the client asks for no
// particular number, and the most it will ever hand out. Large enough that a
// fresh router has a real slice of the netDb to start from, bounded so one
// caller cannot pull the whole thing.
constexpr std::size_t kReseedRoutersDefault = 75;
constexpr std::size_t kReseedRoutersMax = 200;

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}


Bytes bodyBytes(const bazarish::http::Request& request)
{
    return Bytes(request.body.begin(), request.body.end());
}

bazarish::http::Response errorResponse(
    const int status, const ErrorCode code, const std::string& message)
{
    return {status, "application/json", {}, bazarish::makeErrorEnvelope(code, message).dump()};
}

bazarish::http::Response jsonResponse(const nlohmann::json& body)
{
    return {200, "application/json", {}, body.dump()};
}

bazarish::auth::Headers collectAuthHeaders(const bazarish::http::Request& request)
{
    bazarish::auth::Headers headers;
    // Both schemes: the signature headers a request may present, and the session
    // headers it may present instead. Collecting only the first set made every
    // session-authenticated request look unsigned.
    for (const char* const name : {bazarish::auth::kHeaderKeys,
             bazarish::auth::kHeaderTimestamp, bazarish::auth::kHeaderSignatureClassical,
             bazarish::auth::kHeaderSignaturePq, bazarish::auth::kHeaderSession,
             bazarish::auth::kHeaderSeq, bazarish::auth::kHeaderMac}) {
        if (request.hasHeader(name)) {
            headers[name] = request.header(name);
        }
    }
    return headers;
}

}  // namespace

namespace bazarish::server {

HttpApi::HttpApi(Storage& storage, DeliveryEngine& engine, const HttpApiOptions options,
    RemoteFetchFn remoteFetch)
    : storage_(storage)
    , engine_(engine)
    , options_(options)
    , remoteFetch_(std::move(remoteFetch))
    , startedAt_(nowSeconds())
{
    // Mailbox TTL backstop sweep (skipped entirely when retention is disabled).
    if (options_.mailboxRetentionSeconds > 0) {
        janitorThread_ = std::thread([this]() { mailboxJanitorLoop(); });
    }
}

HttpApi::~HttpApi()
{
    stopWorkers();
}

bool HttpApi::listen(const std::string& host, const int port)
{
    if (bindToAnyPort(host, port) <= 0) {
        return false;
    }
    return listenAfterBind();
}

int HttpApi::bindToAnyPort(const std::string& host)
{
    return bindToAnyPort(host, 0);
}

int HttpApi::bindToAnyPort(const std::string& host, const int port)
{
    bazarish::http::Server::Options options;
    options.host = host;
    options.port = port;
    http_ = std::make_unique<bazarish::http::Server>(options);
    setupRoutes();
    try {
        return http_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

bool HttpApi::listenAfterBind()
{
    // The engine serves on its own threads; this call is what keeps the caller's
    // thread (a main()) parked until stop().
    std::unique_lock<std::mutex> lock(stopMutex_);
    stopCv_.wait(lock, [this]() { return stopping_; });
    return true;
}

void HttpApi::stop()
{
    if (http_) {
        http_->stop();
    }
    stopWorkers();
}

void HttpApi::stopWorkers()
{
    {
        const std::lock_guard<std::mutex> lock(stopMutex_);
        if (stopping_) {
            return;
        }
        stopping_ = true;
    }
    stopCv_.notify_all();
    if (janitorThread_.joinable()) {
        janitorThread_.join();
    }
}

void HttpApi::mailboxJanitorLoop()
{
    // Hourly is ample for a day-scale TTL: a reclaimed blob is freed within an
    // hour of crossing the retention window.
    constexpr std::chrono::seconds kSweepInterval{3600};
    for (;;) {
        {
            std::unique_lock<std::mutex> lock(stopMutex_);
            // Sleep one interval, but return at once on shutdown (notify_all).
            if (stopCv_.wait_for(lock, kSweepInterval, [this]() { return stopping_; })) {
                return;
            }
        }  // release stopMutex_ before touching storage (it takes its own lock)
        try {
            storage_.purgeExpired(nowSeconds() - options_.mailboxRetentionSeconds);
            // Token hashes outlive mail by design (a contact may write years
            // later), but not forever.
            constexpr std::int64_t kSecondsPerDay = 24 * 3600;
            storage_.purgeTokensRegisteredBefore(
                bazarish::kTokenHashRetentionDays * kSecondsPerDay);
        } catch (const std::exception& error) {
            // Best-effort housekeeping; a sweep failure must never crash the node -
            // but a sweep that never succeeds fills the disk, so it is reported.
            bazarish::log::warn("mailbox sweep failed: {}", error.what());
        }
    }
}

void HttpApi::wakeUser(const std::string& user)
{
    if (eventGate_ != nullptr && !user.empty()) {
        eventGate_->notify(user);
    }
}

std::optional<bazarish::http::Response> HttpApi::authenticateRequest(
    const bazarish::http::Request& request, std::string* const outUser)
{
    const auth::Headers authHeaders = collectAuthHeaders(request);
    if (auth::hasSessionHeaders(authHeaders)) {
        // A session MAC. Every refusal here is typed eSessionInvalid, so a client
        // can tell "open a new session" from "your identity is wrong" and never
        // retries the second in a loop. The handle differs per request: what
        // arrives identifies the session only to the server holding its secret.
        const std::string handle = authHeaders.at(auth::kHeaderSession);
        const std::optional<SessionStore::Session> session
            = sessions_.findByHandle(handle, nowSeconds());
        if (!session.has_value()) {
            return errorResponse(401, ErrorCode::eSessionInvalid, "unknown or expired session");
        }
        try {
            const std::uint64_t seq = auth::verifyMac(authHeaders, session->key, nowSeconds(),
                request.method, request.path, bodyBytes(request));
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
            bodyBytes(request), replayCache_);
    } catch (const std::exception& error) {
        return errorResponse(401, ErrorCode::eDeliveryRejected, error.what());
    }
    return std::nullopt;
}

void HttpApi::setupRoutes()
{
    // Authorizes an operator-internal request by hybrid signature: the caller
    // must sign the request with an identity whose fingerprint is configured as an
    // operator (the service node for quota/transient pushes, the admin panel for
    // management and health). No shared secret. Responds 403 and returns false on
    // any failure.
    // Nothing when the caller is an authorised operator; otherwise the refusal to
    // send back, so a handler can return it unchanged.
    const auto operatorRejection
        = [this](const bazarish::http::Request& request) -> std::optional<bazarish::http::Response> {
        try {
            auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                request.path, bodyBytes(request), options_.operatorFingerprints);
            return std::nullopt;
        } catch (const std::exception& error) {
            return errorResponse(403, ErrorCode::eDeliveryRejected, error.what());
        }
    };

    // Authenticated liveness for the admin panel: service name, version, uptime
    // and resident memory. Operator-only (signed), so it leaks nothing to an
    // unauthenticated caller.
    http_->get("/healthz",
        [this, operatorRejection](const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            return {200, "application/json", {},
                health::reportJson("server-core", options_.version, startedAt_, nowSeconds(),
                    options_.statusExtras ? options_.statusExtras() : std::string())};
        });

    // Wraps a handler with request authentication and uniform error
    // mapping. The handler receives the verified caller fingerprint.
    const auto authenticated = [this](auto handler) {
        return [this, handler](const bazarish::http::Request& request) -> bazarish::http::Response {
            std::string user;
            if (const std::optional<bazarish::http::Response> refused
                = authenticateRequest(request, &user);
                refused.has_value()) {
                return *refused;
            }
            try {
                return handler(request, user);
            } catch (const nlohmann::json::exception& error) {
                return errorResponse(400, ErrorCode::eDeliveryRejected, error.what());
            } catch (const std::invalid_argument& error) {
                return errorResponse(400, ErrorCode::eDeliveryRejected, error.what());
            }
        };
    };

    // Left unused below; kept as the single place both schemes are decided.

    Storage& store = storage_;

    // Returns the registered client ID of the request or reports
    // CLIENT_UNREGISTERED. Registration itself is the only exception.
    const auto requireClient
        = [&store](const bazarish::http::Request& request, const std::string& user) -> std::string {
        const std::string clientId = request.header("X-Bazarish-Client");
        if (clientId.empty() || !store.isClientRegistered(user, clientId)) {
            return {};  // the caller answers CLIENT_UNREGISTERED
        }
        return clientId;
    };
    const auto clientUnregistered = []() {
        return errorResponse(
            403, ErrorCode::eClientUnregistered, "client ID is not registered for this user");
    };

    // The long-poll face, on the same engine: a request with nothing to report is
    // parked on the gate instead of answered empty, so a client learns about a
    // message when it arrives rather than on its next tick. Registered only when
    // there is a gate to park on.
    if (eventGate_ != nullptr) {
        EventGate* const gate = eventGate_;
        const int maxWait = options_.maxEventWaitSeconds;
        http_->getAsync("/v1/messaging/events",
            [this, &store, requireClient, clientUnregistered, gate, maxWait](
                const bazarish::http::Request& request,
                bazarish::http::Responder respond) -> std::optional<bazarish::http::Response> {
                // The same two schemes every other route accepts; this one is
                // registered outside the wrapper because it may answer later.
                std::string user;
                const std::optional<bazarish::http::Response> refused
                    = authenticateRequest(request, &user);
                if (refused.has_value()) {
                    return *refused;
                }
                // Same client identity as every other route: the header, not a
                // query parameter the caller has to remember to add.
                const std::string clientId = requireClient(request, user);
                if (clientId.empty()) {
                    return clientUnregistered();
                }
                const auto pending = [&store, user, clientId]() {
                    nlohmann::json items = nlohmann::json::array();
                    for (const Storage::PendingEntry& entry : store.listPending(user, clientId)) {
                        items.push_back({{"id", entry.blobId}, {"class", entry.deliveryClass}});
                    }
                    return items;
                };
                nlohmann::json items = pending();
                if (!items.empty()) {
                    return jsonResponse({{"pending", items}});
                }
                int wait = maxWait;
                const std::string asked = request.query("wait");
                if (!asked.empty()) {
                    try {
                        wait = std::min(std::stoi(asked), maxWait);
                    } catch (const std::exception& error) {
                        bazarish::log::debug("bad wait '{}': {}", asked, error.what());
                    }
                }
                gate->wait(http_->executor(), user, std::chrono::seconds(wait),
                    [&store, user, clientId, respond]() {
                        nlohmann::json items = nlohmann::json::array();
                        try {
                            for (const Storage::PendingEntry& entry :
                                store.listPending(user, clientId)) {
                                items.push_back(
                                    {{"id", entry.blobId}, {"class", entry.deliveryClass}});
                            }
                        } catch (const std::exception& error) {
                            bazarish::log::warn("event face: {}", error.what());
                        }
                        respond(jsonResponse({{"pending", items}}));
                    });
                return std::nullopt;  // answered from the gate
            });
    }

    // A client opens a session with one hybrid signature and authenticates every
    // later request with a MAC: ~150 bytes instead of ~8.3 KB, an HMAC instead of
    // an ML-DSA verification, and nothing the server could show a third party as
    // proof this user made this request.
    //
    // The secret is sealed to the serving sealing key of the caller's own
    // destination - this server holds its private half, so no key has to be
    // distributed for this, and the facade in between sees a sealed blob.
    http_->post("/v1/auth/session",
        authenticated([this](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (!options_.assignDestination) {
                return errorResponse(
                    503, ErrorCode::eDeliveryRejected, "sessions are not available here");
            }
            const DestinationAssignment assigned = options_.assignDestination(user);
            if (!assigned.servingKey) {
                // Nothing to seal to yet: the account has no destination, so it
                // keeps signing every request until it publishes one.
                return errorResponse(409, ErrorCode::eDeliveryRejected,
                    "no serving key yet: publish your destination first");
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const Bytes opened
                = cms::unseal(fromBase64(body.at("sealed").get<std::string>()), *assigned.servingKey);
            const nlohmann::json inner = nlohmann::json::parse(opened.begin(), opened.end());
            const Bytes secret = fromBase64(inner.at("secret").get<std::string>());
            const Key replyKey
                = Key::fromPublicDer(fromBase64(inner.at("replyKey").get<std::string>()));
            std::int64_t expiresUnix = 0;
            sessions_.open(user, secret, nowSeconds(), &expiresUnix);
            // Sealed to the one-time key that came inside the request, so the
            // facade carries an opaque blob in this direction too. The client is
            // told when the session lapses, so it renews ahead of time rather
            // than learning it from a refused request.
            const nlohmann::json answer = {{"expiresUnix", expiresUnix}};
            const std::string answerText = answer.dump();
            return jsonResponse({{"sealed",
                toBase64(cms::seal(Bytes(answerText.begin(), answerText.end()), replyKey))}});
        }));

    // --- Client registry ---

    http_->post("/v1/messaging/clients",
        authenticated([&store](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            store.registerClient(user, body.at("clientId").get<std::string>());
            return jsonResponse({{"ok", true}});
        }));

    // The user's own devices. A message is deleted only once every registered
    // device has acked it, so a device nobody uses any more holds mail for the
    // whole retention window: the list is what makes that visible, and the
    // delete below is what ends it.
    http_->get("/v1/messaging/clients",
        authenticated([&store](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const auto header = request.headers.find("x-bazarish-client");
            const std::string caller
                = header != request.headers.end() ? header->second : std::string();
            nlohmann::json clients = nlohmann::json::array();
            for (const std::string& clientId : store.listClients(user)) {
                // What this device still holds: the mail it has not acked. A
                // device that stopped fetching is the one whose queue grows,
                // which is what tells its owner which id to retire.
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

    // Private reseed: a random slice of this server's netDb, so a client's first
    // I2P start never reaches for a public reseed host - the most blocked and
    // most telling part of a bootstrap. Deliberately unauthenticated (the client
    // has nothing yet) and deliberately random per request: the server picks
    // which routers a client learns first, so a fixed set would be an eclipse
    // handle. Every RouterInfo carries its own signature, so this adds no trust.
    http_->get("/v1/messaging/reseed",
        [this](const bazarish::http::Request& request) -> bazarish::http::Response {
            if (!options_.reseedSample) {
                return errorResponse(503, ErrorCode::eI2pUnavailable, "no reseed available");
            }
            std::size_t count = kReseedRoutersDefault;
            if (!request.query("count").empty()) {
                count = std::min<std::size_t>(
                    std::strtoull(request.query("count").c_str(), nullptr, 10),
                    kReseedRoutersMax);
            }
            const std::vector<Bytes> routers = options_.reseedSample(count);
            if (routers.empty()) {
                return errorResponse(503, ErrorCode::eI2pUnavailable, "netdb is empty");
            }
            nlohmann::json list = nlohmann::json::array();
            for (const Bytes& router : routers) {
                list.push_back(toBase64(router));
            }
            return jsonResponse({{"routers", list}});
        });

    // The caller's assigned serving destination + the public serving sealing
    // key for it, so the client can fold both into its self-signed contact card
    // (see docs-main api/InviteAnonymity.md). Resolved from the authenticated
    // caller's fingerprint.
    http_->get("/v1/messaging/destination",
        authenticated([this](const bazarish::http::Request&, const std::string& user)
                          -> bazarish::http::Response {
            const DestinationAssignment assigned = options_.assignDestination
                ? options_.assignDestination(user)
                : DestinationAssignment{};
            return jsonResponse({
                    {"dest", assigned.dest},
                    {"servingKey", assigned.servingKey
                            ? toBase64(assigned.servingKey->publicDer())
                            : std::string()},
                    {"state", assigned.state},
                });
        }));

    // The authenticated caller's own mailbox storage: bytes currently held and the
    // effective quota (their override, else the server default). Lets a client show
    // "used / free / total" for its server-core mailbox in per-account settings.
    http_->get("/v1/messaging/storage-usage",
        authenticated([this](const bazarish::http::Request&, const std::string& user)
                          -> bazarish::http::Response {
            return jsonResponse({
                    {"usedBytes", storage_.usage(user)},
                    {"quotaBytes", storage_.userQuota(user, options_.defaultQuotaBytes)},
                });
        }));

    // --- Operator-internal: one account, as this server sees it ---
    //
    // What the operator panel cannot get anywhere else: the mailbox as it stands
    // (a quota is a promise, this is what is in it) and how many devices hold the
    // account - a message is kept until every registered device has acked it, so
    // a device nobody uses any more is mail nobody collects.
    http_->get("/v1/messaging/account",
        [this, &store, operatorRejection](
            const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            const std::string user = request.query("user");
            if (user.empty()) {
                return errorResponse(400, ErrorCode::eDeliveryRejected, "no user named");
            }
            return jsonResponse({
                {"devices", store.listClients(user).size()},
                {"usedBytes", store.usage(user)},
                {"quotaBytes", store.userQuota(user, options_.defaultQuotaBytes)},
            });
        });

    // --- Operator-internal: what the storage occupies ---
    //
    // The panel shows this next to the sum of the quotas: the two answer
    // different questions, and only this one is measured.
    http_->get("/v1/messaging/storage",
        [this, operatorRejection](
            const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            if (!options_.diskUsage) {
                return errorResponse(
                    503, ErrorCode::eDeliveryRejected, "this server cannot measure its storage");
            }
            return jsonResponse({{"usedBytes", options_.diskUsage()}});
        });

    // --- Operator-internal: per-user storage quota ---
    //
    // Set by the operator's service node over the private channel when a user's
    // storage plan changes. Authorised by an operator signature, not by user auth
    // (the user must not set their own quota).
    http_->put("/v1/messaging/quota",
        [&store, operatorRejection](
            const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            try {
                const nlohmann::json body = nlohmann::json::parse(request.body);
                store.setUserQuota(body.at("user").get<std::string>(),
                    body.at("quotaBytes").get<std::uint64_t>());
                return jsonResponse({{"ok", true}});
            } catch (const std::exception& error) {
                return errorResponse(400, ErrorCode::eDeliveryRejected, error.what());
            }
        });

    // Per-user I2P destination (operator-internal). Set by the operator's
    // service node when a paid user's i2pDest plan changes: it hands over the
    // client-owned offline transient so this server can operate the user's
    // personal destination. Same operator signature as quota. A request without a
    // transient revokes the destination.
    http_->put("/v1/messaging/i2p-dest",
        [this, operatorRejection](const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            if (!options_.provisionI2pDest || !options_.revokeI2pDest) {
                return errorResponse(503, ErrorCode::eDeliveryRejected,
                    "per-user destinations not available");
            }
            try {
                const nlohmann::json body = nlohmann::json::parse(request.body);
                const std::string user = body.at("user").get<std::string>();
                const std::string transient = body.value("transient", std::string());
                if (transient.empty()) {
                    options_.revokeI2pDest(user);
                } else {
                    options_.provisionI2pDest(user, transient,
                        body.at("expiresUnix").get<std::int64_t>());
                }
                return jsonResponse({{"ok", true}});
            } catch (const std::exception& error) {
                return errorResponse(400, ErrorCode::eDeliveryRejected, error.what());
            }
        });

    // Rotating a user's serving sealing key. Operator-signed, like the other
    // node-to-server pushes; two phases, because the key only comes into force
    // when the user has signed it into a contact card their contacts can read.
    http_->put("/v1/messaging/serving-key",
        [this, operatorRejection](const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            if (!options_.prepareServingKey || !options_.commitServingKey) {
                return errorResponse(503, ErrorCode::eDeliveryRejected,
                    "per-user destinations not available");
            }
            try {
                const nlohmann::json body = nlohmann::json::parse(request.body);
                const std::string user = body.at("user").get<std::string>();
                const std::string phase = body.at("phase").get<std::string>();
                if (phase == "prepare") {
                    return jsonResponse({{"servingKey", options_.prepareServingKey(user)}});
                }
                if (phase == "commit") {
                    if (!options_.commitServingKey(user)) {
                        return errorResponse(409, ErrorCode::eDeliveryRejected,
                            "no prepared serving key for this user");
                    }
                    return jsonResponse({{"ok", true}});
                }
                return errorResponse(400, ErrorCode::eDeliveryRejected, "unknown phase");
            } catch (const std::exception& error) {
                return errorResponse(400, ErrorCode::eDeliveryRejected, error.what());
            }
        });

    // --- Token hashes ---

    http_->post("/v1/messaging/tokens",
        authenticated([&store, requireClient, clientUnregistered](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (requireClient(request, user).empty()) {
                return clientUnregistered();
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            std::vector<Bytes> hashes;
            for (const nlohmann::json& entry : body.at("hashes")) {
                Bytes hash = fromBase64(entry.get<std::string>());
                if (hash.size() != kFingerprintBytes) {
                    throw std::invalid_argument("token hash has wrong size");
                }
                hashes.push_back(std::move(hash));
            }
            store.registerTokenHashes(user, hashes);
            return jsonResponse({{"ok", true}});
        }));

    http_->del("/v1/messaging/tokens",
        authenticated([&store, requireClient, clientUnregistered](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (requireClient(request, user).empty()) {
                return clientUnregistered();
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            std::vector<Bytes> hashes;
            for (const nlohmann::json& entry : body.at("hashes")) {
                hashes.push_back(fromBase64(entry.get<std::string>()));
            }
            store.deleteTokenHashes(user, hashes);
            return jsonResponse({{"ok", true}});
        }));

    // --- Pending content ---

    http_->get("/v1/messaging/pending",
        authenticated([&store, requireClient, clientUnregistered](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const std::string clientId = requireClient(request, user);
            if (clientId.empty()) {
                return clientUnregistered();
            }
            nlohmann::json pending = nlohmann::json::array();
            for (const Storage::PendingEntry& entry : store.listPending(user, clientId)) {
                pending.push_back({{"id", entry.blobId}, {"class", entry.deliveryClass}});
            }
            return jsonResponse({{"pending", pending}});
        }));

    http_->get(R"(/v1/messaging/pending/([a-z0-9_-]+))",
        authenticated([&store, requireClient, clientUnregistered](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (requireClient(request, user).empty()) {
                return clientUnregistered();
            }
            const std::string blobId = request.captures.at(0);
            if (!store.hasBlob(user, blobId)) {
                return errorResponse(404, ErrorCode::eDeliveryRejected, "no such blob");
            }
            const Bytes data = store.getBlob(user, blobId);
            return {200, "application/octet-stream", {}, std::string(data.begin(), data.end())};
        }));

    http_->post("/v1/messaging/ack",
        authenticated([&store, requireClient, clientUnregistered](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            const std::string clientId = requireClient(request, user);
            if (clientId.empty()) {
                return clientUnregistered();
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            store.ackBlob(user, body.at("blobId").get<std::string>(), clientId);
            return jsonResponse({{"ok", true}});
        }));

    // One device of an account writing to the account's own other devices. It is
    // the only write into a mailbox that needs no token and no destination: the
    // caller is the mailbox owner, proved by the signature on this very request,
    // so there is no stranger to gate and nothing to federate. That also keeps it
    // out of the tokenless contact budget, which exists to bound strangers.
    //
    // The payload stays sealed to the account's own sealing key; this server
    // stores ciphertext, exactly as it does for mail from anyone else.
    http_->post("/v1/messaging/self",
        authenticated([this, requireClient, clientUnregistered](
                          const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (requireClient(request, user).empty()) {
                return clientUnregistered();
            }
            const std::string caller = requireClient(request, user);
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string deliveryId = body.at("deliveryId").get<std::string>();
            const Bytes payload = fromBase64(body.at("payload").get<std::string>());
            if (payload.size() > bazarish::kMaxMessagePayloadBytes) {
                return errorResponse(413, ErrorCode::eMessageTooLarge,
                    "a message may carry at most "
                        + std::to_string(bazarish::kMaxMessagePayloadBytes) + " bytes");
            }
            // Nobody to tell: an account with one device is talking to itself,
            // and the disk should not carry that conversation.
            if (storage_.listClients(user).size() <= 1) {
                return jsonResponse({{"ok", true}, {"stored", false}});
            }
            // The writer is counted as having read it, so the blob is deleted as
            // soon as the account's other devices have.
            const Storage::PutResult result = storage_.putBlob(user, deliveryId, payload,
                kDeviceDeliveryClass, nowSeconds(),
                storage_.userQuota(user, options_.defaultQuotaBytes), caller);
            if (result == Storage::PutResult::eQuotaExceeded) {
                return errorResponse(507, ErrorCode::eStorageFull, "your storage is full");
            }
            // Wake whichever of the account's devices is holding a poll open.
            if (result == Storage::PutResult::eStored) {
                wakeUser(user);
            }
            return jsonResponse({{"ok", true}});
        }));

    // First-contact discovery proxy (fallback for a client without its own I2P transport):
    // relay a sealed fetch (op "card" to a serving server, "resolve" to the
    // central resolver) to toDest over I2P and return the sealed response. The
    // server moves opaque bytes - the client sealed the query and verifies the
    // response (see docs-main api/FederatedResolve.md).
    http_->post("/v1/messaging/fetch",
        authenticated([this](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            (void)user;
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string toDest = body.at("toDest").get<std::string>();
            validateB32I2pHost(toDest);
            const std::string op = body.at("op").get<std::string>();
            if (op != "card" && op != "resolve") {
                return errorResponse(400, ErrorCode::eDeliveryRejected, "unsupported fetch op");
            }
            const Bytes sealed = fromBase64(body.at("sealed").get<std::string>());
            if (!remoteFetch_) {
                return errorResponse(400, ErrorCode::eDeliveryRejected, "no federation transport");
            }
            const RemoteFetchResult result = remoteFetch_(toDest, op, sealed);
            if (!result.reachable) {
                return errorResponse(400, ErrorCode::eRecipientServerUnreachable,
                    "destination could not be reached");
            }
            nlohmann::json reply = {{"ok", result.ok}};
            if (result.ok) {
                reply["sealed"] = toBase64(result.sealed);
            } else if (!result.errorCode.empty()) {
                reply["errorCode"] = result.errorCode;
            }
            return jsonResponse(reply);
        }));
}

}  // namespace bazarish::server
