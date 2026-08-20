// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "EventGate.hpp"

#include <bazarish/Cms.hpp>

#include <bazarish/Log.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Health.hpp>
#include <bazarish/I2pAddress.hpp>

#include <bazarish/HttpServer.hpp>
#include <nlohmann/json.hpp>

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

// Backoff before the next transient delivery round. The first rounds retry with
// no pause to catch a tunnel that is about to finish building, then the wait
// grows so a longer outage is not hammered: rounds 0-2 immediate, rounds 3-5 one
// second, then +1s per round capped at five seconds.
std::chrono::seconds retryBackoff(int round)
{
    int seconds = 0;
    if (round >= 6) {
        seconds = std::min(5, round - 4);
    } else if (round >= 3) {
        seconds = 1;
    }
    return std::chrono::seconds(seconds);
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
    RemoteDeliverFn remoteDeliver, RemoteFetchFn remoteFetch)
    : storage_(storage)
    , engine_(engine)
    , options_(options)
    , remoteDeliver_(std::move(remoteDeliver))
    , remoteFetch_(std::move(remoteFetch))
    , startedAt_(nowSeconds())
{
    // Background delivery workers (store-and-forward). A small fixed pool: each
    // worker may sit in a per-message retry loop for a while, so size it for the
    // expected number of concurrently-in-flight slow deliveries.
    constexpr int kDeliveryWorkers = 8;
    deliveryWorkers_.reserve(kDeliveryWorkers);
    for (int i = 0; i < kDeliveryWorkers; ++i) {
        deliveryWorkers_.emplace_back([this]() { deliveryWorkerLoop(); });
    }
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
    std::unique_lock<std::mutex> lock(jobsMutex_);
    jobsCv_.wait(lock, [this]() { return stopping_; });
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
        const std::lock_guard<std::mutex> lock(jobsMutex_);
        if (stopping_) {
            return;
        }
        stopping_ = true;
    }
    jobsCv_.notify_all();
    for (std::thread& worker : deliveryWorkers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    deliveryWorkers_.clear();
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
            std::unique_lock<std::mutex> lock(jobsMutex_);
            // Sleep one interval, but return at once on shutdown (notify_all).
            if (jobsCv_.wait_for(lock, kSweepInterval, [this]() { return stopping_; })) {
                return;
            }
        }  // release jobsMutex_ before touching storage (it takes its own lock)
        try {
            storage_.purgeExpired(nowSeconds() - options_.mailboxRetentionSeconds);
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

void HttpApi::setAttempt(const std::string& attemptId, const Attempt& attempt)
{
    std::string settledFor;
    {
        const std::lock_guard<std::mutex> lock(attemptsMutex_);
        Attempt updated = attempt;
        // A delivered-ack may already have marked this attempt delivered; never let
        // a later job round downgrade it. Also keep the messageId so the index
        // prunes, and the sender, so the wake below knows whom to wake.
        const auto existing = attempts_.find(attemptId);
        if (existing != attempts_.end()) {
            if (existing->second.status == "delivered") {
                return;
            }
            if (updated.messageId.empty()) {
                updated.messageId = existing->second.messageId;
            }
            if (updated.user.empty()) {
                updated.user = existing->second.user;
            }
        }
        settledFor = updated.user;
        attempts_[attemptId] = updated;
    }
    // The sender has been waiting on this since it handed the message over; the
    // recipient's server answered synchronously, so the only thing left between
    // that answer and the tick on their screen is this wake.
    wakeUser(settledFor);
}

void HttpApi::setAttemptPhase(const std::string& attemptId, const std::string& phase)
{
    const std::lock_guard<std::mutex> lock(attemptsMutex_);
    const auto found = attempts_.find(attemptId);
    // Annotate only a still-pending attempt; never relabel or resurrect a terminal one.
    if (found != attempts_.end() && found->second.status == "pending") {
        found->second.phase = phase;
    }
}

void HttpApi::markDeliveredByMessageId(const std::string& messageId)
{
    if (messageId.empty()) {
        return;
    }
    std::unique_lock<std::mutex> lock(attemptsMutex_);
    const auto idx = messageIdToAttempt_.find(messageId);
    if (idx == messageIdToAttempt_.end()) {
        return;
    }
    const auto found = attempts_.find(idx->second);
    if (found == attempts_.end()) {
        return;
    }
    // Upgrade an in-flight (or given-up) attempt to delivered; never override a
    // terminal rejection ("failed").
    std::string settledFor;
    if (found->second.status == "pending" || found->second.status == "unconfirmed") {
        found->second.status = "delivered";
        found->second.completedAt = nowSeconds();
        settledFor = found->second.user;
    }
    lock.unlock();
    wakeUser(settledFor);
}

void HttpApi::deliveryWorkerLoop()
{
    for (;;) {
        DeliveryJob job;
        {
            std::unique_lock<std::mutex> lock(jobsMutex_);
            jobsCv_.wait(lock, [this]() { return stopping_ || !jobs_.empty(); });
            if (stopping_ && jobs_.empty()) {
                return;
            }
            job = std::move(jobs_.front());
            jobs_.pop_front();
        }
        runDeliveryJob(job);
    }
}

void HttpApi::runDeliveryJob(const DeliveryJob& job)
{
    // A foreign server may be momentarily unreachable while its I2P leaseset
    // publishes; that is transient, so retry for a bounded time. Any other
    // outcome (delivered, token rejected, too large, reachable-but-refused) is
    // terminal. The attempt stays "pending" between rounds so a polling client
    // keeps waiting instead of seeing a spurious failure.
    const int kMaxRounds = options_.deliveryMaxRounds > 0 ? options_.deliveryMaxRounds : 1;
    const std::string unreachableCode
        = std::string(toString(ErrorCode::eRecipientServerUnreachable));
    for (int round = 0; round < kMaxRounds; ++round) {
        {
            const std::lock_guard<std::mutex> lock(jobsMutex_);
            if (stopping_) {
                return;
            }
        }
        {
            // The recipient's signed delivered-ack may have already confirmed this
            // send (the authoritative path); if so, stop retrying the unreliable
            // synchronous reply.
            const std::lock_guard<std::mutex> lock(attemptsMutex_);
            const auto found = attempts_.find(job.attemptId);
            if (found != attempts_.end() && found->second.status == "delivered") {
                return;
            }
        }
        Attempt attempt;
        const std::int64_t now = nowSeconds();
        if (job.senderServingKey && !job.senderDest.empty() && job.toDest == job.senderDest) {
            const DeliveryEngine::Outcome outcome
                = engine_.deliver(job.sealed, job.payload, now, *job.senderServingKey);
            attempt.status = outcome.delivered ? "delivered" : "failed";
            attempt.errorCode = outcome.errorCode;
            attempt.errorMessage = outcome.errorMessage;
        } else {
            RemoteDeliveryResult remote;
            if (remoteDeliver_) {
                // Surface each federation phase onto the attempt so a polling client
                // sees real progress (dialing/connected/sending) while it is pending.
                remote = remoteDeliver_(job.senderDest, job.toDest, job.sealed, job.payload,
                    [this, &job](const std::string& phase) {
                        setAttemptPhase(job.attemptId, phase);
                    });
            }
            if (!remote.reachable) {
                attempt.status = "failed";
                attempt.errorCode = unreachableCode;
                attempt.errorMessage = "recipient server could not be reached";
            } else {
                attempt.status = remote.delivered ? "delivered" : "failed";
                attempt.errorCode = remote.errorCode;
                attempt.errorMessage = remote.errorMessage;
            }
        }
        const bool transient = attempt.status == "failed" && attempt.errorCode == unreachableCode;
        if (!transient) {
            attempt.completedAt = now;
            setAttempt(job.attemptId, attempt);
            return;
        }
        // Transient (the recipient's leaseset/tunnels were momentarily bad, or the
        // synchronous reply's return leg dropped on a flaky path - the message may
        // well already be stored, the dedup makes a re-delivery harmless): surface a
        // "retrying" phase so a polling client shows real progress, then wait with a
        // capped backoff before the next round (so the retry window spans minutes and
        // catches the path's recovery without the client needing a manual resend).
        setAttemptPhase(job.attemptId,
            "retry " + std::to_string(round + 1) + "/" + std::to_string(kMaxRounds));
        const auto backoff = retryBackoff(round);
        std::unique_lock<std::mutex> lock(jobsMutex_);
        if (jobsCv_.wait_for(lock, backoff, [this]() { return stopping_; })) {
            return;
        }
    }
    // Retries exhausted while the recipient stayed unreachable. This is NOT a
    // delivery failure: the envelope may well have been stored on the recipient
    // (its acknowledgement could have been lost on the return leg), so reporting
    // "failed" here would be a false negative. Mark it "unconfirmed" - the client
    // keeps the message grey ("at your server"); a read receipt later confirms it
    // (green). completedAt is set so the attempt prunes normally. A true failure
    // (token rejected, too large, refused) is terminal above and is the only path
    // to a red "failed".
    Attempt unconfirmed;
    unconfirmed.status = "unconfirmed";
    unconfirmed.completedAt = nowSeconds();
    setAttempt(job.attemptId, unconfirmed);
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
                health::reportJson("server-core", options_.version, startedAt_, nowSeconds())};
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
                clients.push_back(
                    {{"clientId", clientId}, {"current", clientId == caller}});
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
    // "used / free / total" for its server-core mailbox in per-profile settings.
    http_->get("/v1/messaging/storage-usage",
        authenticated([this](const bazarish::http::Request&, const std::string& user)
                          -> bazarish::http::Response {
            return jsonResponse({
                    {"usedBytes", storage_.usage(user)},
                    {"quotaBytes", storage_.userQuota(user, options_.defaultQuotaBytes)},
                });
        }));

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

    http_->post("/v1/messaging/send",
        authenticated([this, requireClient, clientUnregistered](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (requireClient(request, user).empty()) {
                return clientUnregistered();
            }
            if (request.body.size() > options_.perMessageLimitBytes) {
                return errorResponse(413, ErrorCode::eQuotaExceeded,
                    "envelope exceeds the per-message limit of "
                        + std::to_string(options_.perMessageLimitBytes) + " bytes");
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string toDest = body.at("toDest").get<std::string>();
            // Routing target must be a full .b32.i2p host (no raw destinations,
            // no addressbook names). Rejected as a 400 by the wrapper.
            validateB32I2pHost(toDest);
            const Bytes sealed = fromBase64(body.at("sealed").get<std::string>());
            const Bytes payload = fromBase64(body.at("payload").get<std::string>());
            // The delivery messageId (also sealed inside the envelope, where only
            // the recipient server can read it): the client passes it in the clear
            // so we can correlate the recipient's signed delivered-ack back to this
            // attempt. Optional for older clients (then there is no amber, only the
            // grey/green it already had).
            const std::string messageId = body.value("messageId", std::string());

            const std::int64_t now = nowSeconds();
            // Routed by destination. Local short-circuit ONLY when toDest is the
            // sender's own destination (same i2p destination): then the recipient
            // shares that destination, so a local store leaks no co-location. Any
            // other destination - including a recipient this server hosts on a
            // different destination - is federated, so delivery latency cannot
            // distinguish a local recipient from a remote one. Resolved here, on
            // the request thread, from the authenticated caller.
            const DestinationAssignment sender
                = options_.assignDestination ? options_.assignDestination(user) : DestinationAssignment{};

            // Accept the envelope into the outbound buffer and hand it to a
            // background worker (store-and-forward): this POST returns at once
            // (the "grey"/at-our-server state) and federation - with its own
            // retries for a recipient whose leaseset is still publishing - runs
            // off the request thread. The client polls the attempt for the
            // delivered/failed outcome instead of blocking this request on I2P.
            const std::string attemptId = toHex(randomBytes(16));
            {
                const std::lock_guard<std::mutex> lock(attemptsMutex_);
                // Lazy pruning keeps the in-memory map bounded; there is
                // deliberately no persistent outbound state. A still-pending
                // attempt is never pruned (its delivery is in flight).
                for (auto it = attempts_.begin(); it != attempts_.end();) {
                    if (it->second.status != "pending"
                        && it->second.completedAt + options_.attemptRetentionSeconds < now) {
                        if (!it->second.messageId.empty()) {
                            messageIdToAttempt_.erase(it->second.messageId);
                        }
                        it = attempts_.erase(it);
                    } else {
                        ++it;
                    }
                }
                Attempt pending;
                pending.user = user;
                pending.status = "pending";
                pending.phase = "queued";  // until the delivery worker starts dialing
                pending.messageId = messageId;
                attempts_[attemptId] = pending;
                if (!messageId.empty()) {
                    messageIdToAttempt_[messageId] = attemptId;
                }
            }
            {
                const std::lock_guard<std::mutex> lock(jobsMutex_);
                jobs_.push_back(DeliveryJob{
                    attemptId, toDest, sealed, payload, sender.dest, sender.servingKey});
            }
            jobsCv_.notify_all();
            return jsonResponse({{"attemptId", attemptId}, {"status", "pending"}});
        }));

    http_->get(R"(/v1/messaging/send/([a-f0-9]+))",
        authenticated([this](const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            (void)user;
            const std::lock_guard<std::mutex> lock(attemptsMutex_);
            const auto found = attempts_.find(request.captures.at(0));
            if (found == attempts_.end()) {
                return errorResponse(404, ErrorCode::eAttemptUnknown,
                    "attempt is not known (expired or server restarted)");
            }
            nlohmann::json result = {{"status", found->second.status}};
            if (!found->second.phase.empty()) {
                result["phase"] = found->second.phase;
            }
            if (!found->second.errorCode.empty()) {
                result["error"] = {
                    {"code", found->second.errorCode},
                    {"message", found->second.errorMessage},
                };
            }
            return jsonResponse(result);
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
