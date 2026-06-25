// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Health.hpp>
#include <bazarish/I2pAddress.hpp>

#include <httplib/httplib.h>
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

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

// The full blob length the upstream store declares: the Content-Range total for
// a partial (206) response, else Content-Length. 0 when neither is parseable.
std::uint64_t blobTotalFromHead(const bazarish::server::I2pBlobReader& reader)
{
    const std::map<std::string, std::string>& headers = reader.headers();
    if (reader.status() == 206) {
        const auto range = headers.find("content-range");
        if (range != headers.end()) {
            const std::size_t slash = range->second.rfind('/');
            if (slash != std::string::npos) {
                try {
                    return static_cast<std::uint64_t>(std::stoull(range->second.substr(slash + 1)));
                } catch (const std::exception&) {
                    // fall through to Content-Length
                }
            }
        }
    }
    const auto length = headers.find("content-length");
    if (length != headers.end()) {
        try {
            return static_cast<std::uint64_t>(std::stoull(length->second));
        } catch (const std::exception&) {
            return 0;
        }
    }
    return 0;
}

Bytes bodyBytes(const httplib::Request& request)
{
    return Bytes(request.body.begin(), request.body.end());
}

void respondError(httplib::Response& response, const int status, const ErrorCode code,
    const std::string& message)
{
    response.status = status;
    response.set_content(
        bazarish::makeErrorEnvelope(code, message).dump(), "application/json");
}

void respondJson(httplib::Response& response, const nlohmann::json& body)
{
    response.set_content(body.dump(), "application/json");
}

bazarish::auth::Headers collectAuthHeaders(const httplib::Request& request)
{
    bazarish::auth::Headers headers;
    for (const char* const name : {bazarish::auth::kHeaderKeys,
             bazarish::auth::kHeaderTimestamp, bazarish::auth::kHeaderSignatureClassical,
             bazarish::auth::kHeaderSignaturePq}) {
        if (request.has_header(name)) {
            headers[name] = request.get_header_value(name);
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
    , http_(std::make_unique<httplib::Server>())
    , startedAt_(nowSeconds())
{
    setupRoutes();
    // Background delivery workers (store-and-forward). A small fixed pool: each
    // worker may sit in a per-message retry loop for a while, so size it for the
    // expected number of concurrently-in-flight slow deliveries.
    constexpr int kDeliveryWorkers = 4;
    deliveryWorkers_.reserve(kDeliveryWorkers);
    for (int i = 0; i < kDeliveryWorkers; ++i) {
        deliveryWorkers_.emplace_back([this]() { deliveryWorkerLoop(); });
    }
}

HttpApi::~HttpApi()
{
    stopWorkers();
}

bool HttpApi::listen(const std::string& host, const int port)
{
    return http_->listen(host, port);
}

int HttpApi::bindToAnyPort(const std::string& host)
{
    return http_->bind_to_any_port(host);
}

bool HttpApi::listenAfterBind()
{
    return http_->listen_after_bind();
}

void HttpApi::stop()
{
    http_->stop();
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
}

void HttpApi::setAttempt(const std::string& attemptId, const Attempt& attempt)
{
    const std::lock_guard<std::mutex> lock(attemptsMutex_);
    Attempt updated = attempt;
    // A delivered-ack may already have marked this attempt delivered; never let a
    // later job round downgrade it. Also keep the messageId so the index prunes.
    const auto existing = attempts_.find(attemptId);
    if (existing != attempts_.end()) {
        if (existing->second.status == "delivered") {
            return;
        }
        if (updated.messageId.empty()) {
            updated.messageId = existing->second.messageId;
        }
    }
    attempts_[attemptId] = updated;
}

void HttpApi::markDeliveredByMessageId(const std::string& messageId)
{
    if (messageId.empty()) {
        return;
    }
    const std::lock_guard<std::mutex> lock(attemptsMutex_);
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
    if (found->second.status == "pending" || found->second.status == "unconfirmed") {
        found->second.status = "delivered";
        found->second.completedAt = nowSeconds();
    }
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
    const auto kRetryDelay = std::chrono::seconds(options_.deliveryRetryDelaySeconds);
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
                remote = remoteDeliver_(job.senderDest, job.toDest, job.sealed, job.payload);
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
        // Transient: leave the attempt "pending" and wait before the next round,
        // wakeable immediately on shutdown.
        std::unique_lock<std::mutex> lock(jobsMutex_);
        if (jobsCv_.wait_for(lock, kRetryDelay, [this]() { return stopping_; })) {
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

void HttpApi::setupRoutes()
{
    // Authorizes an operator-internal request by hybrid signature: the caller
    // must sign the request with an identity whose fingerprint is configured as an
    // operator (the service node for quota/transient pushes, the admin panel for
    // management and health). No shared secret. Responds 403 and returns false on
    // any failure.
    const auto operatorAuthorized
        = [this](const httplib::Request& request, httplib::Response& response) -> bool {
        try {
            auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                request.path, bodyBytes(request), options_.operatorFingerprints);
            return true;
        } catch (const std::exception& error) {
            respondError(response, 403, ErrorCode::eDeliveryRejected, error.what());
            return false;
        }
    };

    // Authenticated liveness for the admin panel: service name, version, uptime
    // and resident memory. Operator-only (signed), so it leaks nothing to an
    // unauthenticated caller.
    http_->Get("/healthz",
        [this, operatorAuthorized](const httplib::Request& request, httplib::Response& response) {
            if (!operatorAuthorized(request, response)) {
                return;
            }
            response.set_content(
                health::reportJson("server-core", options_.version, startedAt_, nowSeconds()),
                "application/json");
        });

    // Wraps a handler with request authentication and uniform error
    // mapping. The handler receives the verified caller fingerprint.
    const auto authenticated = [this](auto handler) {
        return [this, handler](const httplib::Request& request, httplib::Response& response) {
            std::string user;
            try {
                user = auth::verifyRequest(collectAuthHeaders(request), nowSeconds(),
                    request.method, request.path, bodyBytes(request), replayCache_);
            } catch (const std::exception& error) {
                respondError(response, 401, ErrorCode::eDeliveryRejected, error.what());
                return;
            }
            try {
                handler(request, response, user);
            } catch (const nlohmann::json::exception& error) {
                respondError(response, 400, ErrorCode::eDeliveryRejected, error.what());
            } catch (const std::invalid_argument& error) {
                respondError(response, 400, ErrorCode::eDeliveryRejected, error.what());
            }
        };
    };

    Storage& store = storage_;

    // Returns the registered client ID of the request or reports
    // CLIENT_UNREGISTERED. Registration itself is the only exception.
    const auto requireClient = [&store](const httplib::Request& request,
                                   httplib::Response& response,
                                   const std::string& user) -> std::string {
        const std::string clientId = request.get_header_value("X-Bazarish-Client");
        if (clientId.empty() || !store.isClientRegistered(user, clientId)) {
            respondError(response, 403, ErrorCode::eClientUnregistered,
                "client ID is not registered for this user");
            return {};
        }
        return clientId;
    };

    // --- Client registry ---

    http_->Post("/v1/messaging/clients",
        authenticated([&store](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            store.registerClient(user, body.at("clientId").get<std::string>());
            respondJson(response, {{"ok", true}});
        }));

    http_->Delete(R"(/v1/messaging/clients/([a-z0-9_-]+))",
        authenticated([&store](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            store.unregisterClient(user, request.matches[1].str());
            respondJson(response, {{"ok", true}});
        }));

    // The caller's assigned serving destination + the public serving sealing
    // key for it, so the client can fold both into its self-signed contact card
    // (see docs-main api/InviteAnonymity.md). Resolved from the authenticated
    // caller's fingerprint.
    http_->Get("/v1/messaging/destination",
        authenticated([this](const httplib::Request&, httplib::Response& response,
                          const std::string& user) {
            const DestinationAssignment assigned = options_.assignDestination
                ? options_.assignDestination(user)
                : DestinationAssignment{};
            respondJson(response,
                {
                    {"dest", assigned.dest},
                    {"servingKey", assigned.servingKey
                            ? toBase64(assigned.servingKey->publicDer())
                            : std::string()},
                    {"state", assigned.state},
                });
        }));

    // --- Operator-internal: per-user storage quota ---
    //
    // Set by the operator's service node over the private channel when a user's
    // storage plan changes. Authorised by an operator signature, not by user auth
    // (the user must not set their own quota).
    http_->Put("/v1/messaging/quota",
        [&store, operatorAuthorized](
            const httplib::Request& request, httplib::Response& response) {
            if (!operatorAuthorized(request, response)) {
                return;
            }
            try {
                const nlohmann::json body = nlohmann::json::parse(request.body);
                store.setUserQuota(body.at("user").get<std::string>(),
                    body.at("quotaBytes").get<std::uint64_t>());
                respondJson(response, {{"ok", true}});
            } catch (const std::exception& error) {
                respondError(response, 400, ErrorCode::eDeliveryRejected, error.what());
            }
        });

    // Per-user I2P destination (operator-internal). Set by the operator's
    // service node when a paid user's i2pDest plan changes: it hands over the
    // client-owned offline transient so this server can operate the user's
    // personal destination. Same operator signature as quota. A request without a
    // transient revokes the destination.
    http_->Put("/v1/messaging/i2p-dest",
        [this, operatorAuthorized](const httplib::Request& request, httplib::Response& response) {
            if (!operatorAuthorized(request, response)) {
                return;
            }
            if (!options_.provisionI2pDest || !options_.revokeI2pDest) {
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "per-user destinations not available");
                return;
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
                respondJson(response, {{"ok", true}});
            } catch (const std::exception& error) {
                respondError(response, 400, ErrorCode::eDeliveryRejected, error.what());
            }
        });

    // --- Token hashes ---

    http_->Post("/v1/messaging/tokens",
        authenticated([&store, requireClient](const httplib::Request& request,
                          httplib::Response& response, const std::string& user) {
            if (requireClient(request, response, user).empty()) {
                return;
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
            respondJson(response, {{"ok", true}});
        }));

    http_->Delete("/v1/messaging/tokens",
        authenticated([&store, requireClient](const httplib::Request& request,
                          httplib::Response& response, const std::string& user) {
            if (requireClient(request, response, user).empty()) {
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            std::vector<Bytes> hashes;
            for (const nlohmann::json& entry : body.at("hashes")) {
                hashes.push_back(fromBase64(entry.get<std::string>()));
            }
            store.deleteTokenHashes(user, hashes);
            respondJson(response, {{"ok", true}});
        }));

    // --- Pending content ---

    http_->Get("/v1/messaging/pending",
        authenticated([&store, requireClient](const httplib::Request& request,
                          httplib::Response& response, const std::string& user) {
            const std::string clientId = requireClient(request, response, user);
            if (clientId.empty()) {
                return;
            }
            nlohmann::json pending = nlohmann::json::array();
            for (const Storage::PendingEntry& entry : store.listPending(user, clientId)) {
                pending.push_back({{"id", entry.blobId}, {"class", entry.deliveryClass}});
            }
            respondJson(response, {{"pending", pending}});
        }));

    http_->Get(R"(/v1/messaging/pending/([a-z0-9_-]+))",
        authenticated([&store, requireClient](const httplib::Request& request,
                          httplib::Response& response, const std::string& user) {
            if (requireClient(request, response, user).empty()) {
                return;
            }
            const std::string blobId = request.matches[1].str();
            if (!store.hasBlob(user, blobId)) {
                respondError(response, 404, ErrorCode::eDeliveryRejected, "no such blob");
                return;
            }
            const Bytes data = store.getBlob(user, blobId);
            response.set_content(
                std::string(data.begin(), data.end()), "application/octet-stream");
        }));

    http_->Post("/v1/messaging/ack",
        authenticated([&store, requireClient](const httplib::Request& request,
                          httplib::Response& response, const std::string& user) {
            const std::string clientId = requireClient(request, response, user);
            if (clientId.empty()) {
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            store.ackBlob(user, body.at("blobId").get<std::string>(), clientId);
            respondJson(response, {{"ok", true}});
        }));

    // --- Blob proxy (for clients without their own I2P transport) ---

    // Proxies a large-message blob op over I2P on the client's behalf: the client
    // passes the blob's .b32.i2p host + path (+ method GET download / DELETE
    // unsend, + delete-token), the server runs it over a fresh transient I2P
    // destination and relays the result. Only .b32.i2p hosts - never an open proxy.
    http_->Get("/v1/messaging/blob-proxy",
        authenticated([this, requireClient](const httplib::Request& request,
                          httplib::Response& response, const std::string& user) {
            if (requireClient(request, response, user).empty()) {
                return;
            }
            const std::string method = request.has_param("method")
                ? request.get_param_value("method")
                : std::string("GET");
            if (method != "GET" && method != "DELETE") {
                respondError(response, 400, ErrorCode::eDeliveryRejected, "unsupported proxy method");
                return;
            }
            const std::string host = request.get_param_value("host");
            const std::string path = request.get_param_value("path");
            const std::string token = request.get_param_value("token");
            const std::string range
                = request.has_param("range") ? request.get_param_value("range") : std::string();
            const std::string suffix = ".b32.i2p";
            if (host.size() <= suffix.size()
                || host.compare(host.size() - suffix.size(), suffix.size(), suffix) != 0) {
                respondError(
                    response, 400, ErrorCode::eDeliveryRejected, "host is not a .b32.i2p address");
                return;
            }
            // Unsend: a small whole-body op.
            if (method == "DELETE") {
                if (!options_.blobProxyFetch) {
                    respondError(response, 503, ErrorCode::eDeliveryRejected, "blob proxy disabled");
                    return;
                }
                try {
                    const BlobProxyResult fetched
                        = options_.blobProxyFetch(method, host, path, token);
                    if (fetched.status != 200) {
                        respondError(response, 502, ErrorCode::eDeliveryRejected,
                            "blob op returned status " + std::to_string(fetched.status));
                        return;
                    }
                    response.set_content(std::string(fetched.body.begin(), fetched.body.end()),
                        "application/octet-stream");
                } catch (const std::exception& error) {
                    respondError(response, 502, ErrorCode::eDeliveryRejected, error.what());
                }
                return;
            }
            // Download: stream the ciphertext through so the whole blob is never
            // buffered here. The full blob length rides in X-Blob-Total (derived
            // from the upstream Content-Length or Content-Range) so the recipient
            // can detect a truncated transfer and resume with a Range request.
            if (!options_.blobProxyDownload) {
                respondError(response, 503, ErrorCode::eDeliveryRejected, "blob proxy disabled");
                return;
            }
            std::shared_ptr<I2pBlobReader> reader;
            try {
                reader = options_.blobProxyDownload(host, path, range);
            } catch (const std::exception& error) {
                respondError(response, 502, ErrorCode::eDeliveryRejected, error.what());
                return;
            }
            if (reader->status() != 200 && reader->status() != 206) {
                respondError(response, 502, ErrorCode::eDeliveryRejected,
                    "blob op returned status " + std::to_string(reader->status()));
                return;
            }
            response.set_header("X-Blob-Total", std::to_string(blobTotalFromHead(*reader)));
            response.set_chunked_content_provider("application/octet-stream",
                [reader](std::size_t, httplib::DataSink& sink) {
                    std::array<char, 65536> buffer{};
                    const std::size_t got = reader->readBody(buffer.data(), buffer.size());
                    if (got == 0) {
                        sink.done();
                        return true;
                    }
                    return sink.write(buffer.data(), got);
                });
        }));

    // --- Sending: submit + poll ---

    http_->Post("/v1/messaging/send",
        authenticated([this, requireClient](const httplib::Request& request,
                          httplib::Response& response, const std::string& user) {
            if (requireClient(request, response, user).empty()) {
                return;
            }
            if (request.body.size() > options_.perMessageLimitBytes) {
                respondError(response, 413, ErrorCode::eQuotaExceeded,
                    "envelope exceeds the per-message limit of "
                        + std::to_string(options_.perMessageLimitBytes) + " bytes");
                return;
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
                pending.status = "pending";
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
            respondJson(response, {{"attemptId", attemptId}, {"status", "pending"}});
        }));

    http_->Get(R"(/v1/messaging/send/([a-f0-9]+))",
        authenticated([this](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            (void)user;
            const std::lock_guard<std::mutex> lock(attemptsMutex_);
            const auto found = attempts_.find(request.matches[1].str());
            if (found == attempts_.end()) {
                respondError(response, 404, ErrorCode::eAttemptUnknown,
                    "attempt is not known (expired or server restarted)");
                return;
            }
            nlohmann::json result = {{"status", found->second.status}};
            if (!found->second.errorCode.empty()) {
                result["error"] = {
                    {"code", found->second.errorCode},
                    {"message", found->second.errorMessage},
                };
            }
            respondJson(response, result);
        }));

    // First-contact discovery proxy (fallback for a client without its own I2P transport):
    // relay a sealed fetch (op "card" to a serving server, "resolve" to the
    // central resolver) to toDest over I2P and return the sealed response. The
    // server moves opaque bytes - the client sealed the query and verifies the
    // response (see docs-main api/FederatedResolve.md).
    http_->Post("/v1/messaging/fetch",
        authenticated([this](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            (void)user;
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string toDest = body.at("toDest").get<std::string>();
            validateB32I2pHost(toDest);
            const std::string op = body.at("op").get<std::string>();
            if (op != "card" && op != "resolve") {
                respondError(response, 400, ErrorCode::eDeliveryRejected, "unsupported fetch op");
                return;
            }
            const Bytes sealed = fromBase64(body.at("sealed").get<std::string>());
            if (!remoteFetch_) {
                respondError(
                    response, 400, ErrorCode::eDeliveryRejected, "no federation transport");
                return;
            }
            const RemoteFetchResult result = remoteFetch_(toDest, op, sealed);
            if (!result.reachable) {
                respondError(response, 400, ErrorCode::eRecipientServerUnreachable,
                    "destination could not be reached");
                return;
            }
            nlohmann::json reply = {{"ok", result.ok}};
            if (result.ok) {
                reply["sealed"] = toBase64(result.sealed);
            } else if (!result.errorCode.empty()) {
                reply["errorCode"] = result.errorCode;
            }
            respondJson(response, reply);
        }));
}

}  // namespace bazarish::server
