// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <ctime>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
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
    RemoteDeliverFn remoteDeliver)
    : storage_(storage)
    , engine_(engine)
    , options_(options)
    , remoteDeliver_(std::move(remoteDeliver))
    , http_(std::make_unique<httplib::Server>())
{
    setupRoutes();
}

HttpApi::~HttpApi() = default;

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
}

void HttpApi::setupRoutes()
{
    // Wraps a handler with request authentication and uniform error
    // mapping. The handler receives the verified caller fingerprint.
    const auto authenticated = [](auto handler) {
        return [handler](const httplib::Request& request, httplib::Response& response) {
            std::string user;
            try {
                user = auth::verifyRequest(collectAuthHeaders(request), nowSeconds(),
                    request.method, request.path, bodyBytes(request));
            } catch (const std::exception& error) {
                respondError(response, 401, ErrorCode::kDeliveryRejected, error.what());
                return;
            }
            try {
                handler(request, response, user);
            } catch (const nlohmann::json::exception& error) {
                respondError(response, 400, ErrorCode::kDeliveryRejected, error.what());
            } catch (const std::invalid_argument& error) {
                respondError(response, 400, ErrorCode::kDeliveryRejected, error.what());
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
            respondError(response, 403, ErrorCode::kClientUnregistered,
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

    // --- Operator-internal: per-user storage quota ---
    //
    // Set by the operator's service node over the private channel when a user's
    // storage plan changes. Authorised by a shared secret, not by user auth (the
    // user must not set their own quota).
    http_->Put("/v1/messaging/quota",
        [this, &store](const httplib::Request& request, httplib::Response& response) {
            if (options_.operatorSecret.empty()
                || request.get_header_value("X-Operator-Secret") != options_.operatorSecret) {
                respondError(response, 403, ErrorCode::kDeliveryRejected,
                    "operator authentication required");
                return;
            }
            try {
                const nlohmann::json body = nlohmann::json::parse(request.body);
                store.setUserQuota(body.at("user").get<std::string>(),
                    body.at("quotaBytes").get<std::uint64_t>());
                respondJson(response, {{"ok", true}});
            } catch (const std::exception& error) {
                respondError(response, 400, ErrorCode::kDeliveryRejected, error.what());
            }
        });

    // Per-user I2P destination (operator-internal). Set by the operator's
    // service node when a paid user's i2pDest plan changes: it hands over the
    // client-owned offline transient so this server can operate the user's
    // personal destination. Same shared secret as quota. A request without a
    // transient revokes the destination.
    http_->Put("/v1/messaging/i2p-dest",
        [this](const httplib::Request& request, httplib::Response& response) {
            if (options_.operatorSecret.empty()
                || request.get_header_value("X-Operator-Secret") != options_.operatorSecret) {
                respondError(response, 403, ErrorCode::kDeliveryRejected,
                    "operator authentication required");
                return;
            }
            if (!options_.provisionI2pDest || !options_.revokeI2pDest) {
                respondError(response, 503, ErrorCode::kDeliveryRejected,
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
                respondError(response, 400, ErrorCode::kDeliveryRejected, error.what());
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
                respondError(response, 404, ErrorCode::kDeliveryRejected, "no such blob");
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

    // --- Blob proxy (for clients without a local SAM bridge) ---

    // Proxies a large-message blob op over I2P on the client's behalf: the client
    // passes the blob's .b32.i2p host + path (+ method GET download / DELETE
    // unsend, + delete-token), the server runs it over a fresh transient SAM
    // session and relays the result. Only .b32.i2p hosts — never an open proxy.
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
                respondError(response, 400, ErrorCode::kDeliveryRejected, "unsupported proxy method");
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
                    response, 400, ErrorCode::kDeliveryRejected, "host is not a .b32.i2p address");
                return;
            }
            // Unsend: a small whole-body op.
            if (method == "DELETE") {
                if (!options_.blobProxyFetch) {
                    respondError(response, 503, ErrorCode::kDeliveryRejected, "blob proxy disabled");
                    return;
                }
                try {
                    const BlobProxyResult fetched
                        = options_.blobProxyFetch(method, host, path, token);
                    if (fetched.status != 200) {
                        respondError(response, 502, ErrorCode::kDeliveryRejected,
                            "blob op returned status " + std::to_string(fetched.status));
                        return;
                    }
                    response.set_content(std::string(fetched.body.begin(), fetched.body.end()),
                        "application/octet-stream");
                } catch (const std::exception& error) {
                    respondError(response, 502, ErrorCode::kDeliveryRejected, error.what());
                }
                return;
            }
            // Download: stream the ciphertext through so the whole blob is never
            // buffered here. The full blob length rides in X-Blob-Total (derived
            // from the upstream Content-Length or Content-Range) so the recipient
            // can detect a truncated transfer and resume with a Range request.
            if (!options_.blobProxyDownload) {
                respondError(response, 503, ErrorCode::kDeliveryRejected, "blob proxy disabled");
                return;
            }
            std::shared_ptr<I2pBlobReader> reader;
            try {
                reader = options_.blobProxyDownload(host, path, range);
            } catch (const std::exception& error) {
                respondError(response, 502, ErrorCode::kDeliveryRejected, error.what());
                return;
            }
            if (reader->status() != 200 && reader->status() != 206) {
                respondError(response, 502, ErrorCode::kDeliveryRejected,
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
                respondError(response, 413, ErrorCode::kQuotaExceeded,
                    "envelope exceeds the per-message limit of "
                        + std::to_string(options_.perMessageLimitBytes) + " bytes");
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string toDest = body.at("toDest").get<std::string>();
            const Bytes sealed = fromBase64(body.at("sealed").get<std::string>());
            const Bytes payload = fromBase64(body.at("payload").get<std::string>());

            const std::int64_t now = nowSeconds();
            Attempt attempt;
            // Routed by destination: a delivery to this server's own destination
            // is local (unsealed with the home key); anything else is federated.
            if (!options_.localDest.empty() && toDest == options_.localDest) {
                const DeliveryEngine::Outcome outcome
                    = engine_.deliver(sealed, payload, now, engine_.sealingKey());
                attempt.status = outcome.delivered ? "delivered" : "failed";
                attempt.errorCode = outcome.errorCode;
                attempt.errorMessage = outcome.errorMessage;
            } else {
                RemoteDeliveryResult remote;
                if (remoteDeliver_) {
                    remote = remoteDeliver_(toDest, sealed, payload);
                }
                if (!remote.reachable) {
                    attempt.status = "failed";
                    attempt.errorCode
                        = std::string(toString(ErrorCode::kRecipientServerUnreachable));
                    attempt.errorMessage = "recipient server could not be reached";
                } else {
                    attempt.status = remote.delivered ? "delivered" : "failed";
                    attempt.errorCode = remote.errorCode;
                    attempt.errorMessage = remote.errorMessage;
                }
            }
            attempt.completedAt = now;

            const std::string attemptId = toHex(randomBytes(16));
            {
                const std::lock_guard<std::mutex> lock(attemptsMutex_);
                // Lazy pruning keeps the in-memory map bounded; there is
                // deliberately no persistent outbound state.
                for (auto it = attempts_.begin(); it != attempts_.end();) {
                    if (it->second.completedAt + options_.attemptRetentionSeconds < now) {
                        it = attempts_.erase(it);
                    } else {
                        ++it;
                    }
                }
                attempts_[attemptId] = attempt;
            }
            respondJson(response, {{"attemptId", attemptId}});
        }));

    http_->Get(R"(/v1/messaging/send/([a-f0-9]+))",
        authenticated([this](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            (void)user;
            const std::lock_guard<std::mutex> lock(attemptsMutex_);
            const auto found = attempts_.find(request.matches[1].str());
            if (found == attempts_.end()) {
                respondError(response, 404, ErrorCode::kAttemptUnknown,
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
}

}  // namespace bazarish::server
