// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "EventGate.hpp"

#include <bazarish/Cms.hpp>

#include <bazarish/Log.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/Tunnel.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Pass.hpp>
#include <bazarish/Health.hpp>
#include <bazarish/I2p.hpp>
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

// What a listener may be told to bind: TCP's range without port 0, which means
// "any free port" and is never what an operator typed on purpose.
constexpr int kMinPort = 1;
constexpr int kMaxPort = 65535;


using bazarish::Bytes;
using bazarish::ErrorCode;

// How many routers the archive carries, and how often it is repacked. A fresh
// router needs a real slice of the netDb to start from; an hour between packings
// keeps the walk off the disk and means one caller cannot learn more of this
// server's netDb by asking again.
constexpr std::size_t kReseedRouters = 60;
constexpr std::int64_t kReseedRefreshSeconds = 3600;

// A header name as the request map holds it.
std::string lowered(std::string name)
{
    std::transform(name.begin(), name.end(), name.begin(),
        [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return name;
}

// How long the service node has to answer a call forwarded to it. It is on the
// same machine or one hop away, and a client is waiting on the other end.
constexpr int kNodeTimeoutSeconds = 5;

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

HttpApi::HttpApi(Storage& storage, DeliveryEngine& engine, const HttpApiOptions options)
    : storage_(storage)
    , engine_(engine)
    , options_(options)
    , startedAt_(nowSeconds())
{
    // One thread for the node: the mailbox TTL backstop sweep, and the token
    // revocations users ask for. It runs even with retention disabled, because a
    // revocation is not housekeeping - somebody is waiting for it.
    janitorThread_ = std::thread([this]() { mailboxJanitorLoop(); });
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

std::string HttpApi::reseedArchive()
{
    if (!options_.reseedSample) {
        return {};  // no router here, so no netDb to hand out
    }
    const std::lock_guard<std::mutex> lock(reseedMutex_);
    const std::int64_t now = nowSeconds();
    if (!reseedSu3_.empty() && now - reseedPackedAt_ < kReseedRefreshSeconds) {
        return reseedSu3_;
    }
    const std::vector<Bytes> routers = options_.reseedSample(kReseedRouters);
    if (routers.empty()) {
        return reseedSu3_;  // an empty netDb: whatever was packed before, or nothing
    }
    // The name in the header is what an operator sees when they open the file;
    // it names the service, not the server.
    const Bytes su3 = bazarish::i2p::packReseedSu3(routers, "bazarish");
    reseedSu3_.assign(su3.begin(), su3.end());
    reseedPackedAt_ = now;
    bazarish::log::info("reseed archive packed: {} routers, {} bytes", routers.size(),
        reseedSu3_.size());
    return reseedSu3_;
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
            // Sleep one interval, but return at once on shutdown.
            stopCv_.wait_for(lock, kSweepInterval, [this]() { return stopping_; });
            if (stopping_) {
                return;
            }
        }  // release stopMutex_ before touching storage (it takes its own lock)
        if (options_.mailboxRetentionSeconds <= 0) {
            continue;
        }
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

void HttpApi::serveTunnel(
    const bazarish::http::Request& request, bazarish::http::Responder respond)
{
    const Bytes frame(request.body.begin(), request.body.end());
    // Nothing here says why it failed, and nothing distinguishes one failure from
    // another: the only caller who could act on the difference is the one in the
    // middle, and it is the one this exists to keep out. A client that gets this
    // opens a new tunnel.
    const auto refuse = [respond]() {
        bazarish::http::Response response;
        response.status = 400;
        response.contentType = "application/octet-stream";
        respond(std::move(response));
    };
    // By value: a route behind this answers later when it is a long poll, and a
    // responder captured by reference would be gone by the time it did - the
    // client would wait out its read timeout for an answer nobody could send.
    const auto sealed = [respond](const Bytes& body) {
        bazarish::http::Response response;
        response.contentType = "application/octet-stream";
        response.body = std::string(body.begin(), body.end());
        respond(std::move(response));
    };

    if (bazarish::tunnel::isHello(frame)) {
        if (!options_.sealingKey) {
            refuse();
            return;
        }
        try {
            const bazarish::tunnel::Hello hello
                = bazarish::tunnel::openHello(frame, *options_.sealingKey);
            // The one place an identity is presented. Everything after this is
            // authenticated by holding the key that came out of this frame.
            const std::string user = auth::verifyRequest(hello.signature, nowSeconds(),
                bazarish::tunnel::kHelloMethod, bazarish::tunnel::kHelloPath, hello.secret,
                replayCache_);
            std::int64_t expiresUnix = 0;
            const std::string id = sessions_.open(user, hello.secret, nowSeconds(), &expiresUnix);
            sessions_.setTunnelKey(id, bazarish::tunnel::deriveTunnelKey(hello.secret, id));
            sealed(bazarish::tunnel::sealWelcome(
                {expiresUnix}, Key::fromPublicDer(hello.replyKeyDer)));
        } catch (const std::exception& error) {
            bazarish::log::debug("a tunnel did not open: {}", error.what());
            refuse();
        }
        return;
    }

    std::string handle;
    std::optional<SessionStore::Session> session;
    try {
        handle = bazarish::tunnel::handleOf(frame);
        session = sessions_.findByHandle(handle, nowSeconds());
    } catch (const std::exception& error) {
        // The answer is the same whatever went wrong - telling the difference
        // apart is only of use to the one in the middle - but the reason is
        // written down, or a frame this server cannot read leaves no trace
        // anywhere and both sides can only guess.
        bazarish::log::debug("tunnel frame not addressed to any tunnel: {}", error.what());
        refuse();
        return;
    }
    if (!session.has_value() || session->tunnelKey.empty()) {
        bazarish::log::debug("tunnel frame names a tunnel this server does not hold");
        refuse();
        return;
    }
    bazarish::http::Request carried;
    try {
        const bazarish::tunnel::Request inner = bazarish::tunnel::decodeRequest(
            bazarish::tunnel::open(frame, session->tunnelKey));
        carried.method = inner.method;
        carried.path = inner.path;
        carried.target = inner.query.empty() ? inner.path : inner.path + "?" + inner.query;
        carried.body = std::string(inner.body.begin(), inner.body.end());
        for (const auto& [name, value] : inner.headers) {
            carried.headers[lowered(name)] = value;
        }
        if (!inner.contentType.empty()) {
            carried.headers["content-type"] = inner.contentType;
        }
    } catch (const std::exception& error) {
        // A frame that will not open, or will not decode into a request: same
        // uniform refusal, same reason written down.
        bazarish::log::debug("tunnel frame did not open: {}", error.what());
        refuse();
        return;
    }
    // The answer goes back under the same key. Its status rides inside: outside
    // it is always the same, or the code itself would be the channel.
    const Bytes tunnelKey = session->tunnelKey;
    http_->dispatch(carried,
        [respond = std::move(respond), handle, tunnelKey](bazarish::http::Response answer) {
            bazarish::tunnel::Response inner;
            inner.status = answer.status;
            inner.contentType = answer.contentType;
            inner.body = Bytes(answer.body.begin(), answer.body.end());
            const Bytes body = bazarish::tunnel::carry(
                handle, tunnelKey, bazarish::tunnel::encodeResponse(inner));
            bazarish::http::Response outer;
            outer.contentType = "application/octet-stream";
            outer.body = std::string(body.begin(), body.end());
            respond(std::move(outer));
        });
}

bazarish::http::Response HttpApi::forwardToNode(
    const bazarish::http::Request& request, const std::string& user)
{
    if (options_.serviceNodeUrl.empty() || !options_.identity) {
        return errorResponse(503, ErrorCode::eDeliveryRejected, "no service node here");
    }
    // The user is named in the path, which is signed; a header would be a line
    // the link between the two could rewrite. The node authorises the signature
    // against the card it is bound to, so no shared secret and no new setting.
    const std::string target = std::string(bazarish::tunnel::kVouchedPrefix) + user + request.path;
    const Bytes body(request.body.begin(), request.body.end());
    const auth::Headers signed_
        = auth::signRequest(*options_.identity, nowSeconds(), request.method, target, body);
    bazarish::http::ClientRequest forwarded;
    forwarded.method = request.method;
    forwarded.target = request.target.size() > request.path.size()
        ? target + request.target.substr(request.path.size())
        : target;
    forwarded.headers = std::map<std::string, std::string>(signed_.begin(), signed_.end());
    forwarded.body = request.body;
    if (!request.body.empty()) {
        forwarded.contentType = "application/json";
    }
    const ServiceNodeAddress node = parseServiceNodeUrl(options_.serviceNodeUrl);
    bazarish::http::ClientOptions clientOptions;
    clientOptions.connectTimeout = std::chrono::seconds(kNodeTimeoutSeconds);
    clientOptions.readTimeout = std::chrono::seconds(kNodeTimeoutSeconds);
    clientOptions.writeTimeout = std::chrono::seconds(kNodeTimeoutSeconds);
    try {
        const bazarish::http::ClientResponse answered
            = bazarish::http::request(node.host, node.port, forwarded, clientOptions);
        bazarish::http::Response response;
        response.status = answered.status;
        response.contentType = "application/json";
        response.body = answered.body;
        return response;
    } catch (const std::exception& error) {
        bazarish::log::warn("the service node did not answer: {}", error.what());
        return errorResponse(502, ErrorCode::eDeliveryRejected, "the service node did not answer");
    }
}

ServiceNodeAddress parseServiceNodeUrl(const std::string& url)
{
    std::string rest = url;
    if (const std::string scheme = "http://"; rest.rfind(scheme, 0) == 0) {
        rest = rest.substr(scheme.size());
    }
    if (const auto slash = rest.find('/'); slash != std::string::npos) {
        rest = rest.substr(0, slash);
    }
    ServiceNodeAddress address;
    if (const auto colon = rest.find(':'); colon == std::string::npos) {
        address.host = rest;
    } else {
        address.host = rest.substr(0, colon);
        address.port = std::stoi(rest.substr(colon + 1));
    }
    return address;
}

std::optional<bazarish::http::Response> HttpApi::authenticateRequest(
    const bazarish::http::Request& request, std::string* const outUser, const bool allowSession)
{
    const auth::Headers authHeaders = collectAuthHeaders(request);
    // The device this request speaks for. It is part of what was signed or
    // MAC'd, so a facade that rewrote it to another device of the same account -
    // and so acknowledged that device's mail away - fails verification here
    // rather than being obeyed.
    const std::string clientId = request.header("X-Bazarish-Client");
    if (auth::hasSessionHeaders(authHeaders)) {
        if (!allowSession) {
            // Typed as an invalid session on purpose: a client answers that by
            // presenting the signature, which is exactly what this route wants.
            return errorResponse(401, ErrorCode::eSessionInvalid,
                "this route is authenticated by the identity signature, not a session");
        }
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
                request.method, request.path, bodyBytes(request), clientId);
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
            bodyBytes(request), replayCache_, clientId);
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

    // The server card: public, the same answer for everybody, and what a client
    // needs before it can seal anything. It is signed by this server's root key,
    // so a facade may withhold it but cannot put its own in its place - which is
    // what makes the tunnel below trustworthy from an untrusted middle.
    http_->get(std::string(bazarish::tunnel::kServerCardPath),
        [this](const bazarish::http::Request&) -> bazarish::http::Response {
            if (options_.serverCardDer.empty()) {
                return errorResponse(503, ErrorCode::eDeliveryRejected, "no card here");
            }
            bazarish::http::Response response;
            response.contentType = "application/octet-stream";
            response.body = std::string(
                options_.serverCardDer.begin(), options_.serverCardDer.end());
            return response;
        });

    // The one route a facade sees. Everything a client says arrives through it,
    // sealed; everything this server answers leaves through it, sealed.
    http_->routeAsync("POST", std::string(bazarish::tunnel::kTunnelPath),
        [this](const bazarish::http::Request& request,
            bazarish::http::Responder respond) -> std::optional<bazarish::http::Response> {
            serveTunnel(request, std::move(respond));
            return std::nullopt;
        });

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
                    std::string())};
        });

    // Wraps a handler with request authentication and uniform error
    // mapping. The handler receives the verified caller fingerprint.
    const auto authenticate = [this](auto handler, const bool allowSession) {
        return [this, handler, allowSession](
                   const bazarish::http::Request& request) -> bazarish::http::Response {
            std::string user;
            if (const std::optional<bazarish::http::Response> refused
                = authenticateRequest(request, &user, allowSession);
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
    const auto authenticated
        = [authenticate](auto handler) { return authenticate(handler, /*allowSession=*/true); };
    // For the one route a session may not authenticate: the one that issues them.
    const auto signedOnly
        = [authenticate](auto handler) { return authenticate(handler, /*allowSession=*/false); };

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
                // Armed first, looked at second. A delivery that landed between
                // the look above and this arming woke nobody: this request then
                // waited out the whole poll for mail that was already in the
                // mailbox. The re-check below closes that window - waking the
                // waiter is what a delivery would have done.
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
                try {
                    if (!pending().empty()) {
                        gate->notify(user);
                    }
                } catch (const std::exception& error) {
                    // The waiter is armed either way; at worst it waits out its
                    // poll, which is the behaviour this check is improving on.
                    bazarish::log::warn("event face re-check: {}", error.what());
                }
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
        signedOnly([this](const bazarish::http::Request& request,
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

    // The reseed archive, for the portal to publish. Deliberately outside
    // /v1/messaging/: a facade forwards that prefix and a facade is an I2P
    // address, while a reseed is the one thing a client needs BEFORE it has I2P.
    // So this path is reachable only on the private listener, and what faces the
    // clearnet is the portal, which is on it anyway. Nothing is authenticated
    // here and nothing needs to be: every RouterInfo inside is signed by the
    // router it describes.
    http_->get("/internal/i2pseeds.su3",
        [this](const bazarish::http::Request&) -> bazarish::http::Response {
            const std::string archive = reseedArchive();
            if (archive.empty()) {
                return errorResponse(503, ErrorCode::eI2pUnavailable, "no reseed available");
            }
            return bazarish::http::Response{
                200, "application/octet-stream", {}, archive};
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

    // --- Operator-internal: an account is gone ---
    //
    // The node owns the account and this server owns the mail, so a deletion has
    // to be told to both. Everything held for the user goes at once - mail,
    // replay markers, token hashes, devices, quota - because an account that no
    // longer exists must not keep a mailbox that answers for it. Idempotent: a
    // user with nothing here is already in the state this asks for.
    http_->del("/v1/messaging/account",
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
            store.forgetUser(user);
            bazarish::log::info("mailbox of {} dropped: the account was deleted",
                bazarish::log::redact(user));
            return jsonResponse({{"ok", true}});
        });

    // --- Operator-internal: what the storage occupies ---
    //
    // The panel shows this next to the sum of the quotas: the two answer
    // different questions, and only this one is measured.
    // --- Operator-internal: this server's own configuration ---
    //
    // Everything an operator would otherwise edit over SSH. The log level and
    // libi2pd's logging take effect at once; the rest is written for the next
    // start, and the panel says so beside each field.
    http_->get("/v1/messaging/settings",
        [this, operatorRejection](
            const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            if (!options_.settings) {
                return errorResponse(503, ErrorCode::eDeliveryRejected,
                    "this server was started without a config file to write to");
            }
            const ServerSettings::Values values = options_.settings->get();
            return jsonResponse({
                {"logLevel", values.logLevel},
                {"i2pLog", values.i2pLog},
                {"i2pPrivacy", values.i2pPrivacy},
                {"i2pTunnelQuantity", values.i2pTunnelQuantity},
                {"federationRateLimit", values.federationRateLimit},
                {"mailboxRetentionDays", values.mailboxRetentionDays},
                {"listen", {{"host", values.listenHost}, {"port", values.listenPort}}},
                {"serviceNode", values.serviceNodeUrl},
                {"stateDirectory", options_.stateDirectory},
                {"fingerprint", options_.fingerprint},
                {"version", options_.version},
                {"canRestart", static_cast<bool>(options_.requestRestart)},
            });
        });

    http_->put("/v1/messaging/settings",
        [this, operatorRejection](
            const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            if (!options_.settings) {
                return errorResponse(503, ErrorCode::eDeliveryRejected,
                    "this server was started without a config file to write to");
            }
            ServerSettings::Values values = options_.settings->get();
            try {
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
                if (body.contains("federationRateLimit")) {
                    const std::int64_t limit
                        = body.at("federationRateLimit").get<std::int64_t>();
                    if (limit < 1) {
                        throw std::invalid_argument(
                            "a rate limit of zero accepts nothing from anyone");
                    }
                    values.federationRateLimit = static_cast<std::size_t>(limit);
                }
                if (body.contains("mailboxRetentionDays")) {
                    const std::int64_t days
                        = body.at("mailboxRetentionDays").get<std::int64_t>();
                    if (days < 0) {
                        throw std::invalid_argument("a retention cannot be negative");
                    }
                    values.mailboxRetentionDays = days;
                }
                if (body.contains("listen")) {
                    const nlohmann::json& listen = body.at("listen");
                    const std::string host = listen.value("host", values.listenHost);
                    const int port = listen.value("port", values.listenPort);
                    if (host.empty()) {
                        throw std::invalid_argument("a listener needs a host to bind");
                    }
                    if (port < kMinPort || port > kMaxPort) {
                        throw std::invalid_argument("a port is between "
                            + std::to_string(kMinPort) + " and " + std::to_string(kMaxPort));
                    }
                    values.listenHost = host;
                    values.listenPort = port;
                }
                if (body.contains("serviceNode")) {
                    values.serviceNodeUrl = body.at("serviceNode").get<std::string>();
                }
            } catch (const nlohmann::json::exception& error) {
                return errorResponse(400, ErrorCode::eDeliveryRejected, error.what());
            } catch (const std::invalid_argument& error) {
                return errorResponse(400, ErrorCode::eDeliveryRejected, error.what());
            }

            const ServerSettings::Values before = options_.settings->get();
            try {
                options_.settings->set(values);
            } catch (const std::exception& error) {
                return errorResponse(500, ErrorCode::eDeliveryRejected, error.what());
            }
            // The two that do not wait for a restart.
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
            return jsonResponse({{"logLevel", values.logLevel}, {"i2pLog", values.i2pLog}});
        });

    // Restarting is the other half of editing a startup setting from a browser:
    // without it the operator still has to open a terminal to make the change
    // they just saved take effect. The process stops cleanly and its service
    // manager starts it again.
    http_->post("/v1/messaging/restart",
        [this, operatorRejection](
            const bazarish::http::Request& request) -> bazarish::http::Response {
            if (const std::optional<bazarish::http::Response> refused = operatorRejection(request);
                refused.has_value()) {
                return *refused;
            }
            if (!options_.requestRestart) {
                return errorResponse(503, ErrorCode::eDeliveryRejected,
                    "this server cannot restart itself: it was started without a supervisor");
            }
            bazarish::log::info("restarting at the operator's request");
            options_.requestRestart();
            return jsonResponse({{"restarting", true}});
        });

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

    // --- Account management, on its way to the service node ---
    //
    // A client's account calls arrive in the same tunnel as everything else, so
    // the facade cannot tell one kind from the other - it sees one path and one
    // length. This server authenticates them like any other request and passes
    // them on under its own signature, naming whose call it is.
    //
    // An allow-list, not a deny-list: only what a client's own account needs is
    // forwarded. `GET /v1/account/card` is deliberately absent - it answers to
    // anyone holding a view capability, so forwarding it for a client would let
    // one ask "is this user served here?" about anybody. The rule used to live
    // in the facade; it lives here now, where the reasoning is.
    for (const auto& [method, path] :
        std::vector<std::pair<const char*, const char*>>{
            {"POST", "/v1/account/card"},
            {"POST", "/v1/account/serving-key"},
            {"POST", "/v1/account/serving-key/commit"},
            {"POST", "/v1/account/registration"},
            {"DELETE", "/v1/account/registration"},
            {"GET", "/v1/account/portal"},
            {"POST", "/v1/account/i2p-dest"},
            {"GET", "/v1/account/i2p-status"},
        }) {
        http_->route(method, path,
            authenticated([this](const bazarish::http::Request& request,
                              const std::string& user) -> bazarish::http::Response {
                return forwardToNode(request, user);
            }));
    }

    // --- Delivery passes ---
    //
    // Registering one already held is not an error: that is how an account gives
    // a correspondent their pass back after a block, without sending them
    // anything.

    http_->post("/v1/messaging/passes",
        authenticated([&store, requireClient, clientUnregistered](
                          const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (requireClient(request, user).empty()) {
                return clientUnregistered();
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const nlohmann::json& asked = body.at("passes");
            if (asked.size() > kMaxPassesPerRequest) {
                throw std::invalid_argument("too many delivery passes in one request");
            }
            std::vector<Bytes> handles;
            for (const nlohmann::json& entry : asked) {
                Bytes handle = fromBase64(entry.get<std::string>());
                if (handle.size() != kDeliveryPassSize) {
                    throw std::invalid_argument("delivery pass handle has wrong size");
                }
                handles.push_back(std::move(handle));
            }
            // Counted before the write rather than after it: a mailbox holds one
            // of these per correspondent, so anything near the cap is a client
            // that has stopped keeping track, and letting it write first would
            // be letting it past the cap.
            if (store.passCount(user) + handles.size() > kMaxPassesPerMailbox) {
                throw std::invalid_argument("this mailbox holds too many delivery passes");
            }
            store.registerPasses(user, handles);
            return jsonResponse({{"ok", true}, {"held", store.passCount(user)}});
        }));

    // Taking a pass back. Exact - the account names what it issued - so this is
    // done here and answered with what it did, rather than queued for a sweep.
    // It is the only thing that stops a correspondent writing, so a client that
    // does not hear the answer must ask again.
    http_->post("/v1/messaging/passes/revoke",
        authenticated([&store, requireClient, clientUnregistered](
                          const bazarish::http::Request& request,
                          const std::string& user) -> bazarish::http::Response {
            if (requireClient(request, user).empty()) {
                return clientUnregistered();
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const nlohmann::json& asked = body.at("passes");
            if (asked.size() > kMaxPassesPerRequest) {
                throw std::invalid_argument("too many delivery passes in one request");
            }
            std::vector<Bytes> handles;
            for (const nlohmann::json& entry : asked) {
                handles.push_back(fromBase64(entry.get<std::string>()));
            }
            const std::size_t dropped = store.revokePasses(user, handles);
            bazarish::log::info(
                "revoked {} delivery pass(es) for {}", dropped, bazarish::log::redact(user));
            return jsonResponse({{"revoked", dropped}});
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

}

}  // namespace bazarish::server
