// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Descriptor.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Health.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <ctime>
#include <filesystem>
#include <optional>
#include <stdexcept>

namespace {

// What an operator may set from the panel. A captcha shorter than this is not a
// test at all, and one longer is a wall; a lifetime under a minute expires while
// the person is still typing. Ports are TCP's own range without 0, which means
// "any free port" and is never what someone typed on purpose.
constexpr int kMinCaptchaLength = 3;
constexpr int kMaxCaptchaLength = 12;
constexpr std::int64_t kMinCaptchaTtlSeconds = 60;
constexpr int kMinPort = 1;
constexpr int kMaxPort = 65535;

// The knobs an API built without a shared settings object runs on. The portal
// owns the words a login is signed under, so nothing here fills them in. Written
// field by field so a new setting cannot arrive here as a silent zero.
bazarish::service::NodeSettings::Values valuesFrom(
    const bazarish::service::AccountApiOptions& options)
{
    bazarish::service::NodeSettings::Values values;
    values.requireApproval
        = options.registration == bazarish::service::AccountApiOptions::Registration::eApproval;
    values.registrationMessage = options.registrationMessage;
    values.portalMessage = options.portalMessage;
    values.requireCaptcha = options.freeRegistrationCaptcha;
    values.portalLinks = options.portalLinks;
    values.defaultQuotaBytes = options.defaultQuotaBytes;
    return values;
}


using bazarish::Bytes;
using bazarish::ErrorCode;

namespace http = bazarish::http;

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

// The routes are written as "fill in the response"; the engine hands one back.
using Filler = std::function<void(const http::Request&, http::Response&)>;

http::Handler filled(Filler handler)
{
    return [handler = std::move(handler)](const http::Request& request) {
        http::Response response;
        handler(request, response);
        return response;
    };
}

Bytes bodyBytes(const http::Request& request)
{
    return Bytes(request.body.begin(), request.body.end());
}

void respondError(http::Response& response, const int status, const ErrorCode code,
    const std::string& message)
{
    response.status = status;
    response.contentType = "application/json";
    response.body = bazarish::makeErrorEnvelope(code, message).dump();
}

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

bazarish::auth::Headers collectAuthHeaders(const http::Request& request)
{
    bazarish::auth::Headers headers;
    for (const char* const name : {bazarish::auth::kHeaderKeys,
             bazarish::auth::kHeaderTimestamp, bazarish::auth::kHeaderSignatureClassical,
             bazarish::auth::kHeaderSignaturePq}) {
        if (request.hasHeader(name)) {
            headers[name] = request.header(name);
        }
    }
    return headers;
}

// How many accounts a listing answers with when the caller names no limit.
constexpr std::size_t kDefaultUserPageSize = 50;

// What a banned key is told when the operator left the reason empty.
const char* const kDefaultBanReason = "Banned";

std::string lowercased(std::string text)
{
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return text;
}

std::size_t parsedCount(const std::string& text, const std::size_t fallback)
{
    if (text.empty()) {
        return fallback;
    }
    try {
        return static_cast<std::size_t>(std::stoull(text));
    } catch (const std::exception&) {
        throw std::invalid_argument("not a number: " + text);
    }
}

// When the node will drop this account if nothing changes. One rule covers every
// case: an account lives while it keeps a destination delegated here, so the
// clock runs from the last delegation - or from registration, for one that never
// delegated at all (a portal registration no client redeemed, or an account
// still waiting for an operator).
std::int64_t sweepDeadline(
    const std::int64_t idleSince, const bazarish::service::NodeSettings::Values& settings)
{
    constexpr std::int64_t kSecondsPerDay = 24 * 3600;
    if (settings.idleDeleteDays <= 0 || idleSince == 0) {
        return 0;  // the operator keeps them forever
    }
    return idleSince + settings.idleDeleteDays * kSecondsPerDay;
}

// What a waiting account's owner is told: the operator's own words for this
// account when they wrote any, and the node-wide registration message otherwise.
std::string holdMessageFor(const std::optional<bazarish::service::GrantStore::Approval>& approval,
    const bazarish::service::NodeSettings::Values& settings)
{
    if (approval.has_value() && !approval->message.empty()) {
        return approval->message;
    }
    return settings.registrationMessage;
}

}  // namespace

namespace bazarish::service {

AccountApi::AccountApi(
    SubscriptionStore& store, GrantStore& grants, const AccountApiOptions options)
    // Without a shared settings object (tests) the options are the settings, and
    // a change to them has nowhere to be written: an empty config path says so
    // by refusing the write rather than dropping it.
    : settings_(options.settings
              ? options.settings
              : std::make_shared<NodeSettings>(std::filesystem::path(), valuesFrom(options)))
    , store_(store)
    , grants_(grants)
    , options_(options)
    , startedAt_(nowSeconds())
{
}

AccountApi::~AccountApi() = default;

bool AccountApi::listen(const std::string& host, const int port)
{
    if (bindToAnyPort(host, port) <= 0) {
        return false;
    }
    return listenAfterBind();
}

int AccountApi::bindToAnyPort(const std::string& host)
{
    return bindToAnyPort(host, 0);  // 0: the kernel picks the port
}

int AccountApi::bindToAnyPort(const std::string& host, const int port)
{
    http::Server::Options options;
    options.host = host;
    options.port = port;
    http_ = std::make_unique<http::Server>(options);
    setupRoutes();
    try {
        return http_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

bool AccountApi::listenAfterBind()
{
    // The engine serves on its own threads; this call is what keeps the caller's
    // thread (a main()) parked until stop().
    std::unique_lock<std::mutex> lock(stopMutex_);
    stopCv_.wait(lock, [this]() { return stopping_; });
    return true;
}

void AccountApi::stop()
{
    if (http_) {
        http_->stop();
    }
    {
        const std::lock_guard<std::mutex> lock(stopMutex_);
        stopping_ = true;
    }
    stopCv_.notify_all();
}

void AccountApi::revokeDestination(const std::string& user)
{
    if (options_.publishI2pTransient) {
        options_.publishI2pTransient(user, std::string(), 0);
    }
    grants_.setI2pTransient(user, 0, nowSeconds());
}

void AccountApi::deleteAccount(const std::string& user)
{
    if (!grants_.peekApproval(user).has_value() && !store_.getAccount(user).has_value()) {
        // Nothing here to end: an operator got there first, or this key never had
        // an account. Answered like a deletion all the same - the caller must be
        // able to finish, or it is left holding a profile it can never clean up -
        // but there is no destination to revoke and no mailbox to drop.
        return;
    }
    revokeDestination(user);
    // The mail is the messaging server's, so it has to be told separately. Told
    // before the local record goes: while the record is here the deletion can be
    // asked for again, and after it there is nothing left to ask with.
    if (options_.forgetMailbox && !options_.forgetMailbox(user)) {
        bazarish::log::warn("mailbox of {} was not dropped: the messaging server refused it",
            log::redact(user));
    }
    store_.deleteAccount(user);
    grants_.erase(user);
}

// The address an account is served at. It is cached beside the card, but a
// record written before the user published routing carries none - the card
// answers, and the record is repaired on the way out.
std::string AccountApi::destinationOf(const std::optional<SubscriptionStore::Account>& held)
{
    if (!held.has_value() || !held->dest.empty() || held->card.empty()) {
        return held.has_value() ? held->dest : std::string();
    }
    ContactCard card;
    try {
        card = ContactCard::verify(held->card);
    } catch (const std::exception& error) {
        // One unreadable record must not take the whole listing down with it.
        bazarish::log::warn("card of {} is unreadable: {}", log::redact(held->user),
            error.what());
        return {};
    }
    if (card.dest.empty()) {
        return {};
    }
    SubscriptionStore::Account repaired = *held;
    repaired.dest = card.dest;
    store_.putAccount(repaired);
    return card.dest;
}

nlohmann::json AccountApi::userRecord(
    const std::string& user, const std::optional<GrantStore::Approval>& approval)
{
    const std::optional<SubscriptionStore::Account> held = store_.getAccount(user);
    const std::optional<GrantStore::SubscriptionGrant> grant = grants_.peekSubscription(user);
    const std::optional<GrantStore::Transient> transient = grants_.peekTransient(user);
    const std::optional<GrantStore::Ban> ban = grants_.peekBan(user);
    const NodeSettings::Values values = settings();
    // The portal registers the account; a client redeems it later, or never. The
    // first date is the one an operator asks about when nothing else happened.
    const std::int64_t registeredAt = held.has_value() && held->registeredAt != 0
        ? held->registeredAt
        : (grant.has_value() ? grant->grantedAt
                             : (approval.has_value() ? approval->requestedAt : 0));
    // An account lives while it keeps a destination delegated here; the sweep
    // counts from the last delegation, or from registration when there never was
    // one.
    const std::int64_t idleSince
        = held.has_value() && held->delegatedAt != 0 ? held->delegatedAt : registeredAt;
    return {
        {"user", user},
        {"dest", destinationOf(held)},
        {"registeredAt", registeredAt},
        {"delegatedAt", held.has_value() ? held->delegatedAt : 0},
        {"sweepAt", sweepDeadline(idleSince, values)},
        {"banned", ban.has_value()},
        {"banReason", ban.has_value() ? ban->reason : std::string()},
        {"holdMessage", approval.has_value() ? approval->message : std::string()},
        {"quotaBytes",
            held.has_value() ? held->quotaBytes
                             : (grant.has_value() ? grant->quotaBytes
                                                 : settings().defaultQuotaBytes)},
        {"registered", held.has_value()},
        {"grantPending", grant.has_value()},
        {"approval",
            !approval.has_value() ? "none" : (approval->pending() ? "pending" : "approved")},
        {"requestedAt", approval.has_value() ? approval->requestedAt : 0},
        {"approvedAt", approval.has_value() ? approval->approvedAt : 0},
        {"transientExpires", transient.has_value() ? transient->expires : 0},
    };
}

void AccountApi::setupRoutes()
{
    // Authenticated liveness for the admin panel: service name, version, uptime
    // and resident memory. Operator-only (signed), so it leaks nothing to an
    // unauthenticated caller.
    http_->get("/healthz", filled([this](const http::Request& request, http::Response& response) {
        try {
            auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                request.path, Bytes(request.body.begin(), request.body.end()),
                options_.operatorFingerprints);
        } catch (const std::exception& error) {
            respondError(response, 403, ErrorCode::eDeliveryRejected, error.what());
            return;
        }
        response.contentType = "application/json";
        response.body
            = health::reportJson("service-node", options_.version, startedAt_, nowSeconds());
    }));

    const auto authenticated = [this](auto handler) {
        return [this, handler](const http::Request& request, http::Response& response) {
            std::string user;
            try {
                // The device the request speaks for is part of what it signed.
                user = auth::verifyRequest(collectAuthHeaders(request), nowSeconds(),
                    request.method, request.path, bodyBytes(request), replayCache_,
                    request.header("X-Bazarish-Client"));
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

    // Operator-only moderation surface for the admin panel, signed with the
    // panel identity exactly like /healthz.
    const auto operatorOnly = [this](auto handler) {
        return [this, handler](const http::Request& request, http::Response& response) {
            try {
                auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                    request.path, bodyBytes(request), options_.operatorFingerprints);
            } catch (const std::exception& error) {
                respondError(response, 403, ErrorCode::eDeliveryRejected, error.what());
                return;
            }
            try {
                handler(request, response);
            } catch (const nlohmann::json::exception& error) {
                respondError(response, 400, ErrorCode::eDeliveryRejected, error.what());
            } catch (const std::invalid_argument& error) {
                respondError(response, 400, ErrorCode::eDeliveryRejected, error.what());
            }
        };
    };

    // The operator's view of the accounts on this node: everything the panel
    // lists, searches and edits. The search runs here rather than in the browser -
    // a node with ten thousand accounts must not ship them all to filter five.
    http_->get("/v1/account/users",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const std::string query = lowercased(request.query("q"));
            const std::string state = request.query("state");
            const std::size_t limit = parsedCount(request.query("limit"), kDefaultUserPageSize);
            const std::size_t offset = parsedCount(request.query("offset"), 0);

            nlohmann::json users = nlohmann::json::array();
            std::size_t matched = 0;
            for (const std::string& user : grants_.allUsers()) {
                // An operator searches with whatever they were given: the key
                // fingerprint or the address it is served at.
                if (!query.empty()) {
                    const std::optional<SubscriptionStore::Account> held
                        = store_.getAccount(user);
                    const std::string dest = destinationOf(held);
                    const bool matches = lowercased(user).find(query) != std::string::npos
                        || lowercased(dest).find(query) != std::string::npos;
                    if (!matches) {
                        continue;
                    }
                }
                const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
                const bool pending = approval.has_value() && approval->pending();
                if ((state == "pending" && !pending)
                    || (state == "approved" && (!approval.has_value() || pending))) {
                    continue;
                }
                ++matched;
                if (matched <= offset || users.size() >= limit) {
                    continue;
                }
                users.push_back(userRecord(user, approval));
            }
            respondJson(response,
                {{"users", users}, {"total", matched}, {"limit", limit}, {"offset", offset}});
        })));

    // Takes an account out of service without taking it away: the destination is
    // revoked and the account goes back to waiting, with the operator's own words
    // in place of the node-wide message.
    http_->post("/v1/account/undelegate",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
            // A hold is the soft measure: the point of it is what the operator
            // says, so an empty one is a refusal, not a silent nothing.
            const std::string message = body.value("message", std::string());
            if (message.empty()) {
                throw std::invalid_argument("a hold needs a message for the account's owner");
            }
            if (!grants_.peekApproval(user).has_value()) {
                respondError(response, 404, ErrorCode::eDeliveryRejected, "no such account");
                return;
            }
            revokeDestination(user);
            grants_.hold(user, message, nowSeconds());
            respondJson(response, userRecord(user, grants_.peekApproval(user)));
        })));

    // Deletes the account outright: certificate, grants and destination. The key
    // may register again.
    http_->del("/v1/account/user",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            if (!grants_.peekApproval(user).has_value()
                && !store_.getAccount(user).has_value()) {
                respondError(response, 404, ErrorCode::eDeliveryRejected, "no such account");
                return;
            }
            deleteAccount(user);
            respondJson(response, {{"ok", true}});
        })));

    // The same, plus a refusal that outlives it: this key does not register here
    // again, and the reason is what its owner is shown when it tries.
    http_->post("/v1/account/ban",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
            const std::string reason = body.value("reason", std::string());
            deleteAccount(user);
            grants_.ban(user, reason.empty() ? std::string(kDefaultBanReason) : reason,
                nowSeconds());
            respondJson(response, userRecord(user, grants_.peekApproval(user)));
        })));

    http_->post("/v1/account/unban",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
            grants_.unban(user);
            respondJson(response, {{"ok", true}});
        })));

    // What an operator may change while the node runs, and the two totals that
    // say whether the numbers still fit: what has been promised to accounts, and
    // what is actually on disk (which the messaging server owns and answers).
    http_->get("/v1/account/settings",
        filled(operatorOnly([this](const http::Request&, http::Response& response) {
            const NodeSettings::Values values = settings();
            std::uint64_t allocated = 0;
            std::size_t accounts = 0;
            for (const std::string& user : grants_.allUsers()) {
                ++accounts;
                const std::optional<SubscriptionStore::Account> held
                    = store_.getAccount(user);
                const std::optional<GrantStore::SubscriptionGrant> grant
                    = grants_.peekSubscription(user);
                allocated += held.has_value() ? held->quotaBytes
                                              : (grant.has_value() ? grant->quotaBytes
                                                                   : values.defaultQuotaBytes);
            }
            respondJson(response,
                {
                    {"requireApproval", values.requireApproval},
                    {"registrationMessage", values.registrationMessage},
                    {"portalMessage", values.portalMessage},
                    {"loginConsumer",
                        {
                            {"name", values.loginConsumer.name},
                            {"place", values.loginConsumer.place},
                            {"role", values.loginConsumer.role},
                        }},
                    {"requireCaptcha", values.requireCaptcha},
                    {"facades", values.facades},
                    {"reseeds", values.reseeds},
                    {"descriptor",
                        encodeServerDescriptor(
                            {options_.serverFingerprint, values.facades, values.reseeds})},
                    {"portalLinks", values.portalLinks},
                    {"captchaLength", values.captchaLength},
                    {"captchaTtlSeconds", values.captchaTtlSeconds},
                    {"logLevel", values.logLevel},
                    {"listen", {{"host", values.listenHost}, {"port", values.listenPort}}},
                    {"portalListen",
                        {{"host", values.portalListenHost}, {"port", values.portalListenPort}}},
                    {"messaging",
                        {{"host", values.messagingHost}, {"port", values.messagingPort}}},
                    {"defaultQuotaBytes", values.defaultQuotaBytes},
                    {"idleDeleteDays", values.idleDeleteDays},
                    {"canRestart", static_cast<bool>(options_.requestRestart)},
                    {"accounts", accounts},
                    {"allocatedBytes", allocated},
                });
        })));

    http_->put("/v1/account/settings",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            NodeSettings::Values values = settings();
            if (body.contains("requireApproval")) {
                values.requireApproval = body.at("requireApproval").get<bool>();
            }
            if (body.contains("registrationMessage")) {
                values.registrationMessage
                    = body.at("registrationMessage").get<std::string>();
            }
            if (body.contains("portalMessage")) {
                values.portalMessage = body.at("portalMessage").get<std::string>();
            }
            if (body.contains("loginConsumer")) {
                const nlohmann::json& consumer = body.at("loginConsumer");
                LoginConsumer wanted;
                wanted.name = consumer.value("name", values.loginConsumer.name);
                wanted.place = consumer.value("place", values.loginConsumer.place);
                wanted.role = consumer.value("role", values.loginConsumer.role);
                try {
                    requireUsableConsumer(wanted);
                } catch (const std::exception& error) {
                    // The operator's own words, refused for the operator's own
                    // reason: a bad request, not a broken node.
                    throw std::invalid_argument(error.what());
                }
                values.loginConsumer = wanted;
            }
            if (body.contains("requireCaptcha")) {
                values.requireCaptcha = body.at("requireCaptcha").get<bool>();
            }
            if (body.contains("facades")) {
                std::vector<std::string> facades;
                for (const nlohmann::json& entry : body.at("facades")) {
                    std::string url = entry.get<std::string>();
                    if (url.empty()) {
                        continue;
                    }
                    // A facade is where clients talk to this server, and they talk
                    // over I2P and nothing else. A clearnet address here would be
                    // an address no client will ever use.
                    if (!bazarish::isI2pFacadeUrl(url)
                        && !bazarish::allowFacadeWithoutI2pForDevPurposes()) {
                        throw std::invalid_argument(
                            "a facade must be a .b32.i2p address: " + url);
                    }
                    facades.push_back(std::move(url));
                }
                if (facades.empty()) {
                    throw std::invalid_argument("a server with no facade cannot be reached");
                }
                values.facades = std::move(facades);
            }
            if (body.contains("reseeds")) {
                std::vector<std::string> reseeds;
                for (const nlohmann::json& entry : body.at("reseeds")) {
                    std::string url = entry.get<std::string>();
                    if (url.empty()) {
                        continue;
                    }
                    // A reseed is what a client asks BEFORE it has a router. An
                    // I2P address here could never be reached at that moment.
                    if (bazarish::isI2pFacadeUrl(url)
                        && !bazarish::allowFacadeWithoutI2pForDevPurposes()) {
                        throw std::invalid_argument(
                            "a reseed must not be a .b32.i2p address: " + url);
                    }
                    reseeds.push_back(std::move(url));
                }
                values.reseeds = std::move(reseeds);
            }
            if (body.contains("portalLinks")) {
                std::vector<std::string> links;
                for (const nlohmann::json& entry : body.at("portalLinks")) {
                    std::string link = entry.get<std::string>();
                    if (!link.empty()) {
                        links.push_back(std::move(link));
                    }
                }
                values.portalLinks = std::move(links);
            }
            if (body.contains("captchaLength")) {
                values.captchaLength = body.at("captchaLength").get<int>();
                if (values.captchaLength < kMinCaptchaLength
                    || values.captchaLength > kMaxCaptchaLength) {
                    throw std::invalid_argument("a captcha is between "
                        + std::to_string(kMinCaptchaLength) + " and "
                        + std::to_string(kMaxCaptchaLength) + " characters");
                }
            }
            if (body.contains("captchaTtlSeconds")) {
                values.captchaTtlSeconds = body.at("captchaTtlSeconds").get<std::int64_t>();
                if (values.captchaTtlSeconds < kMinCaptchaTtlSeconds) {
                    throw std::invalid_argument("a captcha nobody can read in time is a wall");
                }
            }
            if (body.contains("logLevel")) {
                const std::string level = body.at("logLevel").get<std::string>();
                const std::optional<bazarish::log::Level> parsed
                    = bazarish::log::levelFromString(level);
                if (!parsed.has_value()) {
                    throw std::invalid_argument("not a log level: " + level);
                }
                values.logLevel = level;
            }
            const auto readEndpoint = [&body](const std::string& key, std::string& host,
                                          int& port) {
                if (!body.contains(key)) {
                    return;
                }
                const nlohmann::json& endpoint = body.at(key);
                const std::string wantedHost = endpoint.value("host", host);
                const int wantedPort = endpoint.value("port", port);
                if (wantedHost.empty()) {
                    throw std::invalid_argument("a " + key + " address needs a host");
                }
                if (wantedPort < kMinPort || wantedPort > kMaxPort) {
                    throw std::invalid_argument("a port is between " + std::to_string(kMinPort)
                        + " and " + std::to_string(kMaxPort));
                }
                host = wantedHost;
                port = wantedPort;
            };
            readEndpoint("listen", values.listenHost, values.listenPort);
            readEndpoint("portalListen", values.portalListenHost, values.portalListenPort);
            readEndpoint("messaging", values.messagingHost, values.messagingPort);
            if (body.contains("idleDeleteDays")) {
                values.idleDeleteDays = body.at("idleDeleteDays").get<std::int64_t>();
                if (values.idleDeleteDays < 0) {
                    throw std::invalid_argument("a lifetime cannot be negative");
                }
            }
            if (body.contains("defaultQuotaBytes")) {
                values.defaultQuotaBytes = body.at("defaultQuotaBytes").get<std::uint64_t>();
                if (values.defaultQuotaBytes == 0) {
                    throw std::invalid_argument("a new account needs some storage");
                }
            }
            const std::string levelBefore = settings().logLevel;
            try {
                settings_->set(values);
            } catch (const std::exception& error) {
                // The operator asked for a change that cannot outlive a restart.
                // Saying so beats applying it and losing it later.
                respondError(response, 500, ErrorCode::eDeliveryRejected, error.what());
                return;
            }
            if (values.logLevel != levelBefore) {
                // The one startup value that is not one: a node can be made
                // talkative while it is running the problem being chased.
                if (const std::optional<bazarish::log::Level> level
                    = bazarish::log::levelFromString(values.logLevel);
                    level.has_value()) {
                    bazarish::log::setLevel(*level);
                }
            }
            respondJson(response,
                {
                    {"requireApproval", values.requireApproval},
                    {"registrationMessage", values.registrationMessage},
                    {"defaultQuotaBytes", values.defaultQuotaBytes},
                    {"idleDeleteDays", values.idleDeleteDays},
                });
        })));

    // Restarting is the other half of editing a startup setting from a browser:
    // without it an operator still opens a terminal to make the change they just
    // saved take effect. The node stops cleanly and its service manager starts
    // it again.
    http_->post("/v1/account/restart",
        filled(operatorOnly([this](const http::Request&, http::Response& response) {
            if (!options_.requestRestart) {
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "this node cannot restart itself: it was started without a supervisor");
                return;
            }
            bazarish::log::info("restarting at the operator's request");
            options_.requestRestart();
            respondJson(response, {{"restarting", true}});
        })));

    // One account in full, for the card the operator opens.
    http_->get("/v1/account/user",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            if (!approval.has_value() && !store_.getAccount(user).has_value()) {
                respondError(response, 404, ErrorCode::eDeliveryRejected, "no such account");
                return;
            }
            respondJson(response, userRecord(user, approval));
        })));

    // The quota is this node's to set: it grants it, stores it and pushes it to
    // the messaging server, which would otherwise keep serving its own default.
    http_->put("/v1/account/quota",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
            const auto quotaBytes = body.at("quotaBytes").get<std::uint64_t>();
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            const std::optional<SubscriptionStore::Account> held
                = store_.getAccount(user);
            if (!approval.has_value() && !held.has_value()) {
                respondError(response, 404, ErrorCode::eDeliveryRejected, "no such account");
                return;
            }
            if (held.has_value()) {
                SubscriptionStore::Account updated = *held;
                updated.quotaBytes = quotaBytes;
                store_.putAccount(updated);
            }
            // A grant not yet redeemed carries the quota the certificate will be
            // checked against, so it has to move with it.
            if (const std::optional<GrantStore::SubscriptionGrant> grant
                = grants_.peekSubscription(user);
                grant.has_value()) {
                grants_.grantSubscription(user, quotaBytes, grant->grantedAt);
            }
            if (options_.publishQuota) {
                options_.publishQuota(user, quotaBytes);
            }
            respondJson(response, userRecord(user, approval));
        })));

    http_->post("/v1/account/approve",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
            if (!grants_.peekApproval(user).has_value()) {
                respondError(response, 404, ErrorCode::eDeliveryRejected, "no such account");
                return;
            }
            grants_.approve(user, nowSeconds());
            respondJson(response, {{"ok", true}});
        })));

    // Takes the user's signed contact card: the routing their contacts fetch.
    // This is also what turns a portal registration into an account - the first
    // authenticated call redeems the grant - and it can be repeated whenever the
    // routing changes. There is no term: an account lives while its owner keeps
    // a destination delegated here.
    http_->post("/v1/account/card",
        filled(authenticated([this](const http::Request& request, http::Response& response,
                          const std::string& user) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const Bytes der = fromBase64(body.at("card").get<std::string>());

            ContactCard card;
            try {
                card = ContactCard::verify(der);
            } catch (const std::exception& error) {
                respondError(response, 400, ErrorCode::eDeliveryRejected,
                    std::string("invalid contact card: ") + error.what());
                return;
            }
            if (card.user != user) {
                respondError(response, 403, ErrorCode::eDeliveryRejected,
                    "card does not name the authenticated user");
                return;
            }
            if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(user);
                ban.has_value()) {
                respondError(response, 403, ErrorCode::eDeliveryRejected, ban->reason);
                return;
            }

            const std::int64_t now = nowSeconds();
            const std::optional<GrantStore::SubscriptionGrant> grant
                = grants_.peekSubscription(user);
            const std::optional<SubscriptionStore::Account> held = store_.getAccount(user);
            std::uint64_t quota = 0;
            if (grant.has_value()) {
                grants_.takeSubscription(user);  // consume the one-shot grant
                quota = grant->quotaBytes;
            } else if (held.has_value()) {
                quota = held->quotaBytes;  // re-publishing routing grants nothing
            } else {
                respondError(response, 403, ErrorCode::eDeliveryRejected,
                    "no pending registration - register on the service portal first");
                return;
            }

            SubscriptionStore::Account record;
            record.user = user;
            record.registeredAt
                = held.has_value() && held->registeredAt != 0 ? held->registeredAt : now;
            record.quotaBytes = quota;
            // Registration publishes a card before there is anywhere to be
            // reached: it carries no destination, and taking that as "the address
            // is gone" wiped an address the account had been serving at - which is
            // what the panel then reported. Only a card that names one replaces it;
            // giving the address up is the revoke, which says so.
            record.dest = card.dest.empty() && held.has_value() ? held->dest : card.dest;
            record.delegatedAt = held.has_value() ? held->delegatedAt : 0;
            // Issued once and kept: a descriptor already shared must keep
            // working, and the client puts this in every invite it makes.
            record.view = held.has_value() && !held->view.empty()
                ? held->view
                : toHex(randomBytes(kViewCapabilityBytes));
            record.card = der;
            store_.putAccount(record);
            // The granted quota is this node's to set: push it so the messaging
            // server serves the number the portal promised, not its own default.
            if (options_.publishQuota) {
                options_.publishQuota(user, quota);
            }

            // On an open server the account is servable at once; on a moderated
            // one this only starts the approval clock. Re-publishing keeps the
            // original request time, so a pending account cannot outlive its
            // deadline by publishing again.
            grants_.recordRegistration(user, now, !settings().requireApproval);
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            const bool pending = approval.has_value() && approval->pending();

            respondJson(response,
                {
                    {"quotaBytes", quota},
                    {"view", record.view},
                    {"serverCard", toBase64(options_.serverCardDer)},
                    {"approval", pending ? "pending" : "approved"},
                    {"registrationMessage",
                        pending ? holdMessageFor(approval, settings()) : std::string()},
                });
        })));

    // Closing an account tears it down, it does not merely stop delegating: the
    // destination is revoked and the grants (including the approval) are
    // dropped, so nothing about the account outlives it. Coming back means
    // registering again.
    http_->del("/v1/account/registration",
        filled(authenticated([this](const http::Request&, http::Response& response,
                          const std::string& user) {
            deleteAccount(user);
            respondJson(response, {{"ok", true}});
        })));

    // Receives the user's client-owned offline I2P transient and hands it to the
    // messaging server, which operates the user's own destination. Every account
    // has one - it is the base protocol, not a purchase - but a moderated server
    // withholds it until an operator approves the account, which is what "frozen"
    // means: the account exists and the transient is accepted nowhere. An empty
    // transient revokes the destination. The transient's validity is recorded so
    // the status endpoint can tell the client's other devices when to re-issue.
    http_->post("/v1/account/i2p-dest",
        filled(authenticated([this](const http::Request& request, http::Response& response,
                          const std::string& user) {
            if (!options_.publishI2pTransient) {
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "per-user destinations not available");
                return;
            }
            const std::int64_t now = nowSeconds();
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            if (!approval.has_value()) {
                respondError(response, 403, ErrorCode::eDeliveryRejected,
                    "no account on this server - subscribe first");
                return;
            }
            if (approval->pending()) {
                respondError(response, 403, ErrorCode::eAccountPendingApproval,
                    settings().registrationMessage.empty()
                        ? "account is awaiting operator approval"
                        : settings().registrationMessage);
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string transient = body.value("transient", std::string());
            const std::int64_t expiresUnix
                = transient.empty() ? 0 : body.at("expiresUnix").get<std::int64_t>();
            // The ceiling is the protocol's: a server that could hold a longer
            // delegation than this would keep operating someone's address after
            // they decided to leave.
            constexpr std::int64_t kSecondsPerDay = 24 * 3600;
            if (expiresUnix > now + kMaxDelegationDays * kSecondsPerDay) {
                respondError(response, 400, ErrorCode::eDeliveryRejected,
                    "a delegation may run at most " + std::to_string(kMaxDelegationDays)
                        + " days");
                return;
            }
            if (!options_.publishI2pTransient(user, transient, expiresUnix)) {
                // Recording it here would make i2p-status report a destination the
                // messaging server never raised: published to the user, dark to
                // everyone else.
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "the messaging server did not accept the delegation");
                return;
            }
            grants_.setI2pTransient(user, expiresUnix, now);
            // Giving the address up is said here, and nowhere else: the account
            // record stops naming one, so the panel and the sweep both read the
            // same thing.
            if (transient.empty()) {
                if (const std::optional<SubscriptionStore::Account> held
                    = store_.getAccount(user);
                    held.has_value() && !held->dest.empty()) {
                    SubscriptionStore::Account record = *held;
                    record.dest.clear();
                    store_.putAccount(record);
                }
            }
            respondJson(response, {{"ok", true}});
        })));

    // What the client's devices need to keep the user's destination alive: the
    // approval state (a frozen account has no destination) and the validity of
    // the transient currently delegated, so any device knows when to issue the
    // next one without holding it.
    http_->get("/v1/account/i2p-status",
        filled(authenticated([this](const http::Request&, http::Response& response,
                          const std::string& user) {
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            const std::optional<GrantStore::Transient> transient = grants_.peekTransient(user);
            respondJson(response,
                {
                    {"approval",
                        !approval.has_value() ? "none"
                                              : (approval->pending() ? "pending" : "approved")},
                    {"registrationMessage",
                        approval.has_value() && approval->pending()
                            ? holdMessageFor(approval, settings())
                                                                    : std::string()},
                    {"transientExpires", transient.has_value() ? transient->expires : 0},
                    {"transientUpdatedAt", transient.has_value() ? transient->updatedAt : 0},
                });
        })));

    // The contact card a peer fetches, answered only to someone who already
    // holds the descriptor: the query carries its `key` - the per-user serving
    // key this node handed out - and a wrong key is refused exactly like an
    // unknown user. Without that, asking by fingerprint would tell anyone which
    // server hosts whom.
    //
    // Reached from the messaging server, which unseals the peer's query on the
    // user's own destination; nothing about this answer names the server.
    // Rotating the serving key and the view together. Two calls, because the
    // switch has to be the user's: this node prepares, the user signs the
    // prepared key into a card, and only the commit puts either in force. A
    // rotation that stops halfway leaves the account exactly as it was.
    http_->post("/v1/account/serving-key",
        filled(authenticated([this](const http::Request& request, http::Response& response,
                          const std::string& user) {
            (void)request;
            const std::optional<SubscriptionStore::Account> held = store_.getAccount(user);
            if (!held.has_value()) {
                respondError(response, 403, ErrorCode::eDeliveryRejected, "no account here");
                return;
            }
            if (!options_.prepareServingKey) {
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "the messaging server cannot rotate serving keys");
                return;
            }
            const std::optional<std::string> prepared = options_.prepareServingKey(user);
            if (!prepared.has_value()) {
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "the messaging server did not prepare a key");
                return;
            }
            SubscriptionStore::Account record = *held;
            record.pendingServingKey = *prepared;
            record.pendingView = toHex(randomBytes(kViewCapabilityBytes));
            store_.putAccount(record);
            respondJson(response,
                {{"servingKey", record.pendingServingKey}, {"view", record.pendingView}});
        })));

    http_->post("/v1/account/serving-key/commit",
        filled(authenticated([this](const http::Request& request, http::Response& response,
                          const std::string& user) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::optional<SubscriptionStore::Account> held = store_.getAccount(user);
            if (!held.has_value() || held->pendingServingKey.empty()) {
                respondError(response, 409, ErrorCode::eDeliveryRejected,
                    "no rotation is in progress");
                return;
            }
            const Bytes der = fromBase64(body.at("card").get<std::string>());
            ContactCard card;
            try {
                card = ContactCard::verify(der);
            } catch (const std::exception& error) {
                respondError(response, 400, ErrorCode::eDeliveryRejected,
                    std::string("invalid contact card: ") + error.what());
                return;
            }
            if (card.user != user) {
                respondError(response, 403, ErrorCode::eDeliveryRejected,
                    "card does not name the authenticated user");
                return;
            }
            // The card has to carry the key that was prepared, or the commit would
            // put a key into force that nobody can read the card for.
            if (toBase64(card.servingSealingKeyDer) != held->pendingServingKey) {
                respondError(response, 400, ErrorCode::eDeliveryRejected,
                    "the card does not carry the prepared serving key");
                return;
            }
            // The card and the capability go in first: until the messaging server
            // commits, the old key still serves, so a card nobody can use yet is
            // harmless - while the reverse would refuse every contact.
            SubscriptionStore::Account record = *held;
            record.card = der;
            record.dest = card.dest;
            record.view = held->pendingView;
            record.pendingView.clear();
            record.pendingServingKey.clear();
            store_.putAccount(record);
            if (!options_.commitServingKey || !options_.commitServingKey(user)) {
                // Put back what was there: a stored card whose key never came into
                // force is a card that refuses every message sent to it.
                store_.putAccount(*held);
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "the messaging server did not take the new key - nothing was changed");
                return;
            }
            respondJson(response, {{"ok", true}, {"view", record.view}});
        })));

    http_->get("/v1/account/card",
        filled([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            const std::string view = request.query("view");
            std::optional<SubscriptionStore::Account> account;
            try {
                account = user.empty() ? std::nullopt : store_.getAccount(user);
            } catch (const std::exception& error) {
                // A record this node cannot read is one it cannot serve a card
                // from, and it must look exactly like every other miss: any
                // answer that stands out turns this into the enumeration oracle
                // the key check exists to close.
                bazarish::log::warn("account record of {} is unreadable: {}", log::redact(user),
                    error.what());
            }
            // The capability is compared against the one stored beside the card,
            // and nothing is verified before it matches: work that only happens
            // for a user this node has would answer the question by how long it
            // took.
            const bool known = account.has_value() && !account->card.empty()
                && !account->view.empty() && account->view == view;
            if (!known) {
                // One answer for "not here" and "that is not the key I issued",
                // so nothing is learnt by asking. A caller holding a descriptor
                // that no longer matches learns exactly what is true: it is out
                // of date.
                respondError(response, 404, ErrorCode::eClientUnregistered,
                    "that descriptor is out of date");
                return;
            }
            respondJson(response, {{"user", user}, {"card", toBase64(account->card)}});
        }));

    // Registering without a page to visit. Only when the operator asks for no
    // captcha: a captcha is a person's proof that they are one, and a client
    // cannot stand in for it. The account is granted exactly what the portal
    // grants, approval included, so the two doors lead to the same place.
    http_->post("/v1/account/registration",
        filled(authenticated([this](const http::Request&, http::Response& response,
                          const std::string& user) {
            if (settings().requireCaptcha) {
                respondError(response, 403, ErrorCode::eDeliveryRejected,
                    "this server registers on its portal");
                return;
            }
            if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(user);
                ban.has_value()) {
                respondError(response, 403, ErrorCode::eDeliveryRejected, ban->reason);
                return;
            }
            const NodeSettings::Values values = settings();
            const std::int64_t now = nowSeconds();
            // Exactly what the portal's register button does, so an account that
            // came this way is indistinguishable from one that came that way.
            if (!store_.getAccount(user).has_value()
                && !grants_.peekSubscription(user).has_value()) {
                grants_.grantSubscription(user, values.defaultQuotaBytes, now);
            }
            respondJson(response,
                {{"ok", true}, {"quotaBytes", values.defaultQuotaBytes},
                    {"requiresApproval", values.requireApproval},
                    {"message", values.requireApproval ? values.registrationMessage
                                                       : std::string()}});
        })));

    // Onboarding discovery: where to register and on what terms. Unauthenticated
    // - the client shows the message and link(s); registration happens on the
    // portal, not here. Nothing on this node is for sale, so there is no service
    // catalogue: the only variables are whether a captcha is required and
    // whether an operator has to approve the account.
    http_->get("/v1/account/portal", filled([this](const http::Request&, http::Response& response) {
            const NodeSettings::Values live = settings();
            nlohmann::json links = nlohmann::json::array();
            for (const std::string& link :
                live.portalLinks.empty() ? options_.portalLinks : live.portalLinks) {
                links.push_back(link);
            }
            respondJson(response,
                {
                    {"message", settings().portalMessage.empty() ? options_.portalMessage
                                                                : settings().portalMessage},
                    {"links", links},
                    {"registration",
                        {
                            {"captcha", settings().requireCaptcha},
                            {"requiresApproval",
                                settings().requireApproval},
                            {"message", settings().registrationMessage},
                        }},
                    {"quotaBytes", settings().defaultQuotaBytes},
                });
        }));
}

}  // namespace bazarish::service
