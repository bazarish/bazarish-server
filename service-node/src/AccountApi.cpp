// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include <FleetRoutes.hpp>
#include <Health.hpp>
#include <LoginRelay.hpp>
#include <OpsGate.hpp>

#include "AccountRemoval.hpp"
#include "IdleSweep.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/HttpResponses.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PlainText.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/Tunnel.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <stdexcept>

namespace {

using bazarish::Bytes;
using bazarish::ErrorCode;

namespace http = bazarish::http;

using bazarish::nowSeconds;
using bazarish::http::filled;

constexpr std::string_view kSchemeEnd = "://";

// The client puts the slash back where it needs one, so a URL is kept without it.
std::string withoutTrailingSlash(std::string url)
{
    const std::size_t scheme = url.find(kSchemeEnd);
    const std::size_t floor = scheme == std::string::npos ? 0 : scheme + kSchemeEnd.size();
    while (url.size() > floor && url.back() == '/') {
        url.pop_back();
    }
    return url;
}

void addOnce(std::vector<std::string>& list, const std::string& url)
{
    if (std::find(list.begin(), list.end(), url) == list.end()) {
        list.push_back(url);
    }
}

std::vector<std::string> normalizedUrls(const std::vector<std::string>& urls)
{
    std::vector<std::string> out;
    for (const std::string& url : urls) {
        if (!url.empty()) {
            addOnce(out, withoutTrailingSlash(url));
        }
    }
    return out;
}

std::string loginStateName(const bazarish::service::LoginMailbox::State state)
{
    switch (state) {
    case bazarish::service::LoginMailbox::State::eWaiting:
        return "waiting";
    case bazarish::service::LoginMailbox::State::eSigned:
        return "signed";
    case bazarish::service::LoginMailbox::State::eGone:
        return "gone";
    }
    throw std::logic_error("an unknown login state");
}

Bytes bodyBytes(const http::Request& request)
{
    return Bytes(request.body.begin(), request.body.end());
}

void respondError(http::Response& response, const int status, const ErrorCode code,
    const std::string& message)
{
    response = http::errorResponse(status, code, message);
}

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

using bazarish::http::collectAuthHeaders;

constexpr std::size_t kDefaultUserPageSize = 50;
constexpr std::size_t kMaxUserPageSize = 500;

const char* const kDefaultBanReason = "Banned";

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

std::int64_t sweepDeadline(
    const std::int64_t idleSince, const bazarish::service::NodeSettings::Values& settings)
{
    if (settings.idleDeleteDays <= 0 || idleSince == 0) {
        return 0;
    }
    return idleSince + settings.idleDeleteDays * bazarish::kSecondsPerDay;
}

const char* approvalState(
    const std::optional<bazarish::service::GrantStore::Approval>& approval)
{
    if (!approval.has_value()) {
        return "none";
    }
    return approval->pending() ? "pending" : "approved";
}

std::string holdMessageFor(const std::optional<bazarish::service::GrantStore::Approval>& approval,
    const bazarish::service::NodeSettings::Values& settings)
{
    if (approval.has_value() && !approval->message.empty()) {
        return approval->message;
    }
    return settings.registrationMessage;
}

void editSettings(const nlohmann::json& body, bazarish::service::NodeSettings::Values& values)
{
    if (body.contains("requireApproval")) {
        values.requireApproval = body.at("requireApproval").get<bool>();
    }
    if (body.contains("registrationMessage")) {
        values.registrationMessage
            = body.at("registrationMessage").get<std::string>();
    }
    if (body.contains("loginConsumer")) {
        const nlohmann::json& consumer = body.at("loginConsumer");
        bazarish::service::LoginConsumer wanted;
        wanted.name = consumer.value("name", values.loginConsumer.name);
        wanted.place
            = normalizedUrls(consumer.value("place", values.loginConsumer.place));
        wanted.role = consumer.value("role", values.loginConsumer.role);
        try {
            bazarish::service::requireUsableConsumer(wanted);
        } catch (const std::exception& error) {
            throw std::invalid_argument(error.what());
        }
        values.loginConsumer = wanted;
    }
    if (body.contains("facades")) {
        std::vector<std::string> facades;
        for (const nlohmann::json& entry : body.at("facades")) {
            std::string address = entry.get<std::string>();
            if (address.empty()) {
                continue;
            }
            if (address.find('/') != std::string::npos) {
                throw std::invalid_argument(
                    "a facade is an address, with no scheme and no path");
            }
            if (!bazarish::isI2pFacadeAddress(address)
                && !bazarish::allowFacadeWithoutI2pForDevPurposes()) {
                throw std::invalid_argument(
                    "a facade must be a .b32.i2p address: " + address);
            }
            facades.push_back(std::move(address));
        }
        if (facades.empty()) {
            throw std::invalid_argument("a server with no facade cannot be reached");
        }
        values.facades = std::move(facades);
    }
    if (body.contains("reseeds")) {
        std::vector<std::string> reseeds;
        for (const nlohmann::json& entry : body.at("reseeds")) {
            const std::string url = withoutTrailingSlash(entry.get<std::string>());
            if (url.empty()) {
                continue;
            }
            if (!bazarish::i2p::isReseedUrl(url)) {
                throw std::invalid_argument("a reseed is an https URL: " + url);
            }
            if (bazarish::isI2pUrl(url) && !bazarish::allowFacadeWithoutI2pForDevPurposes()) {
                throw std::invalid_argument(
                    "a reseed must not be a .b32.i2p address: " + url);
            }
            addOnce(reseeds, url);
        }
        values.reseeds = std::move(reseeds);
    }
    if (body.contains("portalLinks")) {
        values.portalLinks
            = normalizedUrls(body.at("portalLinks").get<std::vector<std::string>>());
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
    bazarish::readEndpointInto(body, "listen", values.listenHost, values.listenPort);
    bazarish::readEndpointInto(
        body, "portalListen", values.portalListenHost, values.portalListenPort);
    bazarish::readEndpointInto(body, "messaging", values.messagingHost, values.messagingPort);
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
}

}  // namespace

namespace bazarish::service {

AccountApi::AccountApi(
    SubscriptionStore& store, GrantStore& grants, const AccountApiOptions options)
    : settings_(options.settings)
    , store_(store)
    , grants_(grants)
    , options_(options)
    , startedAt_(nowSeconds())
    , tunnel_(options_.sealingKey)
{
    if (!options_.publishQuota || !options_.publishCardChanged) {
        throw std::invalid_argument("the node tells its messaging server of every quota and card");
    }
}

AccountApi::~AccountApi() = default;

int AccountApi::bind(const std::string& host, const int port)
{
    http::Server::Options options;
    options.host = host;
    options.port = port;
    options.certificate = options_.tlsCertificate;
    options.key = options_.tlsKey;
    http_ = std::make_unique<http::Server>(options);
    setupRoutes();
    try {
        return http_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

int AccountApi::bindOps(const std::string& host, const int port)
{
    http::Server::Options options;
    options.host = host;
    options.port = port;
    options.threads = 1;
    options.certificate = options_.tlsCertificate;
    options.key = options_.tlsKey;
    options.clientPins = options_.opsClientPins;
    ops_ = std::make_unique<http::Server>(options);
    setupOpsRoutes();
    try {
        return ops_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

void AccountApi::wait()
{
    stopGate_.wait();
}

void AccountApi::stop()
{
    stopGate_.stop();
    if (http_) {
        http_->stop();
    }
    if (ops_) {
        ops_->stop();
    }
}

void AccountApi::revokeDestination(const std::string& user)
{
    if (options_.publishI2pTransient) {
        options_.publishI2pTransient(user, std::string(), 0, {});
    }
    grants_.setI2pTransient(user, 0);
}

void AccountApi::deleteAccount(const std::string& user)
{
    if (!grants_.peekApproval(user).has_value() && !store_.getAccount(user).has_value()) {
        return;
    }
    removeAccount(user, store_, grants_,
        [this](const std::string& gone) {
            return options_.publishI2pTransient(gone, std::string(), 0, {}).has_value();
        },
        options_.forgetMailbox);
}

nlohmann::json AccountApi::userRecord(
    const std::string& user, const std::optional<GrantStore::Approval>& approval)
{
    const std::optional<SubscriptionStore::Account> held = store_.getAccount(user);
    const std::optional<GrantStore::SubscriptionGrant> grant = grants_.peekSubscription(user);
    const std::optional<GrantStore::Transient> transient = grants_.peekTransient(user);
    const std::optional<GrantStore::Ban> ban = grants_.peekBan(user);
    const NodeSettings::Values values = settings();
    const std::int64_t registeredAt = held.has_value() && held->registeredAt != 0
        ? held->registeredAt
        : (grant.has_value() ? grant->grantedAt
                             : (approval.has_value() ? approval->requestedAt : 0));
    const std::int64_t idleFrom = idleSince(held, grants_, user);
    return {
        {"user", user},
        {"dest", held.has_value() ? held->dest : std::string()},
        {"registeredAt", registeredAt},
        {"delegatedAt", held.has_value() ? held->delegatedAt : 0},
        {"sweepAt", sweepDeadline(idleFrom, values)},
        {"banned", ban.has_value()},
        {"banReason", ban.has_value() ? ban->reason : std::string()},
        {"holdMessage", approval.has_value() ? approval->message : std::string()},
        {"heldUntil", approval.has_value() ? approval->heldUntil : 0},
        {"quotaBytes",
            held.has_value() ? held->quotaBytes
                             : (grant.has_value() ? grant->quotaBytes
                                                 : values.defaultQuotaBytes)},
        {"registered", held.has_value()},
        {"grantPending", grant.has_value()},
        {"approval", approvalState(approval)},
        {"requestedAt", approval.has_value() ? approval->requestedAt : 0},
        {"approvedAt", approval.has_value() ? approval->approvedAt : 0},
        {"transientExpires", transient.has_value() ? transient->expires : 0},
    };
}

void AccountApi::setupOpsRoutes()
{
    const auto operatorOnly = [this](http::Filler handler) {
        return server::operatorOnly(options_.operatorFingerprints, replayCache_, std::move(handler));
    };

    ops_->post(fleet::kLoginExpect,
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            if (!options_.logins->expect(body.at("challenge").get<std::string>(),
                    body.at("token").get<std::string>(),
                    linkKeyFromText(body.at("key").get<std::string>()), nowSeconds())) {
                respondError(response, 503, ErrorCode::eRequestFailed,
                    "too many sign-ins are waiting");
                return;
            }
            respondJson(response, {{"ok", true}});
        })));

    ops_->post(fleet::kLoginClaim,
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const LoginMailbox::Claim claim = options_.logins->claim(
                body.at("nonce").get<std::string>(), body.at("token").get<std::string>(),
                nowSeconds());
            respondJson(response,
                {
                    {"state", loginStateName(claim.state)},
                    {"challenge", claim.challenge},
                    {"blob", claim.blob},
                });
        })));

    ops_->get("/healthz",
        filled(operatorOnly([this](const http::Request&, http::Response& response) {
            response.contentType = "application/json";
            response.body
                = health::reportJson("service-node", options_.version, startedAt_, nowSeconds());
        })));

    ops_->get("/v1/account/users",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const std::string query = asciiLower(request.query("q"));
            const std::string state = request.query("state");
            const std::size_t limit
                = std::min(parsedCount(request.query("limit"), kDefaultUserPageSize),
                    kMaxUserPageSize);
            const std::size_t offset = parsedCount(request.query("offset"), 0);

            nlohmann::json users = nlohmann::json::array();
            std::size_t matched = 0;
            for (const std::string& user : grants_.allUsers()) {
                if (!query.empty()) {
                    const std::optional<SubscriptionStore::Account> held
                        = store_.getAccount(user);
                    const std::string dest = held.has_value() ? held->dest : std::string();
                    const bool matches = asciiLower(user).find(query) != std::string::npos
                        || asciiLower(dest).find(query) != std::string::npos;
                    if (!matches) {
                        continue;
                    }
                }
                const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
                const bool pending = approval.has_value() && approval->pending();
                if (state == "banned" && !grants_.peekBan(user).has_value()) {
                    continue;
                }
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

    ops_->post(fleet::kAccountUndelegate,
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const std::string user = body.at("user").get<std::string>();
            const std::string message = body.value("message", std::string());
            if (message.empty()) {
                throw std::invalid_argument("a hold needs a message for the account's owner");
            }
            const UserLocks::Held locked = options_.userLocks->hold(user);
            if (!grants_.peekApproval(user).has_value()) {
                respondError(response, 404, ErrorCode::eAccountUnknown, "no such account");
                return;
            }
            const std::optional<GrantStore::Transient> transient = grants_.peekTransient(user);
            revokeDestination(user);
            grants_.hold(user, message, nowSeconds(), transient.has_value() ? transient->expires : 0);
            respondJson(response, userRecord(user, grants_.peekApproval(user)));
        })));

    ops_->del("/v1/account/user",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            const UserLocks::Held locked = options_.userLocks->hold(user);
            if (!grants_.peekApproval(user).has_value()
                && !store_.getAccount(user).has_value()) {
                respondError(response, 404, ErrorCode::eAccountUnknown, "no such account");
                return;
            }
            deleteAccount(user);
            respondJson(response, {{"ok", true}});
        })));

    ops_->post(fleet::kAccountBan,
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const std::string user = body.at("user").get<std::string>();
            const std::string reason = body.value("reason", std::string());
            const UserLocks::Held locked = options_.userLocks->hold(user);
            deleteAccount(user);
            grants_.ban(user, reason.empty() ? std::string(kDefaultBanReason) : reason);
            respondJson(response, userRecord(user, grants_.peekApproval(user)));
        })));

    ops_->post(fleet::kAccountUnban,
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const std::string user = body.at("user").get<std::string>();
            const UserLocks::Held locked = options_.userLocks->hold(user);
            grants_.unban(user);
            respondJson(response, {{"ok", true}});
        })));

    ops_->get(fleet::kAccountSettings,
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
                    {"loginConsumer",
                        {
                            {"name", values.loginConsumer.name},
                            {"place", values.loginConsumer.place},
                            {"role", values.loginConsumer.role},
                        }},
                    {"facades", values.facades},
                    {"reseeds", values.reseeds},
                    {"descriptor",
                        encodeServerDescriptor(
                            {options_.serverFingerprint, values.facades, values.reseeds})},
                    {"portalLinks", values.portalLinks},
                    {"logLevel", values.logLevel},
                    {"listen", {{"host", values.listenHost}, {"port", values.listenPort}}},
                    {"portalListen",
                        {{"host", values.portalListenHost}, {"port", values.portalListenPort}}},
                    {"messaging",
                        {{"host", values.messagingHost}, {"port", values.messagingPort}}},
                    {"defaultQuotaBytes", values.defaultQuotaBytes},
                    {"idleDeleteDays", values.idleDeleteDays},
                    {"accounts", accounts},
                    {"allocatedBytes", allocated},
                });
        })));

    ops_->put(fleet::kAccountSettings,
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            NodeSettings::Values probe = settings();
            editSettings(body, probe);
            std::string levelBefore;
            NodeSettings::Values values;
            try {
                values = settings_->update([&body, &levelBefore](NodeSettings::Values& edited) {
                    levelBefore = edited.logLevel;
                    editSettings(body, edited);
                });
            } catch (const std::exception& error) {
                respondError(response, 500, ErrorCode::eRequestFailed, error.what());
                return;
            }
            if (values.logLevel != levelBefore) {
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

    ops_->post(fleet::kAccountRestart,
        filled(operatorOnly([this](const http::Request&, http::Response& response) {
            bazarish::log::info("restarting at the operator's request");
            options_.requestRestart();
            respondJson(response, {{"restarting", true}});
        })));

    ops_->get("/v1/account/user",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            if (!approval.has_value() && !store_.getAccount(user).has_value()) {
                respondError(response, 404, ErrorCode::eAccountUnknown, "no such account");
                return;
            }
            respondJson(response, userRecord(user, approval));
        })));

    ops_->put(fleet::kAccountQuota,
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const std::string user = body.at("user").get<std::string>();
            const auto quotaBytes = body.at("quotaBytes").get<std::uint64_t>();
            const UserLocks::Held locked = options_.userLocks->hold(user);
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            const std::optional<SubscriptionStore::Account> held
                = store_.getAccount(user);
            if (!approval.has_value() && !held.has_value()) {
                respondError(response, 404, ErrorCode::eAccountUnknown, "no such account");
                return;
            }
            if (held.has_value()) {
                SubscriptionStore::Account updated = *held;
                updated.quotaBytes = quotaBytes;
                store_.putAccount(updated);
            }
            if (const std::optional<GrantStore::SubscriptionGrant> grant
                = grants_.peekSubscription(user);
                grant.has_value()) {
                grants_.grantSubscription(user, quotaBytes, grant->grantedAt);
            }
            options_.publishQuota(user, quotaBytes);
            respondJson(response, userRecord(user, approval));
        })));

    ops_->post(fleet::kAccountApprove,
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const std::string user = body.at("user").get<std::string>();
            const UserLocks::Held locked = options_.userLocks->hold(user);
            if (!grants_.peekApproval(user).has_value()) {
                respondError(response, 404, ErrorCode::eAccountUnknown, "no such account");
                return;
            }
            grants_.approve(user, nowSeconds());
            respondJson(response, {{"ok", true}});
        })));

}

void AccountApi::setupRoutes()
{
    http_->get(std::string(bazarish::tunnel::kNodeCardPath),
        filled([this](const http::Request&, http::Response& response) {
            response.contentType = "application/octet-stream";
            response.body
                = std::string(options_.nodeCardDer.begin(), options_.nodeCardDer.end());
        }));

    http_->post(loginrelay::kCallbackPath,
        filled([this](const http::Request& request, http::Response& response) {
            const std::int64_t now = nowSeconds();
            std::string nonce;
            try {
                nonce = loginAnswerNonce(request.body);
            } catch (const std::exception& error) {
                respondError(response, 400, ErrorCode::eRequestFailed,
                    std::string("a sealed answer expected: ") + error.what());
                return;
            }
            const std::optional<LoginMailbox::Held> held = options_.logins->held(nonce, now);
            if (!held.has_value()) {
                respondError(response, 404, ErrorCode::eRequestFailed,
                    "no sign-in waits for this challenge");
                return;
            }
            std::optional<LoginAnswer> answer;
            try {
                answer = openLoginAnswer(held->key, request.body);
                if (answer.has_value()) {
                    (void)verifyLoginBlob(answer->blob, now, answer->challenge);
                }
            } catch (const std::exception& error) {
                respondError(response, 403, ErrorCode::eRequestFailed, error.what());
                return;
            }
            if (!answer.has_value()) {
                respondError(response, 403, ErrorCode::eRequestFailed,
                    "the answer is sealed under another key");
                return;
            }
            const std::string& challenge = answer->challenge;
            const std::string& blob = answer->blob;
            if (!options_.logins->deliver(nonce, challenge, blob, now)) {
                respondError(response, 404, ErrorCode::eRequestFailed,
                    "no sign-in waits for this challenge");
                return;
            }
            respondJson(response, {{"ok", true}});
        }));

    http_->get(std::string(loginrelay::kChallengePrefix) + "{hex}",
        filled([this](const http::Request& request, http::Response& response) {
            const std::optional<LoginMailbox::Held> held
                = options_.logins->held(request.captures.at(0), nowSeconds());
            if (!held.has_value()) {
                respondError(response, 404, ErrorCode::eRequestFailed,
                    "no sign-in waits with this challenge");
                return;
            }
            const Bytes sealed = sealLoginChallenge(held->key, held->challenge);
            response.contentType = "application/octet-stream";
            response.body.assign(sealed.begin(), sealed.end());
        }));

    http_->routeAsync("POST", std::string(bazarish::tunnel::kNodeTunnelPath),
        [this](const http::Request& request,
            http::Responder respond) -> std::optional<http::Response> {
            tunnel_.serve(request, *http_, std::move(respond));
            return std::nullopt;
        });

    const auto authenticated = [this](auto handler) {
        return [this, handler](const http::Request& request, http::Response& response) {
            const server::Caller caller = tunnel_.authenticate(request);
            if (caller.refused.has_value()) {
                response = *caller.refused;
                return;
            }
            const std::string& user = caller.user;
            if (options_.admitsUser && !options_.admitsUser(user)) {
                respondError(response, 403, ErrorCode::eRequestFailed,
                    "this node serves only its own accounts");
                return;
            }
            const UserLocks::Held locked = options_.userLocks->hold(user);
            try {
                handler(request, response, user);
            } catch (const nlohmann::json::exception& error) {
                respondError(response, 400, ErrorCode::eRequestFailed, error.what());
            } catch (const std::invalid_argument& error) {
                respondError(response, 400, ErrorCode::eRequestFailed, error.what());
            }
        };
    };

    const auto fromServer = [this](auto handler) {
        return [this, handler](const http::Request& request, http::Response& response) {
            try {
                auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                    request.target, bodyBytes(request), {options_.serverFingerprint}, replayCache_);
            } catch (const std::exception& error) {
                respondError(response, 403, ErrorCode::eRequestFailed, error.what());
                return;
            }
            handler(request, response);
        };
    };
    const auto clientRoute = [this, &authenticated](const std::string& method,
                                 const std::string& path, auto handler) {
        http_->route(method, path, filled(authenticated(handler)));
    };

    clientRoute("POST", fleet::kAccountCard,
        [this](const http::Request& request, http::Response& response,
                          const std::string& user) {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const Bytes der = fromBase64(body.at("card").get<std::string>());

            ContactCard card;
            Bytes cardKey;
            try {
                card = ContactCard::verify(der);
                cardKey = linkKeyFromText(body.at("cardKey").get<std::string>());
            } catch (const std::exception& error) {
                respondError(response, 400, ErrorCode::eRequestFailed,
                    std::string("invalid contact card: ") + error.what());
                return;
            }
            if (card.fingerprint() != user) {
                respondError(response, 403, ErrorCode::eRequestFailed,
                    "this card was signed by somebody else");
                return;
            }
            if (!isB32I2pHost(card.dest)) {
                respondError(response, 400, ErrorCode::eRequestFailed,
                    "a card names the destination its account is reached at");
                return;
            }
            if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(user);
                ban.has_value()) {
                respondError(response, 403, ErrorCode::eRequestFailed, ban->reason);
                return;
            }

            const std::int64_t now = nowSeconds();
            const std::optional<GrantStore::SubscriptionGrant> grant
                = grants_.peekSubscription(user);
            const std::optional<SubscriptionStore::Account> held = store_.getAccount(user);
            if (held.has_value() && !held->card.empty()) {
                try {
                    if (const ContactCard previous = ContactCard::verify(held->card);
                        card.issuedAt <= previous.issuedAt) {
                        respondError(response, 409, ErrorCode::eRequestFailed,
                            "this card is not newer than the one already published");
                        return;
                    }
                } catch (const std::exception& error) {
                    bazarish::log::warn("the card held for {} could not be read, replacing it: {}",
                        bazarish::log::redact(user), error.what());
                }
            }
            if (card.issuedAt > now + auth::kAuthFreshnessWindowSeconds) {
                respondError(response, 400, ErrorCode::eRequestFailed,
                    "this card is dated in the future - check the clock on that device");
                return;
            }
            std::uint64_t quota = 0;
            if (grant.has_value()) {
                grants_.takeSubscription(user);
                quota = grant->quotaBytes;
            } else if (held.has_value()) {
                quota = held->quotaBytes;
            } else {
                respondError(response, 404, ErrorCode::eAccountUnknown,
                    "no pending registration - register on the service portal first");
                return;
            }

            SubscriptionStore::Account record;
            record.user = user;
            record.registeredAt
                = held.has_value() && held->registeredAt != 0 ? held->registeredAt : now;
            record.quotaBytes = quota;
            record.dest = card.dest.empty() && held.has_value() ? held->dest : card.dest;
            record.delegatedAt = held.has_value() ? held->delegatedAt : 0;
            record.card = der;
            record.cardKey = cardKey;
            store_.putAccount(record);
            options_.publishQuota(user, quota);
            options_.publishCardChanged(user);

            grants_.recordRegistration(user, now, !settings().requireApproval);
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            const bool pending = approval.has_value() && approval->pending();

            respondJson(response,
                {
                    {"quotaBytes", quota},
                    {"serverCard", toBase64(options_.serverCardDer)},
                    {"approval", pending ? "pending" : "approved"},
                    {"registrationMessage",
                        pending ? holdMessageFor(approval, settings()) : std::string()},
                });
        });

    clientRoute("DELETE", "/v1/account/registration",
        [this](const http::Request&, http::Response& response,
                          const std::string& user) {
            deleteAccount(user);
            respondJson(response, {{"ok", true}});
        });

    clientRoute("POST", "/v1/account/i2p-dest",
        [this](const http::Request& request, http::Response& response,
                          const std::string& user) {
            if (!options_.publishI2pTransient) {
                respondError(response, 503, ErrorCode::eRequestFailed,
                    "per-user destinations not available");
                return;
            }
            const std::int64_t now = nowSeconds();
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            if (!approval.has_value()) {
                respondError(response, 404, ErrorCode::eAccountUnknown,
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
            const nlohmann::json body = bazarish::parseJson(request.body);
            const std::string transient = body.value("transient", std::string());
            const std::int64_t expiresUnix
                = transient.empty() ? 0 : body.at("expiresUnix").get<std::int64_t>();
            if (expiresUnix > now + kMaxDelegationDays * bazarish::kSecondsPerDay) {
                respondError(response, 400, ErrorCode::eRequestFailed,
                    "a delegation may run at most " + std::to_string(kMaxDelegationDays)
                        + " days");
                return;
            }
            if (!transient.empty() && expiresUnix <= now) {
                respondError(response, 400, ErrorCode::eRequestFailed,
                    "this delegation has already run out");
                return;
            }
            if (!transient.empty()) {
                try {
                    const i2p::Keys delegation = i2p::Keys::fromBlob(fromBase64(transient));
                    i2p::requireUsableDelegation(delegation, now);
                    i2p::requireDelegationEnds(delegation, expiresUnix);
                } catch (const std::exception& error) {
                    respondError(response, 400, ErrorCode::eRequestFailed, error.what());
                    return;
                }
            }
            const AddressKeys keys{body.value("sealingKey", std::string()),
                body.value("signingKey", std::string())};
            if (!transient.empty() && (keys.sealingPem.empty() || keys.signingPem.empty())) {
                respondError(response, 400, ErrorCode::eRequestFailed,
                    "a delegation comes with the serving and signing keys of its address");
                return;
            }
            const std::optional<ServedDestination> served
                = options_.publishI2pTransient(user, transient, expiresUnix, keys);
            if (!served.has_value()) {
                respondError(response, 503, ErrorCode::eRequestFailed,
                    "the messaging server did not accept the delegation");
                return;
            }
            grants_.setI2pTransient(user, expiresUnix);
            if (const std::optional<SubscriptionStore::Account> held = store_.getAccount(user);
                held.has_value()) {
                SubscriptionStore::Account record = *held;
                if (transient.empty()) {
                    record.dest.clear();
                } else {
                    record.delegatedAt = now;
                }
                store_.putAccount(record);
            }
            respondJson(response, {{"dest", served->dest}});
        });

    clientRoute("GET", "/v1/account/i2p-status",
        [this](const http::Request&, http::Response& response,
                          const std::string& user) {
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            const std::optional<GrantStore::Transient> transient = grants_.peekTransient(user);
            respondJson(response,
                {
                    {"approval", approvalState(approval)},
                    {"registrationMessage",
                        approval.has_value() && approval->pending()
                            ? holdMessageFor(approval, settings())
                            : std::string()},
                    {"transientExpires", transient.has_value() ? transient->expires : 0},
                });
        });

    http_->get(fleet::kAccountCard,
        filled(fromServer([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            std::optional<SubscriptionStore::Account> account;
            try {
                account = user.empty() ? std::nullopt : store_.getAccount(user);
            } catch (const std::exception& error) {
                bazarish::log::warn("account record of {} is unreadable: {}", log::redact(user),
                    error.what());
            }
            const std::optional<GrantStore::Approval> approval
                = user.empty() ? std::nullopt : grants_.peekApproval(user);
            const bool known = account.has_value() && !account->card.empty()
                && !(approval.has_value() && approval->pending());
            if (!known) {
                respondError(response, 404, ErrorCode::eAccountUnknown,
                    "no card for that account");
                return;
            }
            respondJson(response, {{"user", user}, {"card", toBase64(account->card)},
                {"cardKey", linkKeyText(account->cardKey)}});
        })));

    clientRoute("POST", "/v1/account/registration",
        [this](const http::Request&, http::Response& response,
                          const std::string& user) {
            if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(user);
                ban.has_value()) {
                respondError(response, 403, ErrorCode::eRequestFailed, ban->reason);
                return;
            }
            const NodeSettings::Values values = settings();
            const std::int64_t now = nowSeconds();
            if (!store_.getAccount(user).has_value()
                && !grants_.peekSubscription(user).has_value()) {
                grants_.grantSubscription(user, values.defaultQuotaBytes, now);
            }
            respondJson(response,
                {{"ok", true}, {"quotaBytes", values.defaultQuotaBytes},
                    {"requiresApproval", values.requireApproval},
                    {"message", values.requireApproval ? values.registrationMessage
                                                       : std::string()}});
        });
}

}  // namespace bazarish::service
