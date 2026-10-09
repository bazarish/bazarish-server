// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Tunnel.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Descriptor.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/Errors.hpp>
#include <Health.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <optional>
#include <stdexcept>

namespace {

const char* const kFingerprintPattern = "([a-z2-7]{52})";

using bazarish::Bytes;
using bazarish::ErrorCode;

namespace http = bazarish::http;

using bazarish::nowSeconds;
using bazarish::http::filled;

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

using bazarish::http::collectAuthHeaders;

constexpr std::size_t kDefaultUserPageSize = 50;
constexpr std::size_t kMaxUserPageSize = 500;

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

}  // namespace

namespace bazarish::service {

AccountApi::AccountApi(
    SubscriptionStore& store, GrantStore& grants, const AccountApiOptions options)
    : settings_(options.settings)
    , store_(store)
    , grants_(grants)
    , options_(options)
    , startedAt_(nowSeconds())
{
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
        options_.publishI2pTransient(user, std::string(), 0);
    }
    grants_.setI2pTransient(user, 0, nowSeconds());
}

void AccountApi::deleteAccount(const std::string& user)
{
    if (!grants_.peekApproval(user).has_value() && !store_.getAccount(user).has_value()) {
        return;
    }
    revokeDestination(user);
    if (options_.forgetMailbox && !options_.forgetMailbox(user)) {
        bazarish::log::warn("mailbox of {} was not dropped: the messaging server refused it",
            log::redact(user));
    }
    store_.deleteAccount(user);
    grants_.erase(user);
}

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
    const std::int64_t registeredAt = held.has_value() && held->registeredAt != 0
        ? held->registeredAt
        : (grant.has_value() ? grant->grantedAt
                             : (approval.has_value() ? approval->requestedAt : 0));
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
    const auto operatorOnly = [this](auto handler) {
        return [this, handler](const http::Request& request, http::Response& response) {
            if (const std::optional<http::Response> refused
                = http::operatorRefusal(
                    request, nowSeconds(), options_.operatorFingerprints, replayCache_);
                refused.has_value()) {
                response = *refused;
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

    ops_->get("/healthz",
        filled(operatorOnly([this](const http::Request&, http::Response& response) {
            response.contentType = "application/json";
            response.body
                = health::reportJson("service-node", options_.version, startedAt_, nowSeconds());
        })));

    ops_->get("/v1/account/users",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const std::string query = lowercased(request.query("q"));
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
                    const std::string dest = destinationOf(held);
                    const bool matches = lowercased(user).find(query) != std::string::npos
                        || lowercased(dest).find(query) != std::string::npos;
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

    ops_->post("/v1/account/undelegate",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
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

    ops_->del("/v1/account/user",
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

    ops_->post("/v1/account/ban",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
            const std::string reason = body.value("reason", std::string());
            deleteAccount(user);
            grants_.ban(user, reason.empty() ? std::string(kDefaultBanReason) : reason,
                nowSeconds());
            respondJson(response, userRecord(user, grants_.peekApproval(user)));
        })));

    ops_->post("/v1/account/unban",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
            grants_.unban(user);
            respondJson(response, {{"ok", true}});
        })));

    ops_->get("/v1/account/settings",
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

    ops_->put("/v1/account/settings",
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
                    throw std::invalid_argument(error.what());
                }
                values.loginConsumer = wanted;
            }
            if (body.contains("facades")) {
                std::vector<std::string> facades;
                for (const nlohmann::json& entry : body.at("facades")) {
                    std::string url = entry.get<std::string>();
                    if (url.empty()) {
                        continue;
                    }
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
            if (body.contains("logLevel")) {
                const std::string level = body.at("logLevel").get<std::string>();
                const std::optional<bazarish::log::Level> parsed
                    = bazarish::log::levelFromString(level);
                if (!parsed.has_value()) {
                    throw std::invalid_argument("not a log level: " + level);
                }
                values.logLevel = level;
            }
            readEndpointInto(body, "listen", values.listenHost, values.listenPort);
            readEndpointInto(
                body, "portalListen", values.portalListenHost, values.portalListenPort);
            readEndpointInto(body, "messaging", values.messagingHost, values.messagingPort);
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
                respondError(response, 500, ErrorCode::eDeliveryRejected, error.what());
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

    ops_->post("/v1/account/restart",
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

    ops_->get("/v1/account/user",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            if (!approval.has_value() && !store_.getAccount(user).has_value()) {
                respondError(response, 404, ErrorCode::eDeliveryRejected, "no such account");
                return;
            }
            respondJson(response, userRecord(user, approval));
        })));

    ops_->put("/v1/account/quota",
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

    ops_->post("/v1/account/approve",
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

}

void AccountApi::setupRoutes()
{
    const auto authenticated = [this](auto handler) {
        return [this, handler](const http::Request& request, http::Response& response) {
            std::string user;
            try {
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

    const auto vouched = [this](auto handler) {
        return [this, handler](const http::Request& request, http::Response& response) {
            try {
                auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                    request.path, bodyBytes(request), {options_.serverFingerprint}, replayCache_);
            } catch (const std::exception& error) {
                respondError(response, 403, ErrorCode::eDeliveryRejected, error.what());
                return;
            }
            if (request.captures.empty() || request.captures.at(0).empty()) {
                respondError(response, 400, ErrorCode::eDeliveryRejected, "no user named");
                return;
            }
            handler(request, response, request.captures.at(0));
        };
    };
    const auto fromServer = [this](auto handler) {
        return [this, handler](const http::Request& request, http::Response& response) {
            try {
                auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                    request.path, bodyBytes(request), {options_.serverFingerprint}, replayCache_);
            } catch (const std::exception& error) {
                respondError(response, 403, ErrorCode::eDeliveryRejected, error.what());
                return;
            }
            handler(request, response);
        };
    };
    const auto clientRoute = [this, &authenticated, &vouched](const std::string& method,
                                 const std::string& path, auto handler) {
        http_->route(method, path, filled(authenticated(handler)));
        http_->route(method,
            std::string(bazarish::tunnel::kVouchedPrefix) + kFingerprintPattern + path,
            filled(vouched(handler)));
    };

    clientRoute("POST", "/v1/account/card",
        [this](const http::Request& request, http::Response& response,
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
            if (card.fingerprint() != user) {
                respondError(response, 403, ErrorCode::eDeliveryRejected,
                    "this card was signed by somebody else");
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
            if (held.has_value() && !held->card.empty()) {
                try {
                    if (const ContactCard previous = ContactCard::verify(held->card);
                        card.issuedAt <= previous.issuedAt) {
                        respondError(response, 409, ErrorCode::eDeliveryRejected,
                            "this card is not newer than the one already published");
                        return;
                    }
                } catch (const std::exception& error) {
                    bazarish::log::warn("the card held for {} could not be read, replacing it: {}",
                        bazarish::log::redact(user), error.what());
                }
            }
            if (card.issuedAt > now + auth::kAuthFreshnessWindowSeconds) {
                respondError(response, 400, ErrorCode::eDeliveryRejected,
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
                respondError(response, 403, ErrorCode::eDeliveryRejected,
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
            store_.putAccount(record);
            if (options_.publishQuota) {
                options_.publishQuota(user, quota);
            }

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
            if (expiresUnix > now + kMaxDelegationDays * bazarish::kSecondsPerDay) {
                respondError(response, 400, ErrorCode::eDeliveryRejected,
                    "a delegation may run at most " + std::to_string(kMaxDelegationDays)
                        + " days");
                return;
            }
            if (!transient.empty() && expiresUnix <= now) {
                respondError(response, 400, ErrorCode::eDeliveryRejected,
                    "this delegation has already run out");
                return;
            }
            const std::optional<ServedDestination> served
                = options_.publishI2pTransient(user, transient, expiresUnix);
            if (!served.has_value()) {
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "the messaging server did not accept the delegation");
                return;
            }
            grants_.setI2pTransient(user, expiresUnix, now);
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
            respondJson(response,
                {{"dest", served->dest}, {"servingKey", served->servingKeyB64}});
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
                    {"transientUpdatedAt", transient.has_value() ? transient->updatedAt : 0},
                });
        });

    http_->get("/v1/account/card",
        filled(fromServer([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            std::optional<SubscriptionStore::Account> account;
            try {
                account = user.empty() ? std::nullopt : store_.getAccount(user);
            } catch (const std::exception& error) {
                bazarish::log::warn("account record of {} is unreadable: {}", log::redact(user),
                    error.what());
            }
            const bool known = account.has_value() && !account->card.empty();
            if (!known) {
                respondError(response, 404, ErrorCode::eClientUnregistered,
                    "that descriptor is out of date");
                return;
            }
            respondJson(response, {{"user", user}, {"card", toBase64(account->card)}});
        })));

    clientRoute("POST", "/v1/account/registration",
        [this](const http::Request&, http::Response& response,
                          const std::string& user) {
            if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(user);
                ban.has_value()) {
                respondError(response, 403, ErrorCode::eDeliveryRejected, ban->reason);
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

    const auto portalHandler = [this](const http::Request&, http::Response& response) {
        const NodeSettings::Values live = settings();
        respondJson(response,
            {
                {"message", live.requireApproval ? live.portalMessage : std::string()},
                {"links", live.portalLinks},
                {"registration",
                    {
                        {"requiresApproval", live.requireApproval},
                        {"message", live.requireApproval ? live.registrationMessage
                                                         : std::string()},
                    }},
                {"quotaBytes", live.defaultQuotaBytes},
            });
    };
    http_->get("/v1/account/portal", filled(portalHandler));
    http_->get(std::string(bazarish::tunnel::kVouchedPrefix) + kFingerprintPattern
            + "/v1/account/portal",
        filled(portalHandler));
}

}  // namespace bazarish::service
