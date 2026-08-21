// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Health.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <ctime>
#include <filesystem>
#include <optional>
#include <stdexcept>

namespace {

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

// When the node will drop this account if nothing changes. Two registrations
// never become served accounts: one waiting for an operator who never approves
// it, and one the portal issued that no client ever redeemed. Both are swept
// after the same lifetime; an account that is served is not swept at all.
std::int64_t sweepDeadline(const std::int64_t registeredAt, const bool subscribed,
    const std::optional<bazarish::service::GrantStore::Approval>& approval,
    const bazarish::service::NodeSettings::Values& settings)
{
    constexpr std::int64_t kSecondsPerDay = 24 * 3600;
    if (settings.registrationTtlDays <= 0 || registeredAt == 0) {
        return 0;
    }
    const bool waitingForOperator = approval.has_value() && approval->pending();
    const bool neverRedeemed = !subscribed && !approval.has_value();
    if (!waitingForOperator && !neverRedeemed) {
        return 0;
    }
    const std::int64_t from
        = waitingForOperator ? approval->requestedAt : registeredAt;
    return from + settings.registrationTtlDays * kSecondsPerDay;
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
    : settings_(options.settings ? options.settings
                                 : std::make_shared<NodeSettings>(std::filesystem::path(),
                                       NodeSettings::Values{
                                           options.registration
                                               == AccountApiOptions::Registration::eApproval,
                                           options.registrationMessage,
                                           options.defaultQuotaBytes}))
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
    revokeDestination(user);
    store_.deleteSubscription(user);
    grants_.erase(user);
}

nlohmann::json AccountApi::userRecord(
    const std::string& user, const std::optional<GrantStore::Approval>& approval)
{
    const std::optional<SubscriptionStore::Subscription> held = store_.getSubscription(user);
    const std::optional<GrantStore::SubscriptionGrant> grant = grants_.peekSubscription(user);
    const std::optional<GrantStore::Transient> transient = grants_.peekTransient(user);
    const std::optional<GrantStore::Ban> ban = grants_.peekBan(user);
    const NodeSettings::Values values = settings();
    // The portal registers the account; a client redeems it later, or never. The
    // first date is the one an operator asks about when nothing else happened.
    const std::int64_t registeredAt = grant.has_value() ? grant->grantedAt
        : (approval.has_value() ? approval->requestedAt : 0);
    return {
        {"user", user},
        {"dest", held.has_value() ? held->dest : std::string()},
        {"registeredAt", registeredAt},
        {"sweepAt", sweepDeadline(registeredAt, held.has_value(), approval, values)},
        {"banned", ban.has_value()},
        {"banReason", ban.has_value() ? ban->reason : std::string()},
        {"holdMessage", approval.has_value() ? approval->message : std::string()},
        {"quotaBytes",
            held.has_value() ? held->quotaBytes
                             : (grant.has_value() ? grant->quotaBytes
                                                 : settings().defaultQuotaBytes)},
        {"subscribed", held.has_value()},
        {"notAfter", held.has_value() ? held->notAfter : 0},
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

    http_->get("/v1/account/pending",
        filled(operatorOnly([this](const http::Request&, http::Response& response) {
            nlohmann::json users = nlohmann::json::array();
            for (const std::string& user : grants_.pendingUsers()) {
                const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
                users.push_back({{"user", user},
                    {"requestedAt", approval.has_value() ? approval->requestedAt : 0}});
            }
            respondJson(response, {{"pending", users}});
        })));

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
                    const std::optional<SubscriptionStore::Subscription> held
                        = store_.getSubscription(user);
                    const bool matches = lowercased(user).find(query) != std::string::npos
                        || (held.has_value()
                            && lowercased(held->dest).find(query) != std::string::npos);
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
            const std::string message = body.value("message", std::string());
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
                && !store_.getSubscription(user).has_value()) {
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
                const std::optional<SubscriptionStore::Subscription> held
                    = store_.getSubscription(user);
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
                    {"defaultQuotaBytes", values.defaultQuotaBytes},
                    {"registrationTtlDays", values.registrationTtlDays},
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
            if (body.contains("registrationTtlDays")) {
                values.registrationTtlDays = body.at("registrationTtlDays").get<std::int64_t>();
                if (values.registrationTtlDays < 0) {
                    throw std::invalid_argument("a lifetime cannot be negative");
                }
            }
            if (body.contains("defaultQuotaBytes")) {
                values.defaultQuotaBytes = body.at("defaultQuotaBytes").get<std::uint64_t>();
                if (values.defaultQuotaBytes == 0) {
                    throw std::invalid_argument("a new account needs some storage");
                }
            }
            try {
                settings_->set(values);
            } catch (const std::exception& error) {
                // The operator asked for a change that cannot outlive a restart.
                // Saying so beats applying it and losing it later.
                respondError(response, 500, ErrorCode::eDeliveryRejected, error.what());
                return;
            }
            respondJson(response,
                {
                    {"requireApproval", values.requireApproval},
                    {"registrationMessage", values.registrationMessage},
                    {"defaultQuotaBytes", values.defaultQuotaBytes},
                    {"registrationTtlDays", values.registrationTtlDays},
                });
        })));

    // One account in full, for the card the operator opens.
    http_->get("/v1/account/user",
        filled(operatorOnly([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            if (!approval.has_value() && !store_.getSubscription(user).has_value()) {
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
            const std::optional<SubscriptionStore::Subscription> held
                = store_.getSubscription(user);
            if (!approval.has_value() && !held.has_value()) {
                respondError(response, 404, ErrorCode::eDeliveryRejected, "no such account");
                return;
            }
            if (held.has_value()) {
                SubscriptionStore::Subscription updated = *held;
                updated.quotaBytes = quotaBytes;
                store_.putSubscription(updated);
            }
            // A grant not yet redeemed carries the quota the certificate will be
            // checked against, so it has to move with it.
            if (const std::optional<GrantStore::SubscriptionGrant> grant
                = grants_.peekSubscription(user);
                grant.has_value()) {
                grants_.grantSubscription(user, quotaBytes, grant->termSeconds, grant->grantedAt);
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

    // Validates and stores a subscription certificate. Shared by subscribe
    // and renew - renewal is simply a fresh certificate.
    const auto handleSubscribe
        = [this](const http::Request& request, http::Response& response,
              const std::string& user) {
              const nlohmann::json body = nlohmann::json::parse(request.body);
              const Bytes der = fromBase64(body.at("cert").get<std::string>());

              SubscriptionCertificate cert;
              try {
                  cert = SubscriptionCertificate::verify(der);
              } catch (const std::exception& error) {
                  respondError(response, 400, ErrorCode::eDeliveryRejected,
                      std::string("invalid subscription certificate: ") + error.what());
                  return;
              }
              if (cert.user != user) {
                  respondError(response, 403, ErrorCode::eDeliveryRejected,
                      "certificate does not name the authenticated user");
                  return;
              }
              if (cert.server != options_.serverFingerprint) {
                  respondError(response, 400, ErrorCode::eDeliveryRejected,
                      "certificate names a different server");
                  return;
              }
              const std::int64_t now = nowSeconds();
              if (cert.isExpired(now)) {
                  respondError(response, 400, ErrorCode::eSubscriptionExpired,
                      "certificate is already expired");
                  return;
              }
              if (cert.notAfter - cert.issuedAt > options_.maxTermSeconds) {
                  respondError(response, 400, ErrorCode::eSubscriptionTermTooLong,
                      "requested term exceeds the server maximum of "
                          + std::to_string(options_.maxTermSeconds) + " seconds");
                  return;
              }

              // Registration is authorised on the service portal, which records a
              // pending grant. The Client redeems it here with its user-signed
              // certificate; the grant supplies the quota and bounds the term.
              // Without a grant the only certificate accepted is a re-issue of
              // one already held: the user publishes its routing this way once
              // its destination exists (the destination can only be delegated
              // after the account exists, so the first certificate never carries
              // it) or once an operator approves a moderated account. A re-issue
              // grants nothing - same term, same quota - so it consumes no grant.
              const std::optional<GrantStore::SubscriptionGrant> grant
                  = grants_.peekSubscription(cert.user);
              const std::optional<SubscriptionStore::Subscription> held
                  = store_.getSubscription(cert.user);
              std::uint64_t effectiveQuota = 0;
              if (grant.has_value()) {
                  if (cert.notAfter - cert.issuedAt > grant->termSeconds) {
                      respondError(response, 400, ErrorCode::eSubscriptionTermTooLong,
                          "requested term exceeds the granted term");
                      return;
                  }
                  grants_.takeSubscription(cert.user);  // consume the one-shot grant
                  effectiveQuota = grant->quotaBytes;
              } else if (held.has_value() && cert.notAfter <= held->notAfter) {
                  effectiveQuota = held->quotaBytes;
              } else {
                  respondError(response, 403, ErrorCode::eDeliveryRejected,
                      "no pending subscription grant — register on the service portal first");
                  return;
              }

              if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(cert.user);
                  ban.has_value()) {
                  respondError(response, 403, ErrorCode::eDeliveryRejected, ban->reason);
                  return;
              }

              SubscriptionStore::Subscription record;
              record.user = cert.user;
              record.issuedAt = cert.issuedAt;
              record.notAfter = cert.notAfter;
              record.quotaBytes = effectiveQuota;
              record.dest = cert.dest;
              record.certificate = der;
              store_.putSubscription(record);
              // The granted quota is this node's to set: push it so the messaging
              // server serves the number the portal promised, not its own default.
              if (options_.publishQuota) {
                  options_.publishQuota(cert.user, effectiveQuota);
              }

              // On an open server the account is servable at once; on a moderated
              // one this only starts the approval clock. Renewal keeps the
              // original request time, so a pending account cannot outlive its
              // deadline by renewing.
              grants_.recordRegistration(
                  cert.user, now, !settings().requireApproval);
              const std::optional<GrantStore::Approval> approval
                  = grants_.peekApproval(cert.user);
              const bool pending = approval.has_value() && approval->pending();

              respondJson(response,
                  {
                      {"notAfter", cert.notAfter},
                      {"quotaBytes", effectiveQuota},
                      {"maxTermSeconds", options_.maxTermSeconds},
                      {"serverCard", toBase64(options_.serverCardDer)},
                      {"approval", pending ? "pending" : "approved"},
                      {"registrationMessage",
                          pending ? holdMessageFor(approval, settings()) : std::string()},
                  });
          };

    http_->post("/v1/account/subscribe", filled(authenticated(handleSubscribe)));
    http_->post("/v1/account/renew", filled(authenticated(handleSubscribe)));

    http_->get("/v1/account/subscription",
        filled(authenticated([this](const http::Request&, http::Response& response,
                          const std::string& user) {
            const std::optional<SubscriptionStore::Subscription> record
                = store_.getSubscription(user);
            if (!record.has_value() || record->notAfter < nowSeconds()) {
                respondError(response, 404, ErrorCode::eSubscriptionExpired,
                    "no active subscription");
                return;
            }
            respondJson(response,
                {{"notAfter", record->notAfter}, {"quotaBytes", record->quotaBytes}});
        })));

    // Unsubscribing tears the account down, it does not merely stop renewing:
    // the destination is revoked and the grants (including the approval) are
    // dropped, so nothing about the account outlives it. Coming back means
    // registering again.
    http_->del("/v1/account/subscription",
        filled(authenticated([this](const http::Request&, http::Response& response,
                          const std::string& user) {
            store_.deleteSubscription(user);
            if (options_.publishI2pTransient) {
                options_.publishI2pTransient(user, std::string(), 0);
            }
            grants_.erase(user);
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
            if (!options_.publishI2pTransient(user, transient, expiresUnix)) {
                // Recording it here would make i2p-status report a destination the
                // messaging server never raised: published to the user, dark to
                // everyone else.
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "the messaging server did not accept the delegation");
                return;
            }
            grants_.setI2pTransient(user, expiresUnix, now);
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

    // Contact lookup by fingerprint: returns the user's subscription
    // certificate, which carries the serving server and the sealing prekey a
    // first-contact sender uses to E2E-encrypt the contact request. Like
    // alias resolution this is unauthenticated (a user must be reachable to
    // be messaged); a sealed-relay variant that hides the lookup from the
    // requester's own server is future federation work.
    http_->get("/v1/account/contact",
        filled([this](const http::Request& request, http::Response& response) {
            const std::string user = request.query("user");
            const std::optional<SubscriptionStore::Subscription> subscription
                = store_.getSubscription(user);
            if (!subscription.has_value()) {
                respondError(response, 404, ErrorCode::eSubscriptionExpired,
                    "no active subscription for this user");
                return;
            }
            respondJson(response,
                {
                    {"user", user},
                    {"subscriptionCert", toBase64(subscription->certificate)},
                    {"serverCard", toBase64(options_.serverCardDer)},
                });
        }));

    // Onboarding discovery: where to register and on what terms. Unauthenticated
    // - the client shows the message and link(s); registration happens on the
    // portal, not here. Nothing on this node is for sale, so there is no service
    // catalogue: the only variables are whether a captcha is required and
    // whether an operator has to approve the account.
    http_->get("/v1/account/portal", filled([this](const http::Request&, http::Response& response) {
            nlohmann::json links = nlohmann::json::array();
            for (const std::string& link : options_.portalLinks) {
                links.push_back(link);
            }
            respondJson(response,
                {
                    {"message", options_.portalMessage},
                    {"links", links},
                    {"registration",
                        {
                            {"captcha", options_.freeRegistrationCaptcha},
                            {"requiresApproval",
                                settings().requireApproval},
                            {"message", settings().registrationMessage},
                        }},
                    {"quotaBytes", settings().defaultQuotaBytes},
                });
        }));
}

}  // namespace bazarish::service
