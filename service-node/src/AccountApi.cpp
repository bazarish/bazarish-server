// Bazarish project (c) 2026
#include "AccountApi.hpp"


#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/Health.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <optional>
#include <stdexcept>

namespace {

using bazarish::Bytes;
using bazarish::ErrorCode;

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
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

namespace bazarish::service {

AccountApi::AccountApi(
    SubscriptionStore& store, GrantStore& grants, const AccountApiOptions options)
    : store_(store)
    , grants_(grants)
    , options_(options)
    , http_(std::make_unique<httplib::Server>())
    , startedAt_(nowSeconds())
{
    setupRoutes();
}

AccountApi::~AccountApi() = default;

bool AccountApi::listen(const std::string& host, const int port)
{
    return http_->listen(host, port);
}

int AccountApi::bindToAnyPort(const std::string& host)
{
    return http_->bind_to_any_port(host);
}

bool AccountApi::listenAfterBind()
{
    return http_->listen_after_bind();
}

void AccountApi::stop()
{
    http_->stop();
}

void AccountApi::setupRoutes()
{
    // Authenticated liveness for the admin panel: service name, version, uptime
    // and resident memory. Operator-only (signed), so it leaks nothing to an
    // unauthenticated caller.
    http_->Get("/healthz", [this](const httplib::Request& request, httplib::Response& response) {
        try {
            auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                request.path, Bytes(request.body.begin(), request.body.end()),
                options_.operatorFingerprints);
        } catch (const std::exception& error) {
            respondError(response, 403, ErrorCode::eDeliveryRejected, error.what());
            return;
        }
        response.set_content(
            health::reportJson("service-node", options_.version, startedAt_, nowSeconds()),
            "application/json");
    });

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

    // Operator-only moderation surface for the admin panel, signed with the
    // panel identity exactly like /healthz.
    const auto operatorOnly = [this](auto handler) {
        return [this, handler](const httplib::Request& request, httplib::Response& response) {
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

    http_->Get("/v1/account/pending",
        operatorOnly([this](const httplib::Request&, httplib::Response& response) {
            nlohmann::json users = nlohmann::json::array();
            for (const std::string& user : grants_.pendingUsers()) {
                const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
                users.push_back({{"user", user},
                    {"requestedAt", approval.has_value() ? approval->requestedAt : 0}});
            }
            respondJson(response, {{"pending", users}});
        }));

    http_->Post("/v1/account/approve",
        operatorOnly([this](const httplib::Request& request, httplib::Response& response) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string user = body.at("user").get<std::string>();
            if (!grants_.peekApproval(user).has_value()) {
                respondError(response, 404, ErrorCode::eDeliveryRejected, "no such account");
                return;
            }
            grants_.approve(user, nowSeconds());
            respondJson(response, {{"ok", true}});
        }));

    // Validates and stores a subscription certificate. Shared by subscribe
    // and renew - renewal is simply a fresh certificate.
    const auto handleSubscribe
        = [this](const httplib::Request& request, httplib::Response& response,
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

              SubscriptionStore::Subscription record;
              record.user = cert.user;
              record.issuedAt = cert.issuedAt;
              record.notAfter = cert.notAfter;
              record.quotaBytes = effectiveQuota;
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
                  cert.user, now, options_.registration == AccountApiOptions::Registration::eOpen);
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
                      {"registrationMessage", pending ? options_.registrationMessage : std::string()},
                  });
          };

    http_->Post("/v1/account/subscribe", authenticated(handleSubscribe));
    http_->Post("/v1/account/renew", authenticated(handleSubscribe));

    http_->Get("/v1/account/subscription",
        authenticated([this](const httplib::Request&, httplib::Response& response,
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
        }));

    // Unsubscribing tears the account down, it does not merely stop renewing:
    // the destination is revoked and the grants (including the approval) are
    // dropped, so nothing about the account outlives it. Coming back means
    // registering again.
    http_->Delete("/v1/account/subscription",
        authenticated([this](const httplib::Request&, httplib::Response& response,
                          const std::string& user) {
            store_.deleteSubscription(user);
            if (options_.publishI2pTransient) {
                options_.publishI2pTransient(user, std::string(), 0);
            }
            grants_.erase(user);
            respondJson(response, {{"ok", true}});
        }));

    // Receives the user's client-owned offline I2P transient and hands it to the
    // messaging server, which operates the user's own destination. Every account
    // has one - it is the base protocol, not a purchase - but a moderated server
    // withholds it until an operator approves the account, which is what "frozen"
    // means: the account exists and the transient is accepted nowhere. An empty
    // transient revokes the destination. The transient's validity is recorded so
    // the status endpoint can tell the client's other devices when to re-issue.
    http_->Post("/v1/account/i2p-dest",
        authenticated([this](const httplib::Request& request, httplib::Response& response,
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
                    options_.registrationMessage.empty()
                        ? "account is awaiting operator approval"
                        : options_.registrationMessage);
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string transient = body.value("transient", std::string());
            const std::int64_t expiresUnix
                = transient.empty() ? 0 : body.at("expiresUnix").get<std::int64_t>();
            options_.publishI2pTransient(user, transient, expiresUnix);
            grants_.setI2pTransient(user, expiresUnix, now);
            respondJson(response, {{"ok", true}});
        }));

    // What the client's devices need to keep the user's destination alive: the
    // approval state (a frozen account has no destination) and the validity of
    // the transient currently delegated, so any device knows when to issue the
    // next one without holding it.
    http_->Get("/v1/account/i2p-status",
        authenticated([this](const httplib::Request&, httplib::Response& response,
                          const std::string& user) {
            const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
            const std::optional<GrantStore::Transient> transient = grants_.peekTransient(user);
            respondJson(response,
                {
                    {"approval",
                        !approval.has_value() ? "none"
                                              : (approval->pending() ? "pending" : "approved")},
                    {"registrationMessage",
                        approval.has_value() && approval->pending() ? options_.registrationMessage
                                                                    : std::string()},
                    {"transientExpires", transient.has_value() ? transient->expires : 0},
                    {"transientUpdatedAt", transient.has_value() ? transient->updatedAt : 0},
                });
        }));

    // Contact lookup by fingerprint: returns the user's subscription
    // certificate, which carries the serving server and the sealing prekey a
    // first-contact sender uses to E2E-encrypt the contact request. Like
    // alias resolution this is unauthenticated (a user must be reachable to
    // be messaged); a sealed-relay variant that hides the lookup from the
    // requester's own server is future federation work.
    http_->Get("/v1/account/contact",
        [this](const httplib::Request& request, httplib::Response& response) {
            const std::string user = request.get_param_value("user");
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
        });

    // Onboarding discovery: where to register and on what terms. Unauthenticated
    // - the client shows the message and link(s); registration happens on the
    // portal, not here. Nothing on this node is for sale, so there is no service
    // catalogue: the only variables are whether a captcha is required and
    // whether an operator has to approve the account.
    http_->Get("/v1/account/portal",
        [this](const httplib::Request&, httplib::Response& response) {
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
                                options_.registration == AccountApiOptions::Registration::eApproval},
                            {"message", options_.registrationMessage},
                        }},
                    {"quotaBytes", options_.defaultQuotaBytes},
                });
        });
}

}  // namespace bazarish::service
