// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Errors.hpp>

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

    // Validates and stores a subscription certificate. Shared by subscribe
    // and renew — renewal is simply a fresh certificate.
    const auto handleSubscribe
        = [this](const httplib::Request& request, httplib::Response& response,
              const std::string& user) {
              const nlohmann::json body = nlohmann::json::parse(request.body);
              const Bytes der = fromBase64(body.at("cert").get<std::string>());

              SubscriptionCertificate cert;
              try {
                  cert = SubscriptionCertificate::verify(der);
              } catch (const std::exception& error) {
                  respondError(response, 400, ErrorCode::kDeliveryRejected,
                      std::string("invalid subscription certificate: ") + error.what());
                  return;
              }
              if (cert.user != user) {
                  respondError(response, 403, ErrorCode::kDeliveryRejected,
                      "certificate does not name the authenticated user");
                  return;
              }
              if (cert.server != options_.serverFingerprint) {
                  respondError(response, 400, ErrorCode::kDeliveryRejected,
                      "certificate names a different server");
                  return;
              }
              const std::int64_t now = nowSeconds();
              if (cert.isExpired(now)) {
                  respondError(response, 400, ErrorCode::kSubscriptionExpired,
                      "certificate is already expired");
                  return;
              }
              if (cert.notAfter - cert.issuedAt > options_.maxTermSeconds) {
                  respondError(response, 400, ErrorCode::kSubscriptionTermTooLong,
                      "requested term exceeds the server maximum of "
                          + std::to_string(options_.maxTermSeconds) + " seconds");
                  return;
              }

              // Registration is authorised on the service portal (captcha for
              // free, payment for paid), which records a pending grant. The
              // Client redeems it here with its user-signed certificate; the
              // grant supplies the quota and bounds the term. No grant → the
              // user must register on the portal first.
              const std::optional<GrantStore::SubscriptionGrant> grant
                  = grants_.peekSubscription(cert.user);
              if (!grant.has_value()) {
                  respondError(response, 403, ErrorCode::kDeliveryRejected,
                      "no pending subscription grant — register on the service portal first");
                  return;
              }
              if (cert.notAfter - cert.issuedAt > grant->termSeconds) {
                  respondError(response, 400, ErrorCode::kSubscriptionTermTooLong,
                      "requested term exceeds the granted term");
                  return;
              }
              grants_.takeSubscription(cert.user);  // consume the one-shot grant

              // Effective quota: the paid storage plan while its entitlement is
              // active, otherwise the grant's (free) quota.
              std::uint64_t effectiveQuota = grant->quotaBytes;
              const std::optional<GrantStore::ServiceGrant> storageGrant
                  = grants_.peekService(cert.user, "storage");
              if (storageGrant.has_value() && storageGrant->paidThrough > now
                  && options_.storagePlan.quotaBytes > effectiveQuota) {
                  effectiveQuota = options_.storagePlan.quotaBytes;
              }

              SubscriptionStore::Subscription record;
              record.user = cert.user;
              record.issuedAt = cert.issuedAt;
              record.notAfter = cert.notAfter;
              record.quotaBytes = effectiveQuota;
              record.certificate = der;
              store_.putSubscription(record);

              // Tell the messaging server the user's effective storage quota.
              if (options_.publishQuota) {
                  options_.publishQuota(cert.user, effectiveQuota);
              }

              respondJson(response,
                  {
                      {"notAfter", cert.notAfter},
                      {"quotaBytes", effectiveQuota},
                      {"maxTermSeconds", options_.maxTermSeconds},
                      {"serverCard", toBase64(options_.serverCardDer)},
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
                respondError(response, 404, ErrorCode::kSubscriptionExpired,
                    "no active subscription");
                return;
            }
            respondJson(response,
                {{"notAfter", record->notAfter}, {"quotaBytes", record->quotaBytes}});
        }));

    http_->Delete("/v1/account/subscription",
        authenticated([this](const httplib::Request&, httplib::Response& response,
                          const std::string& user) {
            store_.deleteSubscription(user);
            respondJson(response, {{"ok", true}});
        }));

    http_->Post("/v1/account/alias",
        authenticated([this](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const Bytes der = fromBase64(body.at("cert").get<std::string>());

            AliasCertificate cert;
            try {
                cert = AliasCertificate::verify(der);
            } catch (const std::exception& error) {
                respondError(response, 400, ErrorCode::kDeliveryRejected,
                    std::string("invalid alias certificate: ") + error.what());
                return;
            }
            if (cert.user != user) {
                respondError(response, 403, ErrorCode::kDeliveryRejected,
                    "certificate does not name the authenticated user");
                return;
            }
            // A username is a paid service: the user must hold an active username
            // entitlement bought (and renewed) on the portal. There is no open
            // registration.
            const std::optional<GrantStore::ServiceGrant> entitlement
                = grants_.peekService(user, "username");
            if (!entitlement.has_value() || entitlement->paidThrough <= nowSeconds()) {
                respondError(response, 403, ErrorCode::kDeliveryRejected,
                    "no active username entitlement — buy one on the service portal first");
                return;
            }
            SubscriptionStore::Alias record{cert.alias, cert.user, der};
            if (!store_.putAlias(record)) {
                respondError(response, 409, ErrorCode::kAliasTaken,
                    "alias is already registered to another user");
                return;
            }
            respondJson(response, {{"ok", true}, {"alias", cert.alias}});
        }));

    // Receives a paid user's client-owned offline I2P transient and hands it to
    // the messaging server, which operates the user's personal destination.
    // i2pDest is a paid service: an active entitlement is required. An empty
    // transient revokes the destination.
    http_->Post("/v1/account/i2p-dest",
        authenticated([this](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            if (!options_.publishI2pTransient) {
                respondError(response, 503, ErrorCode::kDeliveryRejected,
                    "per-user destinations not available");
                return;
            }
            const std::optional<GrantStore::ServiceGrant> entitlement
                = grants_.peekService(user, "i2pDest");
            if (!entitlement.has_value() || entitlement->paidThrough <= nowSeconds()) {
                respondError(response, 403, ErrorCode::kDeliveryRejected,
                    "no active i2pDest entitlement — buy one on the service portal first");
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string transient = body.value("transient", std::string());
            const std::int64_t expiresUnix
                = transient.empty() ? 0 : body.at("expiresUnix").get<std::int64_t>();
            options_.publishI2pTransient(user, transient, expiresUnix);
            respondJson(response, {{"ok", true}});
        }));

    http_->Delete("/v1/account/alias",
        authenticated([this](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const std::string alias = body.at("alias").get<std::string>();
            store_.deleteAlias(alias, user);
            respondJson(response, {{"ok", true}});
        }));

    // Alias resolution: returns the trust-chain artifacts the service node
    // holds (alias certificate + subscription certificate). The messaging
    // server adds its server card. Aliases are findable by design, so this
    // is unauthenticated and ALIAS_UNKNOWN is explicit (no anti-enumeration).
    http_->Get("/v1/account/resolve",
        [this](const httplib::Request& request, httplib::Response& response) {
            const std::string alias = request.get_param_value("alias");
            std::optional<SubscriptionStore::Alias> aliasRecord;
            try {
                aliasRecord = store_.getAlias(alias);
            } catch (const std::invalid_argument&) {
                respondError(response, 400, ErrorCode::kAliasUnknown, "malformed alias");
                return;
            }
            if (!aliasRecord.has_value()) {
                respondError(response, 404, ErrorCode::kAliasUnknown, "no such alias");
                return;
            }
            const std::optional<SubscriptionStore::Subscription> subscription
                = store_.getSubscription(aliasRecord->user);
            if (!subscription.has_value()) {
                // The alias exists but its owner is not currently subscribed
                // here: nothing routable to return.
                respondError(response, 404, ErrorCode::kAliasUnknown,
                    "alias owner has no active subscription");
                return;
            }
            respondJson(response,
                {
                    {"user", aliasRecord->user},
                    {"aliasCert", toBase64(aliasRecord->certificate)},
                    {"subscriptionCert", toBase64(subscription->certificate)},
                });
        });

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
                respondError(response, 404, ErrorCode::kSubscriptionExpired,
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

    // Onboarding discovery: where to register and what this server offers.
    // Unauthenticated — the client shows the message and link(s); registration
    // and paid services happen on the portal (captcha / payment), not here.
    http_->Get("/v1/account/portal",
        [this](const httplib::Request&, httplib::Response& response) {
            nlohmann::json links = nlohmann::json::array();
            for (const std::string& link : options_.portalLinks) {
                links.push_back(link);
            }
            const auto serviceJson = [this](const PortalService& service) {
                return nlohmann::json{
                    {"enabled", service.enabled},
                    {"priceAtomic", service.priceAtomic},
                    {"periodDays", service.periodDays},
                    {"currency", options_.settlementCurrency},
                };
            };
            respondJson(response,
                {
                    {"message", options_.portalMessage},
                    {"links", links},
                    {"services",
                        {
                            {"freeRegistration",
                                {{"enabled", true}, {"captcha", options_.freeRegistrationCaptcha}}},
                            {"username", serviceJson(options_.usernameService)},
                            {"i2pDest", serviceJson(options_.i2pDestService)},
                            {"storage",
                                {
                                    {"freeQuotaBytes", options_.defaultQuotaBytes},
                                    {"paid",
                                        {
                                            {"enabled", options_.storagePlan.enabled},
                                            {"quotaBytes", options_.storagePlan.quotaBytes},
                                            {"priceAtomic", options_.storagePlan.priceAtomic},
                                            {"periodDays", options_.storagePlan.periodDays},
                                            {"currency", options_.settlementCurrency},
                                        }},
                                }},
                        }},
                });
        });
}

}  // namespace bazarish::service
