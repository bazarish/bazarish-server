// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include "ServiceLifecycle.hpp"

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

              // Registration is authorised on the service portal (captcha for
              // free, payment for paid), which records a pending grant. The
              // Client redeems it here with its user-signed certificate; the
              // grant supplies the quota and bounds the term. No grant -> the
              // user must register on the portal first.
              const std::optional<GrantStore::SubscriptionGrant> grant
                  = grants_.peekSubscription(cert.user);
              if (!grant.has_value()) {
                  respondError(response, 403, ErrorCode::eDeliveryRejected,
                      "no pending subscription grant — register on the service portal first");
                  return;
              }
              if (cert.notAfter - cert.issuedAt > grant->termSeconds) {
                  respondError(response, 400, ErrorCode::eSubscriptionTermTooLong,
                      "requested term exceeds the granted term");
                  return;
              }
              grants_.takeSubscription(cert.user);  // consume the one-shot grant

              // Catch up auto-renewals so the storage entitlement read below
              // reflects any elapsed terms (and a lapse pushes the free quota).
              if (options_.lifecycle) {
                  options_.lifecycle->evaluate(cert.user, now);
              }

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
                respondError(response, 404, ErrorCode::eSubscriptionExpired,
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

    // Receives a paid user's client-owned offline I2P transient and hands it to
    // the messaging server, which operates the user's personal destination.
    // i2pDest is a paid service: an active entitlement is required (auto-renewed
    // from balance, with the one-step grace). An empty transient revokes the
    // destination. The transient's validity is recorded so the status endpoint
    // can tell the client's other devices when to issue the next one.
    http_->Post("/v1/account/i2p-dest",
        authenticated([this](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            if (!options_.publishI2pTransient) {
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "per-user destinations not available");
                return;
            }
            const std::int64_t now = nowSeconds();
            bool active = false;
            if (options_.lifecycle) {
                active = options_.lifecycle->evaluate(user, now).i2pDest.active;
            } else {
                const std::optional<GrantStore::ServiceGrant> entitlement
                    = grants_.peekService(user, "i2pDest");
                active = entitlement.has_value() && entitlement->paidThrough > now;
            }
            if (!active) {
                respondError(response, 403, ErrorCode::eDeliveryRejected,
                    "no active i2pDest entitlement — enable it on the service portal first");
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

    // The per-user i2p-dest status the client polls: whether the option is on,
    // whether it is paid-active, the recorded transient validity (so any device
    // knows when to re-issue without storing it), the effective storage quota,
    // and honest projected shutoff dates computed from the balance.
    http_->Get("/v1/account/i2p-status",
        authenticated([this](const httplib::Request&, httplib::Response& response,
                          const std::string& user) {
            if (!options_.lifecycle) {
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "per-user destinations not available");
                return;
            }
            const ServiceLifecycle::Snapshot snap
                = options_.lifecycle->evaluate(user, nowSeconds());
            respondJson(response,
                {
                    {"enabled", snap.i2pDest.enabled},
                    {"active", snap.i2pDest.active},
                    {"paidThrough", snap.i2pDest.paidThrough},
                    {"projectedShutoff", snap.i2pDest.projectedShutoff},
                    {"transientExpires", snap.transientExpires},
                    {"transientUpdatedAt", snap.transientUpdatedAt},
                    {"storageQuotaBytes", snap.storageQuotaBytes},
                    {"storageActive", snap.storage.active},
                    {"storageProjectedShutoff", snap.storage.projectedShutoff},
                    {"balanceAtomic", std::to_string(snap.balanceAtomic)},
                    {"currency", options_.settlementCurrency},
                });
        }));

    // Turns the per-user i2p-dest option on or off. Enabling charges one term up
    // front (or resumes if still paid); disabling stops auto-renew and drops the
    // personal destination so the user falls back to their fixed pool address.
    http_->Post("/v1/account/i2p-dest/setting",
        authenticated([this](const httplib::Request& request, httplib::Response& response,
                          const std::string& user) {
            if (!options_.lifecycle) {
                respondError(response, 503, ErrorCode::eDeliveryRejected,
                    "per-user destinations not available");
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            const bool enabled = body.at("enabled").get<bool>();
            const std::int64_t now = nowSeconds();
            if (enabled) {
                if (!options_.lifecycle->enableI2pDest(user, now)) {
                    respondError(response, 402, ErrorCode::eDeliveryRejected,
                        "insufficient balance — top up to enable a personal destination");
                    return;
                }
            } else {
                options_.lifecycle->disableI2pDest(user, now);
            }
            respondJson(response, {{"ok", true}, {"enabled", enabled}});
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

    // Onboarding discovery: where to register and what this server offers.
    // Unauthenticated - the client shows the message and link(s); registration
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
