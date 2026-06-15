// Bazarish project (c) 2026
#include "PortalApi.hpp"

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <exception>
#include <optional>
#include <utility>

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

void respondJson(httplib::Response& response, const nlohmann::json& body)
{
    response.set_content(body.dump(), "application/json");
}

// Reads one cookie value from the request's Cookie header.
std::string cookieValue(const httplib::Request& request, const std::string& name)
{
    const std::string cookies = request.get_header_value("Cookie");
    const std::string key = name + "=";
    const auto pos = cookies.find(key);
    if (pos == std::string::npos) {
        return {};
    }
    const auto start = pos + key.size();
    const auto end = cookies.find(';', start);
    return cookies.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

}  // namespace

namespace bazarish::service {

PortalApi::PortalApi(PortalApiOptions options, Captcha& captcha, GrantStore& grants,
    LedgerStore& ledger, InvoiceStore& invoices, PaymentGateway& gateway)
    : options_(std::move(options))
    , captcha_(captcha)
    , grants_(grants)
    , ledger_(ledger)
    , invoices_(invoices)
    , gateway_(gateway)
    , login_(options_.challengeSecret, options_.audience)
    , session_(options_.sessionSecret, options_.sessionTtlSeconds)
    , http_(std::make_unique<httplib::Server>())
{
    setupRoutes();
}

bool PortalApi::settleInvoice(
    const std::string& invoiceId, const PaymentStatus& status, const std::int64_t now)
{
    if (status.state != PaymentState::kConfirmed) {
        return false;
    }
    const std::optional<std::string> user = invoices_.user(invoiceId);
    if (!user.has_value()) {
        return false;
    }
    std::uint64_t amount = 0;
    try {
        amount = std::stoull(status.paidAmount);
    } catch (const std::exception&) {
        return false;
    }
    if (amount == 0) {
        return false;
    }
    return ledger_.creditOnce(*user, amount, "topup:" + invoiceId, now);
}

PortalApi::~PortalApi() = default;

bool PortalApi::listen(const std::string& host, const int port)
{
    return http_->listen(host, port);
}

int PortalApi::bindToAnyPort(const std::string& host)
{
    return http_->bind_to_any_port(host);
}

bool PortalApi::listenAfterBind()
{
    return http_->listen_after_bind();
}

void PortalApi::stop()
{
    http_->stop();
}

void PortalApi::setupRoutes()
{
    // Issue a fresh login challenge for the user to sign with their Client.
    http_->Get("/portal/login", [this](const httplib::Request&, httplib::Response& response) {
        respondJson(response, {{"challenge", login_.issue(nowSeconds())}});
    });

    // Verify the signed challenge and start a session.
    http_->Post("/portal/login", [this](const httplib::Request& request,
                                      httplib::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body, nullptr, false);
        if (body.is_discarded() || !body.contains("challenge") || !body.contains("blob")) {
            response.status = 400;
            respondJson(response, {{"error", "bad request"}});
            return;
        }
        try {
            const std::string userId = login_.verify(body.at("challenge").get<std::string>(),
                body.at("blob").get<std::string>(), nowSeconds());
            const std::string token = session_.issue(userId, nowSeconds());
            response.set_header(
                "Set-Cookie", "session=" + token + "; HttpOnly; SameSite=Strict; Path=/");
            respondJson(response, {{"ok", true}, {"userId", userId}});
        } catch (const std::exception&) {
            response.status = 401;
            respondJson(response, {{"error", "login failed"}});
        }
    });

    // The logged-in user, from the session cookie.
    http_->Get("/portal/me", [this](const httplib::Request& request, httplib::Response& response) {
        try {
            const std::string userId = session_.verify(cookieValue(request, "session"), nowSeconds());
            respondJson(response, {{"userId", userId}});
        } catch (const std::exception&) {
            response.status = 401;
            respondJson(response, {{"error", "not authenticated"}});
        }
    });

    // A captcha to present before free registration.
    http_->Get("/portal/captcha", [this](const httplib::Request&, httplib::Response& response) {
        const CaptchaChallenge challenge = captcha_.issue(nowSeconds());
        respondJson(response,
            {
                {"captchaId", challenge.id},
                {"contentType", challenge.contentType},
                {"body", challenge.body},
            });
    });

    // Free registration: a logged-in user passes the captcha; the node records a
    // pending subscription grant the Client then redeems with its signed cert.
    http_->Post(
        "/portal/register", [this](const httplib::Request& request, httplib::Response& response) {
            std::string userId;
            try {
                userId = session_.verify(cookieValue(request, "session"), nowSeconds());
            } catch (const std::exception&) {
                response.status = 401;
                respondJson(response, {{"error", "not authenticated"}});
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body, nullptr, false);
            if (body.is_discarded() || !body.contains("captchaId")
                || !body.contains("captchaAnswer")) {
                response.status = 400;
                respondJson(response, {{"error", "bad request"}});
                return;
            }
            if (!captcha_.verify(body.at("captchaId").get<std::string>(),
                    body.at("captchaAnswer").get<std::string>(), nowSeconds())) {
                response.status = 403;
                respondJson(response, {{"error", "captcha failed"}});
                return;
            }
            grants_.grantSubscription(userId, options_.defaultQuotaBytes,
                options_.freeSubscriptionTermSeconds, nowSeconds());
            respondJson(response,
                {
                    {"ok", true},
                    {"quotaBytes", options_.defaultQuotaBytes},
                    {"termSeconds", options_.freeSubscriptionTermSeconds},
                });
        });

    // Wraps a handler so it only runs for a logged-in session, passing the user.
    const auto withSession = [this](auto handler) {
        return [this, handler](const httplib::Request& request, httplib::Response& response) {
            std::string userId;
            try {
                userId = session_.verify(cookieValue(request, "session"), nowSeconds());
            } catch (const std::exception&) {
                response.status = 401;
                respondJson(response, {{"error", "not authenticated"}});
                return;
            }
            handler(request, response, userId);
        };
    };

    // The user's prepaid balance.
    http_->Get("/portal/balance",
        withSession([this](const httplib::Request&, httplib::Response& response,
                        const std::string& userId) {
            respondJson(response,
                {
                    {"balanceAtomic", std::to_string(ledger_.get(userId).balanceAtomic)},
                    {"currency", options_.settlementCurrency},
                });
        }));

    // Top up: create a payment invoice for an atomic amount.
    http_->Post("/portal/topup",
        withSession([this](const httplib::Request& request, httplib::Response& response,
                        const std::string& userId) {
            const nlohmann::json body = nlohmann::json::parse(request.body, nullptr, false);
            if (body.is_discarded() || !body.contains("amount")) {
                response.status = 400;
                respondJson(response, {{"error", "bad request"}});
                return;
            }
            const Money amount{body.at("amount").get<std::string>(), options_.settlementCurrency};
            const Invoice invoice = gateway_.createInvoice(amount, "topup:" + userId);
            invoices_.put(invoice.id, userId);
            respondJson(response,
                {
                    {"invoiceId", invoice.id},
                    {"payTo", invoice.payTo},
                    {"amount", invoice.amount.amount},
                    {"currency", invoice.amount.currency},
                });
        }));

    // Poll an invoice; credit the balance once it confirms.
    http_->Get(R"(/portal/pay/([^/]+))",
        withSession([this](const httplib::Request& request, httplib::Response& response,
                        const std::string& userId) {
            const std::string invoiceId = request.matches[1].str();
            const PaymentStatus status = gateway_.checkStatus(invoiceId);
            settleInvoice(invoiceId, status, nowSeconds());
            respondJson(response,
                {
                    {"state", toString(status.state)},
                    {"paidAmount", status.paidAmount},
                    {"balanceAtomic", std::to_string(ledger_.get(userId).balanceAtomic)},
                });
        }));

    // Submit a txid for an invoice (the pull path when a callback was missed).
    http_->Post(R"(/portal/pay/([^/]+)/txid)",
        withSession([this](const httplib::Request& request, httplib::Response& response,
                        const std::string& userId) {
            const nlohmann::json body = nlohmann::json::parse(request.body, nullptr, false);
            if (body.is_discarded() || !body.contains("txid")) {
                response.status = 400;
                respondJson(response, {{"error", "bad request"}});
                return;
            }
            const std::string invoiceId = request.matches[1].str();
            const PaymentStatus status
                = gateway_.verifyByTxid(invoiceId, body.at("txid").get<std::string>());
            settleInvoice(invoiceId, status, nowSeconds());
            respondJson(response,
                {
                    {"state", toString(status.state)},
                    {"paidAmount", status.paidAmount},
                    {"balanceAtomic", std::to_string(ledger_.get(userId).balanceAtomic)},
                });
        }));

    // Gateway webhook (unauthenticated; the gateway authenticates the body's
    // HMAC and re-verifies the amount against the wallet).
    http_->Post(R"(/v1/pay/callback/([^/]+))",
        [this](const httplib::Request& request, httplib::Response& response) {
            const std::optional<PaymentStatus> status = gateway_.parseWebhook(
                request.body, request.get_header_value("X-Bazarish-Signature"));
            if (!status.has_value()) {
                response.status = 400;
                respondJson(response, {{"error", "invalid callback"}});
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body, nullptr, false);
            if (!body.is_discarded() && body.contains("invoiceId")) {
                settleInvoice(body.at("invoiceId").get<std::string>(), *status, nowSeconds());
            }
            respondJson(response, {{"ok", true}});
        });

    // Buy (or renew) a paid service: debit the balance, extend the entitlement.
    http_->Post("/portal/buy",
        withSession([this](const httplib::Request& request, httplib::Response& response,
                        const std::string& userId) {
            const nlohmann::json body = nlohmann::json::parse(request.body, nullptr, false);
            if (body.is_discarded() || !body.contains("service")) {
                response.status = 400;
                respondJson(response, {{"error", "bad request"}});
                return;
            }
            const std::string service = body.at("service").get<std::string>();
            const auto offered = options_.paidServices.find(service);
            if (offered == options_.paidServices.end()) {
                response.status = 404;
                respondJson(response, {{"error", "service not offered"}});
                return;
            }
            const std::int64_t now = nowSeconds();
            if (!ledger_.debit(userId, offered->second.priceAtomic, "buy:" + service, now)) {
                response.status = 402;
                respondJson(response, {{"error", "insufficient balance"}});
                return;
            }
            // Renewal stacks onto any remaining term.
            const std::optional<GrantStore::ServiceGrant> existing
                = grants_.peekService(userId, service);
            const std::int64_t base
                = existing.has_value() ? std::max(now, existing->paidThrough) : now;
            const std::int64_t paidThrough = base + offered->second.termSeconds;
            grants_.grantService(userId, service, paidThrough, now);
            // A storage purchase takes effect immediately: push the plan quota.
            if (service == "storage" && options_.publishQuota) {
                options_.publishQuota(userId, options_.storageQuotaBytes);
            }
            respondJson(response,
                {
                    {"ok", true},
                    {"service", service},
                    {"paidThrough", paidThrough},
                    {"balanceAtomic", std::to_string(ledger_.get(userId).balanceAtomic)},
                });
        }));
}

}  // namespace bazarish::service
