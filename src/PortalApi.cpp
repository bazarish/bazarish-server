// Bazarish project (c) 2026
#include "PortalApi.hpp"

#include "ServiceLifecycle.hpp"

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <exception>
#include <iterator>
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

// Escapes a string for safe interpolation into HTML text or a quoted attribute.
std::string htmlEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (const char c : s) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&#39;";
            break;
        default:
            out += c;
        }
    }
    return out;
}

// Wraps page body in the shared document shell. All styling is inline so the
// portal pulls in no third-party resource (no CDN font/script to phone home).
std::string htmlPage(const std::string& title, const std::string& body)
{
    return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
           "<title>"
        + htmlEscape(title)
        + " — Bazarish</title><style>"
          ":root{color-scheme:dark}"
          "*{box-sizing:border-box}"
          "body{margin:0;min-height:100vh;display:flex;justify-content:center;"
          "align-items:flex-start;background:#14161a;color:#e6e8eb;"
          "font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}"
          "main{width:100%;max-width:34rem;margin:2.5rem 1rem;padding:1.75rem;"
          "background:#1c1f24;border:1px solid #2a2f37;border-radius:14px}"
          "h1{font-size:1.25rem;margin:0 0 1.25rem}h2{font-size:1.05rem;margin:1.5rem 0 .5rem}"
          "a{color:#7cc0ff}label{display:block;margin:.75rem 0 .25rem;font-size:.9rem;color:#aeb4bd}"
          "input,textarea{width:100%;padding:.6rem;background:#0f1115;color:#e6e8eb;"
          "border:1px solid #333a44;border-radius:8px;font:inherit}"
          "textarea{resize:vertical}"
          "button{margin-top:1rem;padding:.6rem 1.1rem;background:#2f6feb;color:#fff;border:0;"
          "border-radius:8px;font:inherit;cursor:pointer}button:hover{background:#3b7df0}"
          "pre{background:#0f1115;border:1px solid #2a2f37;border-radius:8px;padding:.75rem;"
          "overflow-x:auto;font-size:.85rem;white-space:pre-wrap;word-break:break-all}"
          "code{font-size:.85rem;word-break:break-all}"
          ".flash{background:#16331f;border:1px solid #2c6b3f;color:#bfe9cd;padding:.6rem .8rem;"
          "border-radius:8px}.err{background:#3a1b1f;border:1px solid #7a2b34;color:#f3c2c8;"
          "padding:.6rem .8rem;border-radius:8px}"
          ".svc{border:1px solid #2a2f37;border-radius:10px;padding:.75rem 1rem;margin:.6rem 0}"
          ".svc form{display:inline}.muted{color:#8b929c;font-size:.85rem}"
          ".captcha{margin:.5rem 0;background:#fff;display:inline-block;border-radius:8px;padding:.25rem}"
          "</style></head><body><main><h1>Bazarish portal</h1>"
        + body + "</main></body></html>";
}

void sendHtml(httplib::Response& response, const std::string& html, const int status = 200)
{
    response.status = status;
    response.set_content(html, "text/html; charset=utf-8");
}

void redirectTo(httplib::Response& response, const std::string& location)
{
    response.status = 303;
    response.set_header("Location", location);
}

// A human-readable byte size for the free quota (powers of 1024).
std::string bytesHuman(const std::uint64_t bytes)
{
    const char* const units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(units)) {
        value /= 1024.0;
        ++unit;
    }
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), value < 10.0 ? "%.1f %s" : "%.0f %s", value, units[unit]);
    return buffer;
}

// Maps a post-redirect-get ?msg= code to a flash banner (empty if unknown).
std::string flashBanner(const std::string& code)
{
    std::string text;
    if (code == "registered") {
        text = "Free subscription registered — open your client to redeem it.";
    } else if (code == "bought") {
        text = "Purchase complete.";
    } else if (code == "insufficient") {
        text = "Insufficient balance — top up first.";
    } else if (code == "notoffered") {
        text = "That service is not offered here.";
    } else if (code == "i2pon") {
        text = "Personal I2P destination on — upload a key from your client to go live.";
    } else if (code == "i2poff") {
        text = "Personal I2P destination off — back on the shared pool address.";
    } else {
        return {};
    }
    return "<p class=\"flash\">" + htmlEscape(text) + "</p>";
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
    if (status.state != PaymentState::eConfirmed) {
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

PortalApi::BuyResult PortalApi::buyService(
    const std::string& user, const std::string& service, const std::int64_t now)
{
    const auto offered = options_.paidServices.find(service);
    if (offered == options_.paidServices.end()) {
        return {BuyOutcome::eNotOffered, 0};
    }
    if (!ledger_.debit(user, offered->second.priceAtomic, "buy:" + service, now)) {
        return {BuyOutcome::eInsufficient, 0};
    }
    // Renewal stacks onto any remaining term.
    const std::optional<GrantStore::ServiceGrant> existing = grants_.peekService(user, service);
    const std::int64_t base = existing.has_value() ? std::max(now, existing->paidThrough) : now;
    const std::int64_t paidThrough = base + offered->second.termSeconds;
    grants_.grantService(user, service, paidThrough, now);
    // A storage purchase takes effect immediately: push the plan quota.
    if (service == "storage" && options_.publishQuota) {
        options_.publishQuota(user, options_.storageQuotaBytes);
    }
    return {BuyOutcome::eOk, paidThrough};
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
            if (options_.requireCaptcha) {
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
            const BuyResult result = buyService(userId, service, nowSeconds());
            if (result.outcome == BuyOutcome::eNotOffered) {
                response.status = 404;
                respondJson(response, {{"error", "service not offered"}});
                return;
            }
            if (result.outcome == BuyOutcome::eInsufficient) {
                response.status = 402;
                respondJson(response, {{"error", "insufficient balance"}});
                return;
            }
            respondJson(response,
                {
                    {"ok", true},
                    {"service", service},
                    {"paidThrough", result.paidThrough},
                    {"balanceAtomic", std::to_string(ledger_.get(userId).balanceAtomic)},
                });
        }));

    // Turn the per-user i2p-dest option on/off (the cabinet toggle, JSON face).
    http_->Post("/portal/i2p-dest",
        withSession([this](const httplib::Request& request, httplib::Response& response,
                        const std::string& userId) {
            if (options_.lifecycle == nullptr) {
                response.status = 404;
                respondJson(response, {{"error", "not offered"}});
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body, nullptr, false);
            if (body.is_discarded() || !body.contains("enabled")) {
                response.status = 400;
                respondJson(response, {{"error", "bad request"}});
                return;
            }
            const bool enabled = body.at("enabled").get<bool>();
            const std::int64_t now = nowSeconds();
            if (enabled) {
                if (!options_.lifecycle->enableI2pDest(userId, now)) {
                    response.status = 402;
                    respondJson(response, {{"error", "insufficient balance"}});
                    return;
                }
            } else {
                options_.lifecycle->disableI2pDest(userId, now);
            }
            respondJson(response, {{"ok", true}, {"enabled", enabled}});
        }));

    setupWebRoutes();
}

void PortalApi::setupWebRoutes()
{
    // The logged-in user from the session cookie, or nullopt.
    const auto webUser = [this](const httplib::Request& request) -> std::optional<std::string> {
        try {
            return session_.verify(cookieValue(request, "session"), nowSeconds());
        } catch (const std::exception&) {
            return std::nullopt;
        }
    };

    // The sign-in-with-key page: a fresh challenge the user signs in their
    // client (the key never touches the browser), then pastes the blob back.
    const auto loginPage = [this]() {
        const std::string challenge = login_.issue(nowSeconds());
        const std::string body = "<p>Sign in with your key — your private key never enters the "
                                 "browser. Copy this challenge, sign it in your Bazarish client "
                                 "(Signature), and paste the result below.</p><pre>"
            + htmlEscape(challenge)
            + "</pre>"
              "<form method=\"post\" action=\"/login\">"
              "<input type=\"hidden\" name=\"challenge\" value=\""
            + htmlEscape(challenge)
            + "\"><label for=\"blob\">Signed blob</label>"
              "<textarea id=\"blob\" name=\"blob\" rows=\"4\" required></textarea>"
              "<button type=\"submit\">Sign in</button></form>";
        return htmlPage("Sign in", body);
    };

    // The free-registration page; embeds the captcha SVG inline when required.
    const auto registerPage = [this](const std::string& error) {
        std::string body;
        if (!error.empty()) {
            body += "<p class=\"err\">" + htmlEscape(error) + "</p>";
        }
        body += "<h2>Free registration</h2><p class=\"muted\">A free subscription (quota "
            + htmlEscape(bytesHuman(options_.defaultQuotaBytes))
            + "). Once registered, redeem it from your client.</p>"
              "<form method=\"post\" action=\"/register\">";
        if (options_.requireCaptcha) {
            const CaptchaChallenge challenge = captcha_.issue(nowSeconds());
            body += "<div class=\"captcha\">" + challenge.body + "</div>"
                    "<input type=\"hidden\" name=\"captchaId\" value=\""
                + htmlEscape(challenge.id)
                + "\"><label for=\"ca\">Enter the code</label>"
                  "<input id=\"ca\" name=\"captchaAnswer\" autocomplete=\"off\" required>";
        }
        body += "<button type=\"submit\">Register</button></form><p><a href=\"/\">Back</a></p>";
        return htmlPage("Register", body);
    };

    // The cabinet: balance, subscription state and the offered services.
    const auto cabinet = [this](const std::string& userId, const std::string& msg) {
        const std::int64_t now = nowSeconds();
        std::string body = flashBanner(msg);
        body += "<p class=\"muted\">Signed in as <code>" + htmlEscape(userId) + "</code></p>";

        // The server descriptor: paste it into a client to connect it here. Shown
        // as a legible string (no base64) so it can be checked at a glance.
        if (!options_.serverDescriptor.empty()) {
            body += "<h2>Server descriptor</h2>"
                    "<p class=\"muted\">Paste this into your client to connect it to this "
                    "server.</p><pre>"
                + htmlEscape(options_.serverDescriptor) + "</pre>";
        }

        body += "<h2>Balance</h2><p>" + std::to_string(ledger_.get(userId).balanceAtomic) + " "
            + htmlEscape(options_.settlementCurrency)
            + "</p><p><a href=\"/topup\">Top up</a></p>";

        body += "<h2>Subscription</h2>";
        const std::optional<GrantStore::SubscriptionGrant> sub = grants_.peekSubscription(userId);
        if (sub.has_value()) {
            body += "<p>Active (quota " + htmlEscape(bytesHuman(sub->quotaBytes)) + ").</p>";
        } else {
            body += "<p class=\"muted\">No subscription yet.</p>"
                    "<p><a href=\"/register\">Register (free)</a></p>";
        }

        // Per-user i2p-dest: an opt-in toggle (not a one-shot buy), with the
        // privacy trade-off spelled out. Off by default - the user already has a
        // free, fixed pool address; turning this on serves them on their own
        // stable destination, billed per term and auto-renewed from balance.
        const auto i2pPlan = options_.paidServices.find("i2pDest");
        if (options_.lifecycle != nullptr && i2pPlan != options_.paidServices.end()) {
            const ServiceLifecycle::Snapshot snap = options_.lifecycle->evaluate(userId, now);
            body += "<h2>Personal I2P destination</h2>"
                    "<div class=\"svc\"><p class=\"muted\">Off by default you share a fixed "
                    "address from the server pool. Turn this on to be served on your own stable "
                    "destination (portable across servers, kept even if you move). The trade-off: "
                    "your own destination is a unique, lasting address across all your contacts — "
                    "less crowd-blending than the shared pool.</p>";
            body += "<p>" + std::to_string(i2pPlan->second.priceAtomic) + " "
                + htmlEscape(options_.settlementCurrency) + " / "
                + std::to_string(i2pPlan->second.termSeconds / (24 * 3600)) + " days.</p>";
            if (snap.i2pDest.enabled && snap.i2pDest.active) {
                body += "<p class=\"muted\">On — active, "
                    + std::to_string((snap.i2pDest.paidThrough - now) / (24 * 3600))
                    + " days paid.</p>";
            } else if (snap.i2pDest.enabled) {
                body += "<p class=\"err\">On but unpaid — your personal destination is offline. "
                        "Top up to restore it, or turn it off to fall back to the pool.</p>";
            } else {
                body += "<p class=\"muted\">Off — using the shared pool address.</p>";
            }
            body += "<form method=\"post\" action=\"/i2p-dest\">"
                    "<input type=\"hidden\" name=\"enabled\" value=\""
                + std::string(snap.i2pDest.enabled ? "false" : "true")
                + "\"><button type=\"submit\">"
                + std::string(snap.i2pDest.enabled ? "Turn off" : "Turn on")
                + "</button></form></div>";
        }

        // Other paid services (e.g. storage) keep the one-shot buy/renew
        // flow. i2pDest is handled by its toggle above.
        bool anyOther = false;
        for (const auto& [name, service] : options_.paidServices) {
            if (name == "i2pDest") {
                continue;
            }
            anyOther = true;
            (void)service;
            break;
        }
        if (anyOther) {
            body += "<h2>Services</h2>";
            for (const auto& [name, service] : options_.paidServices) {
                if (name == "i2pDest") {
                    continue;
                }
                const std::optional<GrantStore::ServiceGrant> grant
                    = grants_.peekService(userId, name);
                body += "<div class=\"svc\"><strong>" + htmlEscape(name) + "</strong> — "
                    + std::to_string(service.priceAtomic) + " "
                    + htmlEscape(options_.settlementCurrency) + " / "
                    + std::to_string(service.termSeconds / (24 * 3600)) + " days<br>";
                if (grant.has_value() && grant->paidThrough > now) {
                    body += "<span class=\"muted\">active, "
                        + std::to_string((grant->paidThrough - now) / (24 * 3600))
                        + " days left</span> ";
                }
                body += "<form method=\"post\" action=\"/buy\">"
                        "<input type=\"hidden\" name=\"service\" value=\""
                    + htmlEscape(name)
                    + "\"><button type=\"submit\">"
                    + (grant.has_value() && grant->paidThrough > now ? "Renew" : "Buy")
                    + "</button></form></div>";
            }
        }

        body += "<form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>";
        return htmlPage("Portal", body);
    };

    // Home: the cabinet when logged in, otherwise the login page.
    http_->Get("/", [webUser, loginPage, cabinet](
                        const httplib::Request& request, httplib::Response& response) {
        const std::optional<std::string> user = webUser(request);
        if (!user.has_value()) {
            sendHtml(response, loginPage());
            return;
        }
        sendHtml(response, cabinet(*user, request.get_param_value("msg")));
    });

    http_->Get("/login", [loginPage](const httplib::Request&, httplib::Response& response) {
        sendHtml(response, loginPage());
    });

    http_->Post("/login", [this](const httplib::Request& request, httplib::Response& response) {
        try {
            const std::string userId = login_.verify(request.get_param_value("challenge"),
                request.get_param_value("blob"), nowSeconds());
            const std::string token = session_.issue(userId, nowSeconds());
            response.set_header(
                "Set-Cookie", "session=" + token + "; HttpOnly; SameSite=Strict; Path=/");
            redirectTo(response, "/");
        } catch (const std::exception&) {
            sendHtml(response,
                htmlPage("Sign in",
                    "<p class=\"err\">Sign-in failed — the challenge or blob was invalid or "
                    "expired.</p><p><a href=\"/login\">Try again</a></p>"),
                401);
        }
    });

    http_->Post("/logout", [](const httplib::Request&, httplib::Response& response) {
        response.set_header(
            "Set-Cookie", "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
        redirectTo(response, "/login");
    });

    http_->Get("/register", [webUser, registerPage](
                                const httplib::Request& request, httplib::Response& response) {
        if (!webUser(request).has_value()) {
            redirectTo(response, "/login");
            return;
        }
        sendHtml(response, registerPage(std::string()));
    });

    http_->Post("/register", [this, webUser, registerPage](
                                 const httplib::Request& request, httplib::Response& response) {
        const std::optional<std::string> user = webUser(request);
        if (!user.has_value()) {
            redirectTo(response, "/login");
            return;
        }
        if (options_.requireCaptcha
            && !captcha_.verify(request.get_param_value("captchaId"),
                request.get_param_value("captchaAnswer"), nowSeconds())) {
            sendHtml(response, registerPage("Captcha failed — try again."), 403);
            return;
        }
        grants_.grantSubscription(*user, options_.defaultQuotaBytes,
            options_.freeSubscriptionTermSeconds, nowSeconds());
        redirectTo(response, "/?msg=registered");
    });

    http_->Get("/topup", [this, webUser](
                             const httplib::Request& request, httplib::Response& response) {
        if (!webUser(request).has_value()) {
            redirectTo(response, "/login");
            return;
        }
        const std::string body = "<h2>Top up</h2><form method=\"post\" action=\"/topup\">"
                                 "<label for=\"amt\">Amount ("
            + htmlEscape(options_.settlementCurrency)
            + ")</label><input id=\"amt\" name=\"amount\" inputmode=\"decimal\" required>"
              "<button type=\"submit\">Create invoice</button></form><p><a href=\"/\">Back</a></p>";
        sendHtml(response, htmlPage("Top up", body));
    });

    http_->Post("/topup", [this, webUser](
                              const httplib::Request& request, httplib::Response& response) {
        const std::optional<std::string> user = webUser(request);
        if (!user.has_value()) {
            redirectTo(response, "/login");
            return;
        }
        const std::string amount = request.get_param_value("amount");
        if (amount.empty()) {
            sendHtml(response,
                htmlPage("Top up",
                    "<p class=\"err\">Enter an amount.</p><p><a href=\"/topup\">Back</a></p>"),
                400);
            return;
        }
        const Invoice invoice
            = gateway_.createInvoice(Money{amount, options_.settlementCurrency}, "topup:" + *user);
        invoices_.put(invoice.id, *user);
        const std::string body = "<h2>Invoice created</h2><p>Send <strong>"
            + htmlEscape(invoice.amount.amount) + " " + htmlEscape(invoice.amount.currency)
            + "</strong> to:</p><pre>" + htmlEscape(invoice.payTo)
            + "</pre><p><a href=\"/pay/" + htmlEscape(invoice.id)
            + "\">I've paid — check status</a></p><p><a href=\"/\">Back to portal</a></p>";
        sendHtml(response, htmlPage("Invoice", body));
    });

    http_->Get(R"(/pay/([^/]+))", [this, webUser](
                                      const httplib::Request& request, httplib::Response& response) {
        const std::optional<std::string> user = webUser(request);
        if (!user.has_value()) {
            redirectTo(response, "/login");
            return;
        }
        const std::string invoiceId = request.matches[1].str();
        const PaymentStatus status = gateway_.checkStatus(invoiceId);
        settleInvoice(invoiceId, status, nowSeconds());
        const std::string body = "<h2>Payment status</h2><p>Invoice <code>"
            + htmlEscape(invoiceId) + "</code></p><p>Status: <strong id=\"paystatus\">"
            + htmlEscape(toString(status.state)) + "</strong></p><p>Balance: <span id=\"paybal\">"
            + std::to_string(ledger_.get(*user).balanceAtomic) + "</span> "
            + htmlEscape(options_.settlementCurrency) + "</p><p><a href=\"/pay/"
            + htmlEscape(invoiceId)
            + "\">Refresh</a></p><form method=\"post\" action=\"/pay/" + htmlEscape(invoiceId)
            + "/txid\"><label for=\"tx\">Or submit a transaction id</label>"
              "<input id=\"tx\" name=\"txid\" required><button type=\"submit\">Submit txid</button>"
              "</form><p><a href=\"/\">Back to portal</a></p>"
              // Progressive enhancement: poll the JSON status endpoint so the page
              // reflects confirmation without a manual reload. Same-origin only (no
              // third-party request). With JS off, the Refresh link is the fallback.
              "<script>(function(){var s=document.getElementById('paystatus'),"
              "b=document.getElementById('paybal');function p(){"
              "fetch('/portal'+location.pathname,{headers:{Accept:'application/json'}})"
              ".then(function(r){return r.json()}).then(function(j){"
              "if(s)s.textContent=j.state;if(b)b.textContent=j.balanceAtomic;"
              "if(j.state!=='confirmed')setTimeout(p,4000)}).catch(function(){})}"
              "setTimeout(p,4000)})();</script>";
        sendHtml(response, htmlPage("Payment", body));
    });

    http_->Post(R"(/pay/([^/]+)/txid)", [this, webUser](const httplib::Request& request,
                                            httplib::Response& response) {
        const std::optional<std::string> user = webUser(request);
        if (!user.has_value()) {
            redirectTo(response, "/login");
            return;
        }
        const std::string invoiceId = request.matches[1].str();
        const PaymentStatus status
            = gateway_.verifyByTxid(invoiceId, request.get_param_value("txid"));
        settleInvoice(invoiceId, status, nowSeconds());
        redirectTo(response, "/pay/" + invoiceId);
    });

    http_->Post("/buy", [this, webUser](
                            const httplib::Request& request, httplib::Response& response) {
        const std::optional<std::string> user = webUser(request);
        if (!user.has_value()) {
            redirectTo(response, "/login");
            return;
        }
        const BuyResult result = buyService(*user, request.get_param_value("service"), nowSeconds());
        if (result.outcome == BuyOutcome::eNotOffered) {
            redirectTo(response, "/?msg=notoffered");
        } else if (result.outcome == BuyOutcome::eInsufficient) {
            redirectTo(response, "/?msg=insufficient");
        } else {
            redirectTo(response, "/?msg=bought");
        }
    });

    http_->Post("/i2p-dest", [this, webUser](
                                 const httplib::Request& request, httplib::Response& response) {
        const std::optional<std::string> user = webUser(request);
        if (!user.has_value()) {
            redirectTo(response, "/login");
            return;
        }
        if (options_.lifecycle == nullptr) {
            redirectTo(response, "/?msg=notoffered");
            return;
        }
        if (request.get_param_value("enabled") == "true") {
            if (!options_.lifecycle->enableI2pDest(*user, nowSeconds())) {
                redirectTo(response, "/?msg=insufficient");
                return;
            }
            redirectTo(response, "/?msg=i2pon");
        } else {
            options_.lifecycle->disableI2pDest(*user, nowSeconds());
            redirectTo(response, "/?msg=i2poff");
        }
    });
}

}  // namespace bazarish::service
