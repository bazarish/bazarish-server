// Bazarish project (c) 2026
#include "PortalApi.hpp"


#include <bazarish/HttpServer.hpp>
#include <bazarish/Log.hpp>

#include <functional>
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

namespace http = bazarish::http;

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

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

// Reads one cookie value from the request's Cookie header.
std::string cookieValue(const http::Request& request, const std::string& name)
{
    const std::string cookies = request.header("Cookie");
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

void sendHtml(http::Response& response, const std::string& html, const int status = 200)
{
    response.status = status;
    response.contentType = "text/html; charset=utf-8";
    response.body = html;
}

void redirectTo(http::Response& response, const std::string& location)
{
    response.status = 303;
    response.headers["Location"] = location;
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
        text = "Registered — open your client to redeem it.";
    } else {
        return {};
    }
    return "<p class=\"flash\">" + htmlEscape(text) + "</p>";
}

}  // namespace

namespace bazarish::service {

PortalApi::PortalApi(PortalApiOptions options, Captcha& captcha, GrantStore& grants)
    : options_(std::move(options))
    , captcha_(captcha)
    , grants_(grants)
    , login_(options_.challengeSecret, options_.audience)
    , session_(options_.sessionSecret, options_.sessionTtlSeconds)
{
}

PortalApi::~PortalApi() = default;

bool PortalApi::listen(const std::string& host, const int port)
{
    if (bindToAnyPort(host, port) <= 0) {
        return false;
    }
    return listenAfterBind();
}

int PortalApi::bindToAnyPort(const std::string& host)
{
    return bindToAnyPort(host, 0);  // 0: the kernel picks the port
}

int PortalApi::bindToAnyPort(const std::string& host, const int port)
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

bool PortalApi::listenAfterBind()
{
    // The engine serves on its own threads; this call is what keeps the caller's
    // thread (a main()) parked until stop().
    std::unique_lock<std::mutex> lock(stopMutex_);
    stopCv_.wait(lock, [this]() { return stopping_; });
    return true;
}

void PortalApi::stop()
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

void PortalApi::setupRoutes()
{
    // Issue a fresh login challenge for the user to sign with their Client.
    http_->get("/portal/login", filled([this](const http::Request&, http::Response& response) {
        respondJson(response, {{"challenge", login_.issue(nowSeconds())}});
    }));

    // Verify the signed challenge and start a session.
    http_->post("/portal/login", filled([this](const http::Request& request,
                                      http::Response& response) {
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
            response.headers["Set-Cookie"]
                = "session=" + token + "; HttpOnly; SameSite=Strict; Path=/";
            respondJson(response, {{"ok", true}, {"userId", userId}});
        } catch (const std::exception&) {
            response.status = 401;
            respondJson(response, {{"error", "login failed"}});
        }
    }));

    // The logged-in user, from the session cookie.
    http_->get("/portal/me", filled([this](const http::Request& request, http::Response& response) {
        try {
            const std::string userId = session_.verify(cookieValue(request, "session"), nowSeconds());
            respondJson(response, {{"userId", userId}});
        } catch (const std::exception&) {
            response.status = 401;
            respondJson(response, {{"error", "not authenticated"}});
        }
    }));

    // A captcha to present before free registration.
    http_->get("/portal/captcha", filled([this](const http::Request&, http::Response& response) {
        const CaptchaChallenge challenge = captcha_.issue(nowSeconds());
        respondJson(response,
            {
                {"captchaId", challenge.id},
                {"contentType", challenge.contentType},
                {"body", challenge.body},
            });
    }));

    // Free registration: a logged-in user passes the captcha; the node records a
    // pending subscription grant the Client then redeems with its signed cert.
    http_->post(
        "/portal/register", filled([this](const http::Request& request, http::Response& response) {
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
        }));

    setupWebRoutes();
}

void PortalApi::setupWebRoutes()
{
    // The logged-in user from the session cookie, or nullopt.
    const auto webUser = [this](const http::Request& request) -> std::optional<std::string> {
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

        body += "<h2>Subscription</h2>";
        const std::optional<GrantStore::SubscriptionGrant> sub = grants_.peekSubscription(userId);
        const std::optional<GrantStore::Approval> approval = grants_.peekApproval(userId);
        if (approval.has_value() && approval->pending()) {
            body += "<p class=\"err\">Awaiting operator approval — your account exists but is "
                    "not served yet.</p>";
            if (!options_.registrationMessage.empty()) {
                body += "<p>" + htmlEscape(options_.registrationMessage) + "</p>";
            }
        } else if (approval.has_value()) {
            body += "<p>Active (quota " + htmlEscape(bytesHuman(options_.defaultQuotaBytes))
                + ").</p>";
        } else if (sub.has_value()) {
            body += "<p>Registered (quota " + htmlEscape(bytesHuman(sub->quotaBytes))
                + ") — open your client to redeem it.</p>";
        } else {
            body += "<p class=\"muted\">No subscription yet.</p>"
                    "<p><a href=\"/register\">Register</a></p>";
        }

        body += "<form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>";
        return htmlPage("Portal", body);
    };

    // Home: the cabinet when logged in, otherwise the login page.
    http_->get("/", filled([webUser, loginPage, cabinet](
                        const http::Request& request, http::Response& response) {
        const std::optional<std::string> user = webUser(request);
        if (!user.has_value()) {
            sendHtml(response, loginPage());
            return;
        }
        sendHtml(response, cabinet(*user, request.query("msg")));
    }));

    http_->get("/login", filled([loginPage](const http::Request&, http::Response& response) {
        sendHtml(response, loginPage());
    }));

    http_->post("/login", filled([this](const http::Request& request, http::Response& response) {
        try {
            const std::string userId = login_.verify(request.param("challenge"),
                request.param("blob"), nowSeconds());
            const std::string token = session_.issue(userId, nowSeconds());
            response.headers["Set-Cookie"]
                = "session=" + token + "; HttpOnly; SameSite=Strict; Path=/";
            redirectTo(response, "/");
        } catch (const std::exception&) {
            sendHtml(response,
                htmlPage("Sign in",
                    "<p class=\"err\">Sign-in failed — the challenge or blob was invalid or "
                    "expired.</p><p><a href=\"/login\">Try again</a></p>"),
                401);
        }
    }));

    http_->post("/logout", filled([](const http::Request&, http::Response& response) {
        response.headers["Set-Cookie"] = "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
        redirectTo(response, "/login");
    }));

    http_->get("/register", filled([webUser, registerPage](
                                const http::Request& request, http::Response& response) {
        if (!webUser(request).has_value()) {
            redirectTo(response, "/login");
            return;
        }
        sendHtml(response, registerPage(std::string()));
    }));

    http_->post("/register", filled([this, webUser, registerPage](
                                 const http::Request& request, http::Response& response) {
        const std::optional<std::string> user = webUser(request);
        if (!user.has_value()) {
            redirectTo(response, "/login");
            return;
        }
        if (options_.requireCaptcha
            && !captcha_.verify(request.param("captchaId"),
                request.param("captchaAnswer"), nowSeconds())) {
            sendHtml(response, registerPage("Captcha failed — try again."), 403);
            return;
        }
        grants_.grantSubscription(*user, options_.defaultQuotaBytes,
            options_.freeSubscriptionTermSeconds, nowSeconds());
        redirectTo(response, "/?msg=registered");
    }));

}

}  // namespace bazarish::service
