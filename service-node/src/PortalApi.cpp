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
#include <map>
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

void sendHtml(http::Response& response, const std::string& html, const int status = 200)
{
    response.status = status;
    response.contentType = "text/html; charset=utf-8";
    // Every page carries a single-use challenge or a single-use captcha, so a
    // page served from a cache would be a page that no longer works.
    response.headers["Cache-Control"] = "no-store";
    response.body = html;
}

void redirectTo(http::Response& response, const std::string& location)
{
    response.status = 303;
    response.headers["Location"] = location;
}

constexpr std::size_t kSizeTextBytes = 32;
constexpr std::int64_t kSecondsPerDay = 24 * 3600;

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
    char buffer[kSizeTextBytes];
    std::snprintf(buffer, sizeof(buffer), value < 10.0 ? "%.1f %s" : "%.0f %s", value, units[unit]);
    return buffer;
}

// A notice the node fills into a template's {{error}} / {{message}}: it has to
// disappear entirely when there is nothing to say, which a placeholder in a file
// cannot do on its own.
std::string notice(const std::string& text, const std::string& kind)
{
    if (text.empty()) {
        return {};
    }
    return "<p class=\"notice " + kind + "\">" + htmlEscape(text) + "</p>";
}

}  // namespace

namespace bazarish::service {

PortalApi::PortalApi(PortalApiOptions options, Captcha& captcha, GrantStore& grants)
    : options_(std::move(options))
    , assets_(options_.assetsDirectory)
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
    // The portal's own files, answered from memory. Registering them one by one
    // keeps the directory a site rather than a file share: only what the
    // operator put there, and nothing above it, can be asked for.
    for (const std::string& name : assets_.published()) {
        const WebAssets::File& file = assets_.file(name);
        http_->get("/" + name, [&file](const http::Request&) {
            http::Response response;
            response.contentType = file.contentType;
            response.body = file.body;
            return response;
        });
    }

    // The logged-in user from the session cookie, or an empty string.
    const auto sessionUser = [this](const http::Request& request) -> std::string {
        try {
            return session_.verify(cookieValue(request, "session"), nowSeconds());
        } catch (const std::exception&) {
            return {};
        }
    };

    http_->get("/", filled([this, sessionUser](
                        const http::Request& request, http::Response& response) {
        const std::string user = sessionUser(request);
        // A node that asks for no captcha has nothing left to ask: proving the
        // key is the registration, so it happens as the key is proven instead of
        // behind a button that would only repeat the question.
        if (!user.empty() && !options_.requireCaptcha
            && !grants_.peekSubscription(user).has_value()) {
            grants_.grantSubscription(user, options_.defaultQuotaBytes,
                options_.freeSubscriptionTermSeconds, nowSeconds());
        }
        sendHtml(response, homePage(user, std::string()));
    }));

    http_->post("/login", filled([this](const http::Request& request, http::Response& response) {
        try {
            const std::string userId = login_.verify(request.param("challenge"),
                request.param("blob"), nowSeconds());
            const std::string token = session_.issue(userId, nowSeconds());
            response.headers["Set-Cookie"]
                = "session=" + token + "; HttpOnly; SameSite=Strict; Path=/";
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            bazarish::log::debug("portal sign-in refused: {}", error.what());
            sendHtml(response,
                homePage(std::string(),
                    "That signature did not check out. Sign the challenge below and paste the "
                    "result again."),
                401);
        }
    }));

    http_->post("/logout", filled([](const http::Request&, http::Response& response) {
        response.headers["Set-Cookie"] = "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
        redirectTo(response, "/");
    }));

    // Reading the captcha is the registration: there is no further step, and no
    // account area to move on to.
    http_->post("/register", filled([this, sessionUser](
                                 const http::Request& request, http::Response& response) {
        const std::string user = sessionUser(request);
        if (user.empty()) {
            redirectTo(response, "/");
            return;
        }
        if (options_.requireCaptcha
            && !captcha_.verify(
                request.param("captchaId"), request.param("captchaAnswer"), nowSeconds())) {
            sendHtml(response, homePage(user, "That is not the code. Here is another one."), 403);
            return;
        }
        grants_.grantSubscription(user, options_.defaultQuotaBytes,
            options_.freeSubscriptionTermSeconds, nowSeconds());
        redirectTo(response, "/");
    }));
}

std::string PortalApi::homePage(const std::string& user, const std::string& error)
{
    const std::string server = htmlEscape(options_.audience);
    if (user.empty()) {
        const std::string challenge = login_.issue(nowSeconds());
        return assets_.render("page.html",
            {
                {"title", "Sign in"},
                {"server", server},
                {"session", std::string()},
                {"content",
                    assets_.render("signin.html",
                        {
                            {"challenge", htmlEscape(challenge)},
                            {"error", notice(error, "is-error")},
                        })},
            });
    }

    const std::string session
        = assets_.render("session.html", {{"fingerprint", htmlEscape(user)}});
    const std::optional<GrantStore::SubscriptionGrant> subscription = grants_.peekSubscription(user);
    const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
    const std::string operatorNote = notice(options_.registrationMessage, "is-waiting");

    // What the account is worth saying about, wherever it stands: a user waiting
    // for an operator needs the terms and the descriptor as much as one already
    // served.
    const std::uint64_t quota
        = subscription.has_value() ? subscription->quotaBytes : options_.defaultQuotaBytes;
    const std::map<std::string, std::string> account = {
        {"quota", htmlEscape(bytesHuman(quota))},
        {"term", std::to_string(options_.freeSubscriptionTermSeconds / kSecondsPerDay) + " days"},
        {"descriptor", htmlEscape(options_.serverDescriptor)},
        {"message", operatorNote},
    };

    std::string title;
    std::string content;
    if (approval.has_value() && approval->pending()) {
        title = "Waiting";
        content = assets_.render("waiting.html", account);
    } else if (subscription.has_value() || approval.has_value()) {
        title = "Registered";
        content = assets_.render(
            options_.requiresApproval ? "registered-approval.html" : "registered.html", account);
    } else {
        title = "Register";
        const CaptchaChallenge challenge = captcha_.issue(nowSeconds());
        content = assets_.render("register.html",
            {
                {"quota", htmlEscape(bytesHuman(options_.defaultQuotaBytes))},
                {"captcha", challenge.body},
                {"captchaId", htmlEscape(challenge.id)},
                {"error", notice(error, "is-error")},
            });
    }

    return assets_.render("page.html",
        {
            {"title", htmlEscape(title)},
            {"server", server},
            {"session", session},
            {"content", content},
        });
}

}  // namespace bazarish::service
