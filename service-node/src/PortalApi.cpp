// Bazarish project (c) 2026
#include "PortalApi.hpp"

#include <bazarish/ServerDescriptor.hpp>


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
#include <filesystem>
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
    , settings_(options_.settings
              ? options_.settings
              : std::make_shared<NodeSettings>(std::filesystem::path(),
                    NodeSettings::Values{.requireApproval = options_.requiresApproval,
                        .registrationMessage = options_.registrationMessage,
                        .portalMessage = {},
                        .loginConsumer = options_.consumer,
                        .requireCaptcha = options_.requireCaptcha,
                        .facades = {},
                        .reseeds = {},
                        .defaultQuotaBytes = options_.defaultQuotaBytes}))
    , assets_(options_.assetsDirectory)
    , captcha_(captcha)
    , grants_(grants)
    , login_(options_.challengeSecret, options_.consumer)
    , session_(options_.sessionSecret, options_.sessionTtlSeconds)
{
}

PortalApi::~PortalApi() = default;

LoginChallenge& PortalApi::login()
{
    const LoginConsumer wanted = settings().loginConsumer;
    // Settings that name no consumer - a test's, or a node whose operator has
    // never set one - leave the portal signing under the words it was built
    // with, which beats signing under none.
    const bool named
        = !wanted.name.empty() && !wanted.place.empty() && !wanted.role.empty();
    if (named && wanted != login_.consumer()) {
        login_.setConsumer(wanted);
    }
    return login_;
}

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
        respondJson(response, {{"challenge", login().issue(nowSeconds())}});
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
            const std::string userId = login().verify(body.at("challenge").get<std::string>(),
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
            const std::string userId = session_.verify(request.cookie("session"), nowSeconds());
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
                userId = session_.verify(request.cookie("session"), nowSeconds());
            } catch (const std::exception&) {
                response.status = 401;
                respondJson(response, {{"error", "not authenticated"}});
                return;
            }
            if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(userId);
                ban.has_value()) {
                response.status = 403;
                respondJson(response, {{"error", "banned"}, {"message", ban->reason}});
                return;
            }
            if (settings().requireCaptcha) {
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
            grants_.grantSubscription(userId, settings().defaultQuotaBytes,
                nowSeconds());
            respondJson(response,
                {
                    {"ok", true},
                    {"quotaBytes", settings().defaultQuotaBytes},
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
            return session_.verify(request.cookie("session"), nowSeconds());
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
        if (!user.empty() && !settings().requireCaptcha && !grants_.peekBan(user).has_value()
            && !grants_.peekSubscription(user).has_value()) {
            grants_.grantSubscription(user, settings().defaultQuotaBytes,
                nowSeconds());
        }
        sendHtml(response, homePage(user, std::string()));
    }));

    http_->post("/login", filled([this](const http::Request& request, http::Response& response) {
        try {
            const std::string userId = login().verify(request.param("challenge"),
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

    // An account's owner can end it from a browser: the same teardown the client
    // does on unsubscribe. Two steps, because the page has no script to ask
    // "are you sure" with.
    http_->post("/delete", filled([this, sessionUser](
                               const http::Request& request, http::Response& response) {
        const std::string user = sessionUser(request);
        if (user.empty()) {
            redirectTo(response, "/");
            return;
        }
        if (request.param("confirm") != "yes") {
            sendHtml(response,
                assets_.render("page.html",
                    {
                        {"title", "Delete"},
                        {"server", htmlEscape(options_.serverFingerprint)},
                        {"session", assets_.render("session.html",
                                        {{"fingerprint", htmlEscape(user)}})},
                        {"content", assets_.render("confirm-delete.html",
                                        accountValues(user, grants_.peekSubscription(user)))},
                    }));
            return;
        }
        if (!options_.deleteAccount) {
            sendHtml(response, homePage(user, "This portal cannot delete accounts."), 503);
            return;
        }
        options_.deleteAccount(user);
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
        if (grants_.peekBan(user).has_value()) {
            sendHtml(response, homePage(user, std::string()), 403);
            return;
        }
        if (settings().requireCaptcha
            && !captcha_.verify(
                request.param("captchaId"), request.param("captchaAnswer"), nowSeconds())) {
            sendHtml(response, homePage(user, "That is not the code. Here is another one."), 403);
            return;
        }
        grants_.grantSubscription(user, settings().defaultQuotaBytes,
            nowSeconds());
        redirectTo(response, "/");
    }));
}

std::map<std::string, std::string> PortalApi::accountValues(
    const std::string& user, const std::optional<GrantStore::SubscriptionGrant>& subscription)
{
    const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
    const NodeSettings::Values values = settings();
    const std::uint64_t granted
        = subscription.has_value() ? subscription->quotaBytes : values.defaultQuotaBytes;
    // The operator's own words for this account when they wrote any, the
    // node-wide message otherwise.
    const std::string note = approval.has_value() && !approval->message.empty()
        ? approval->message
        : values.registrationMessage;

    std::string mailbox = "not known";
    std::string devices = "not known";
    if (options_.accountUsage) {
        if (const std::optional<PortalApiOptions::Usage> usage = options_.accountUsage(user);
            usage.has_value()) {
            mailbox = bytesHuman(usage->usedBytes) + " of " + bytesHuman(usage->quotaBytes);
            devices = std::to_string(usage->devices);
        }
    }

    return {
        {"quota", htmlEscape(bytesHuman(granted))},
        // Built from the facades the operator keeps, so the panel and the page
        // can never show different ways in.
        {"descriptor",
            htmlEscape(settings().facades.empty()
                    ? options_.serverDescriptor
                    : encodeServerDescriptor(
                        {options_.serverFingerprint, settings().facades, settings().reseeds}))},
        {"message", notice(note, "is-waiting")},
        {"mailbox", htmlEscape(mailbox)},
        {"devices", htmlEscape(devices)},
    };
}

std::string PortalApi::homePage(const std::string& user, const std::string& error)
{
    const std::string server = htmlEscape(options_.serverFingerprint);
    if (user.empty()) {
        const std::string challenge = login().issue(nowSeconds());
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
    // A refused key is told so and nothing else: no captcha, no terms, no way in.
    if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(user); ban.has_value()) {
        return assets_.render("page.html",
            {
                {"title", "Refused"},
                {"server", server},
                {"session", session},
                {"content",
                    assets_.render("banned.html", {{"message", htmlEscape(ban->reason)}})},
            });
    }

    const std::optional<GrantStore::SubscriptionGrant> subscription = grants_.peekSubscription(user);
    const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);

    const std::map<std::string, std::string> account = accountValues(user, subscription);

    std::string title;
    std::string content;
    if (approval.has_value() && approval->pending()) {
        title = "Waiting";
        content = assets_.render("waiting.html", account);
    } else if (subscription.has_value() || approval.has_value()) {
        title = "Registered";
        content = assets_.render(
            settings().requireApproval ? "registered-approval.html" : "registered.html", account);
    } else {
        title = "Register";
        const CaptchaChallenge challenge = captcha_.issue(nowSeconds());
        content = assets_.render("register.html",
            {
                {"quota", htmlEscape(bytesHuman(settings().defaultQuotaBytes))},
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
