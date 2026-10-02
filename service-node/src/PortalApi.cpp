// Bazarish project (c) 2026
#include "PortalApi.hpp"

#include <bazarish/ServerDescriptor.hpp>


#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Log.hpp>

#include <functional>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <iterator>
#include <map>
#include <optional>
#include <utility>

namespace {

// How long the portal keeps the archive it fetched. The messaging server repacks
// only hourly, so a short hold is enough to keep a burst of clients off the
// private channel without ever serving something much older than it has.
constexpr std::int64_t kReseedHoldSeconds = 300;

namespace http = bazarish::http;

using bazarish::nowSeconds;
using bazarish::htmlEscape;
using bazarish::http::filled;

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

void sendHtml(http::Response& response, const std::string& html, const int status = 200)
{
    response.status = status;
    response.contentType = "text/html; charset=utf-8";
    // Every page carries a single-use challenge, so a page served from a cache
    // would be a page that no longer works.
    response.headers["Cache-Control"] = "no-store";
    response.body = html;
}

void redirectTo(http::Response& response, const std::string& location)
{
    response.status = 303;
    response.headers["Location"] = location;
}

// The attributes every one of the portal's cookies carries. Written once: three
// copies of a cookie line are three places for one of them to lose a flag.
const char* const kSessionCookie = "session";
const char* const kCookieAttributes = "; HttpOnly; SameSite=Strict; Path=/";

void setSessionCookie(http::Response& response, const std::string& token)
{
    response.headers["Set-Cookie"]
        = std::string(kSessionCookie) + "=" + token + kCookieAttributes;
}

void clearSessionCookie(http::Response& response)
{
    response.headers["Set-Cookie"]
        = std::string(kSessionCookie) + "=" + kCookieAttributes + "; Max-Age=0";
}

constexpr std::size_t kSizeTextBytes = 32;

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

PortalApi::PortalApi(PortalApiOptions options, GrantStore& grants)
    : options_(std::move(options))
    , settings_(options_.settings)
    , assets_(options_.assetsDirectory)
    , grants_(grants)
    , login_(options_.challengeSecret, settings_->get().loginConsumer)
    , session_(options_.sessionSecret, options_.sessionTtlSeconds)
{
}

PortalApi::~PortalApi() = default;

LoginChallenge& PortalApi::login()
{
    // The words an operator renamed the portal to, picked up without a restart.
    if (const LoginConsumer wanted = settings().loginConsumer; wanted != login_.consumer()) {
        login_.setConsumer(wanted);
    }
    return login_;
}

int PortalApi::bind(const std::string& host, const int port)
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

void PortalApi::wait()
{
    stopGate_.wait();
}

void PortalApi::stop()
{
    stopGate_.stop();
    if (http_) {
        http_->stop();
    }
}

void PortalApi::setupRoutes()
{
    http_->get("/portal/login", filled([this](const http::Request&, http::Response& response) {
        respondJson(response, {{"challenge", login().issue(nowSeconds())}});
    }));

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
            setSessionCookie(response, session_.issue(userId, nowSeconds()));
            respondJson(response, {{"ok", true}, {"userId", userId}});
        } catch (const std::exception&) {
            response.status = 401;
            respondJson(response, {{"error", "login failed"}});
        }
    }));

    http_->get("/portal/me", filled([this](const http::Request& request, http::Response& response) {
        try {
            const std::string userId
                = session_.verify(request.cookie(kSessionCookie), nowSeconds());
            respondJson(response, {{"userId", userId}});
        } catch (const std::exception&) {
            response.status = 401;
            respondJson(response, {{"error", "not authenticated"}});
        }
    }));

    // Registration: proving the key is the whole of it, so a logged-in user who
    // is not banned gets the pending subscription grant the Client then redeems
    // with its signed cert.
    http_->post(
        "/portal/register", filled([this](const http::Request& request, http::Response& response) {
            std::string userId;
            try {
                userId = session_.verify(request.cookie(kSessionCookie), nowSeconds());
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
            const std::uint64_t quota = settings().defaultQuotaBytes;
            grants_.grantSubscription(userId, quota, nowSeconds());
            respondJson(response, {{"ok", true}, {"quotaBytes", quota}});
        }));

    setupWebRoutes();
}

std::string PortalApi::reseedArchive()
{
    const std::lock_guard<std::mutex> lock(reseedMutex_);
    const std::int64_t now = nowSeconds();
    if (!reseedSu3_.empty() && now - reseedFetchedAt_ < kReseedHoldSeconds) {
        return reseedSu3_;
    }
    try {
        const bazarish::http::Url archive = bazarish::http::parseUrl(options_.reseedArchiveUrl);
        bazarish::http::ClientRequest ask;
        ask.method = "GET";
        ask.target = archive.path.empty() ? "/" : archive.path;
        const bazarish::http::ClientResponse answer
            = bazarish::http::request(archive.host, archive.port, ask, {});
        if (answer.status != 200 || answer.body.empty()) {
            bazarish::log::warn("portal: the messaging server has no reseed archive ({})",
                answer.status);
            return reseedSu3_;  // whatever was fetched before, or nothing
        }
        reseedSu3_ = answer.body;
        reseedFetchedAt_ = now;
    } catch (const std::exception& error) {
        bazarish::log::warn("portal: could not fetch the reseed archive: {}", error.what());
    }
    return reseedSu3_;
}

void PortalApi::setupWebRoutes()
{
    if (!options_.reseedArchiveUrl.empty()) {
        // The reseed, published where the clearnet already reaches: a client with
        // no I2P cannot ask a facade for anything, and this is the one file it
        // needs before it has any. Under the name the format gives it, so a
        // router appends it to whatever address the descriptor names and no
        // special case is needed anywhere. Fetched from the messaging server on
        // the private channel and held for kReseedHoldSeconds - that server packs
        // a fresh one only hourly, so asking it more often buys nothing.
        http_->get("/i2pseeds.su3", [this](const http::Request&) {
            http::Response response;
            const std::string archive = reseedArchive();
            if (archive.empty()) {
                response.status = 503;
                response.contentType = "text/plain";
                response.body = "no reseed available";
                return response;
            }
            response.contentType = "application/octet-stream";
            response.body = archive;
            return response;
        });
    }

    // The portal's own files, answered from memory. Registering them one by one
    // keeps the directory a site rather than a file share: only what the
    // operator put there, and nothing above it, can be asked for.
    for (const std::string& name : assets_.published()) {
        const WebAssets::File& file = assets_.file(name);
        http_->get("/" + name, [&file](const http::Request& request) {
            return serveWebAsset(file, request);
        });
    }

    // The signed-in user, or empty for a visitor.
    const auto sessionUser = [this](const http::Request& request) -> std::string {
        try {
            return session_.verify(request.cookie(kSessionCookie), nowSeconds());
        } catch (const std::exception&) {
            return {};
        }
    };

    http_->get("/", filled([this, sessionUser](
                        const http::Request& request, http::Response& response) {
        const std::string user = sessionUser(request);
        // Proving the key is the registration, so it happens as the key is
        // proven instead of behind a button that would only repeat the question.
        // A moderated node grants the same thing and holds the account until an
        // operator approves it.
        if (!user.empty() && !grants_.peekBan(user).has_value()
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
            setSessionCookie(response, session_.issue(userId, nowSeconds()));
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
        clearSessionCookie(response);
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
                page("Delete", assets_.render("session.html", {{"fingerprint", htmlEscape(user)}}),
                    assets_.render("confirm-delete.html",
                        accountValues(user, grants_.peekSubscription(user)))));
            return;
        }
        if (!options_.deleteAccount) {
            sendHtml(response, homePage(user, "This portal cannot delete accounts."), 503);
            return;
        }
        options_.deleteAccount(user);
        clearSessionCookie(response);
        redirectTo(response, "/");
    }));
}

std::string PortalApi::page(
    const std::string& title, const std::string& session, const std::string& content)
{
    return assets_.render("page.html",
        {
            {"title", htmlEscape(title)},
            {"server", htmlEscape(options_.serverFingerprint)},
            {"session", session},
            {"content", content},
        });
}

std::map<std::string, std::string> PortalApi::accountValues(
    const std::string& user, const std::optional<GrantStore::SubscriptionGrant>& subscription)
{
    const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
    // One snapshot for the whole answer: read field by field, an operator saving a
    // change mid-call would be answered half in the old terms and half in the new.
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
        if (const std::optional<MailboxUsage> usage = options_.accountUsage(user);
            usage.has_value()) {
            mailbox = bytesHuman(usage->usedBytes) + " of " + bytesHuman(usage->quotaBytes);
            devices = std::to_string(usage->devices);
        }
    }

    return {
        {"quota", htmlEscape(bytesHuman(granted))},
        // Built from the facades the operator keeps, so the panel and the page can
        // never show different ways in.
        {"descriptor",
            htmlEscape(encodeServerDescriptor(
                {options_.serverFingerprint, values.facades, values.reseeds}))},
        {"message", notice(note, "is-waiting")},
        {"mailbox", htmlEscape(mailbox)},
        {"devices", htmlEscape(devices)},
    };
}

std::string PortalApi::homePage(const std::string& user, const std::string& error)
{
    if (user.empty()) {
        return page("Sign in", std::string(),
            assets_.render("signin.html",
                {
                    {"challenge", htmlEscape(login().issue(nowSeconds()))},
                    {"error", notice(error, "is-error")},
                }));
    }

    const std::string session
        = assets_.render("session.html", {{"fingerprint", htmlEscape(user)}});
    // A refused key is told so and nothing else: no terms, no way in.
    if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(user); ban.has_value()) {
        return page("Refused", session,
            assets_.render("banned.html", {{"message", htmlEscape(ban->reason)}}));
    }

    const std::map<std::string, std::string> account
        = accountValues(user, grants_.peekSubscription(user));
    // A signed-in key that is not banned was registered as it signed in, so there
    // is no third state to draw here.
    const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
    if (approval.has_value() && approval->pending()) {
        return page("Waiting", session, assets_.render("waiting.html", account));
    }
    return page("Registered", session,
        assets_.render(settings().requireApproval ? "registered-approval.html" : "registered.html",
            account));
}

}  // namespace bazarish::service
