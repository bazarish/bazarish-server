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
    response.headers["Cache-Control"] = "no-store";
    response.body = html;
}

void redirectTo(http::Response& response, const std::string& location)
{
    response.status = 303;
    response.headers["Location"] = location;
}

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
    , messages_(options_.assetsDirectory / "messages.json")
    , grants_(grants)
    , login_(options_.challengeSecret, settings_->get().loginConsumer)
    , session_(options_.sessionSecret, options_.sessionTtlSeconds)
{
}

PortalApi::~PortalApi() = default;

LoginChallenge& PortalApi::login()
{
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
            return reseedSu3_;
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

    for (const std::string& name : assets_.published()) {
        const WebAssets::File& file = assets_.file(name);
        http_->get("/" + name, [&file](const http::Request& request) {
            return serveWebAsset(file, request);
        });
    }

    http_->get("/lang/([a-z-]+)", [this](const http::Request& request) {
        http::Response answer;
        const std::string asked = request.captures.at(0);
        if (messages_.knows(asked)) {
            answer.headers["Set-Cookie"] = languageCookie(asked);
        }
        redirectTo(answer, sameSitePath(request.query("back")));
        return answer;
    });

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
        if (!user.empty() && !grants_.peekBan(user).has_value()
            && !grants_.peekSubscription(user).has_value()) {
            grants_.grantSubscription(user, settings().defaultQuotaBytes,
                nowSeconds());
        }
        sendHtml(response, homePage(request, user, std::string()));
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
                homePage(request, std::string(), "{{t.signin.failed}}"),
                401);
        }
    }));

    http_->post("/logout", filled([](const http::Request&, http::Response& response) {
        clearSessionCookie(response);
        redirectTo(response, "/");
    }));

    http_->post("/delete", filled([this, sessionUser](
                               const http::Request& request, http::Response& response) {
        const std::string user = sessionUser(request);
        if (user.empty()) {
            redirectTo(response, "/");
            return;
        }
        if (request.param("confirm") != "yes") {
            sendHtml(response,
                page(request, "Delete", assets_.render("session.html", {{"fingerprint", htmlEscape(user)}}),
                    assets_.render("confirm-delete.html",
                        accountValues(user, grants_.peekSubscription(user)))));
            return;
        }
        if (!options_.deleteAccount) {
            sendHtml(response, homePage(request, user, "{{t.delete.refused}}"), 503);
            return;
        }
        options_.deleteAccount(user);
        clearSessionCookie(response);
        redirectTo(response, "/");
    }));
}

std::string PortalApi::page(const http::Request& request, const std::string& title,
    const std::string& session, const std::string& content)
{
    const std::string lang = language(request);
    const std::string drawn = assets_.render("page.html",
        {
            {"title", htmlEscape(title)},
            {"strapline",
                htmlEscape(messages_.text(
                    "page.strapline", lang, {options_.serverFingerprint}))},
            {"session", session},
            {"content", content},
            {"lang", lang},
            {"dir", messages_.language(lang).rightToLeft ? "rtl" : "ltr"},
            {"switch", languageSwitch(lang, request.target)},
        });
    return messages_.translate(drawn, lang);
}

std::string PortalApi::language(const http::Request& request) const
{
    return messages_.codeFor(request.cookie("lang"));
}

std::string PortalApi::languageSwitch(const std::string& lang, const std::string& here) const
{
    std::string list;
    for (const Language& language : messages_.languages()) {
        const bool current = language.code == lang;
        list += "      <li><a class=\"lang-one" + std::string(current ? " is-on" : "")
            + "\" href=\"/lang/" + language.code + "?back=" + urlEncode(sameSitePath(here))
            + "\"" + (current ? " aria-current=\"true\"" : "") + ">" + htmlEscape(language.name)
            + "</a></li>\n";
    }
    return "  <details class=\"lang\">\n    <summary class=\"lang-now\" aria-label=\""
        + htmlEscape(messages_.text("switch.title", lang)) + "\">"
        + htmlEscape(messages_.language(lang).name) + "</summary>\n    <ul class=\"lang-list\">\n"
        + list + "    </ul>\n  </details>\n";
}

std::map<std::string, std::string> PortalApi::accountValues(
    const std::string& user, const std::optional<GrantStore::SubscriptionGrant>& subscription)
{
    const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
    const NodeSettings::Values values = settings();
    const std::uint64_t granted
        = subscription.has_value() ? subscription->quotaBytes : values.defaultQuotaBytes;
    const std::string note = approval.has_value() && !approval->message.empty()
        ? approval->message
        : values.registrationMessage;

    std::string mailbox = "{{t.facts.unknown}}";
    std::string devices = "{{t.facts.unknown}}";
    if (options_.accountUsage) {
        if (const std::optional<MailboxUsage> usage = options_.accountUsage(user);
            usage.has_value()) {
            mailbox = bytesHuman(usage->usedBytes) + " of " + bytesHuman(usage->quotaBytes);
            devices = std::to_string(usage->devices);
        }
    }

    return {
        {"quota", htmlEscape(bytesHuman(granted))},
        {"descriptor",
            htmlEscape(encodeServerDescriptor(
                {options_.serverFingerprint, values.facades, values.reseeds}))},
        {"message", notice(note, "is-waiting")},
        {"mailbox", htmlEscape(mailbox)},
        {"devices", htmlEscape(devices)},
    };
}

std::string PortalApi::homePage(
    const http::Request& request, const std::string& user, const std::string& error)
{
    if (user.empty()) {
        return page(request, "Sign in", std::string(),
            assets_.render("signin.html",
                {
                    {"challenge", htmlEscape(login().issue(nowSeconds()))},
                    {"error", notice(error, "is-error")},
                }));
    }

    const std::string session
        = assets_.render("session.html", {{"fingerprint", htmlEscape(user)}});
    if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(user); ban.has_value()) {
        return page(request, "Refused", session,
            assets_.render("banned.html", {{"message", htmlEscape(ban->reason)}}));
    }

    const std::map<std::string, std::string> account
        = accountValues(user, grants_.peekSubscription(user));
    const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
    if (approval.has_value() && approval->pending()) {
        return page(request, "Waiting", session, assets_.render("waiting.html", account));
    }
    return page(request, "Registered", session,
        assets_.render(settings().requireApproval ? "registered-approval.html" : "registered.html",
            account));
}

}  // namespace bazarish::service
