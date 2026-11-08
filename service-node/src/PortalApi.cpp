// Bazarish project (c) 2026
#include "PortalApi.hpp"

#include <LoginRelay.hpp>
#include <QrSvg.hpp>
#include <SignInScan.hpp>
#include <WebFace.hpp>

#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Percent.hpp>
#include <bazarish/ServerDescriptor.hpp>

#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <functional>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

using bazarish::server::clearCookie;
using bazarish::server::newSignInToken;
using bazarish::server::notice;
using bazarish::server::redirectTo;
using bazarish::server::sendHtml;
using bazarish::server::sendJson;
using bazarish::server::setCookie;
using bazarish::server::signInScan;

namespace {

constexpr std::int64_t kReseedHoldSeconds = 300;
constexpr std::int64_t kSessionTtlSeconds = 3600;

namespace http = bazarish::http;

using bazarish::nowSeconds;
using bazarish::htmlEscape;
using bazarish::http::filled;

const char* const kSessionCookie = "session";
const char* const kCookieAttributes = "; HttpOnly; Secure; SameSite=Strict; Path=/";
const char* const kSignInCookie = "signin";
const char* const kSignInCookieAttributes = "; HttpOnly; Secure; SameSite=Strict; Path=/login";
void setSessionCookie(http::Response& response, const std::string& token)
{
    setCookie(response, kSessionCookie, token, kCookieAttributes);
}

void clearSessionCookie(http::Response& response)
{
    clearCookie(response, kSessionCookie, kCookieAttributes);
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

}  // namespace

namespace bazarish::service {

PortalApi::PortalApi(PortalApiOptions options, GrantStore& grants)
    : options_(std::move(options))
    , settings_(options_.settings)
    , assets_(options_.assetsDirectory)
    , messages_(options_.assetsDirectory / "messages.json")
    , grants_(grants)
    , login_(options_.challengeSecret,
          LoginChallenge::ConsumerFn(
              [settings = settings_]() { return settings->get().loginConsumer; }))
    , session_(options_.sessionSecret, kSessionTtlSeconds)
{
}

PortalApi::~PortalApi() = default;

int PortalApi::bind(const std::string& host, const int port)
{
    http::Server::Options options;
    options.denyFraming = true;
    options.host = host;
    options.port = port;
    http_ = std::make_unique<http::Server>(options);
    setupWebRoutes();
    try {
        return http_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

void PortalApi::stop()
{
    if (http_) {
        http_->stop();
    }
}

std::string PortalApi::reseedArchive()
{
    const std::int64_t now = nowSeconds();
    {
        // One fetch at a time and never under the lock: the others take what is held meanwhile.
        const std::lock_guard<std::mutex> lock(reseedMutex_);
        const bool fresh = !reseedSu3_.empty() && now - reseedFetchedAt_ < kReseedHoldSeconds;
        if (fresh || reseedFetching_) {
            return reseedSu3_;
        }
        reseedFetching_ = true;
    }
    std::string archive;
    try {
        archive = options_.fetchReseedArchive();
    } catch (const std::exception& error) {
        bazarish::log::warn("portal: could not fetch the reseed archive: {}", error.what());
    }
    const std::lock_guard<std::mutex> lock(reseedMutex_);
    reseedFetching_ = false;
    if (!archive.empty()) {
        reseedSu3_ = std::move(archive);
        reseedFetchedAt_ = now;
    }
    return reseedSu3_;
}

void PortalApi::setupWebRoutes()
{
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

    for (const std::string& name : assets_.published()) {
        const WebAssets::File& file = assets_.file(name);
        http_->get("/" + name, [&file](const http::Request& request) {
            return serveWebAsset(file, request);
        });
    }

    http_->get("/lang/{lang}", [this](const http::Request& request) {
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
        sendHtml(response, homePage(request, user, std::string(), response));
    }));

    http_->post("/login", filled([this](const http::Request& request, http::Response& response) {
        try {
            const std::string userId = login_.verify(request.param("challenge"),
                request.param("blob"), nowSeconds());
            setSessionCookie(response, session_.issue(userId, nowSeconds()));
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            bazarish::log::debug("portal sign-in refused: {}", error.what());
            sendHtml(response,
                homePage(request, std::string(), "{{t.signin.failed}}", response),
                401);
        }
    }));

    http_->get("/login/wait", filled([this](const http::Request& request, http::Response& response) {
        const std::int64_t now = nowSeconds();
        const LoginMailbox::Claim claim
            = options_.logins->claim(request.query("nonce"), request.cookie(kSignInCookie), now);
        std::string state = claim.state == LoginMailbox::State::eWaiting ? "waiting" : "gone";
        if (claim.state == LoginMailbox::State::eSigned) {
            try {
                setSessionCookie(
                    response, session_.issue(login_.verify(claim.challenge, claim.blob, now), now));
                state = "signedIn";
            } catch (const std::exception& error) {
                bazarish::log::debug("portal sign-in refused: {}", error.what());
            }
        }
        sendJson(response, {{"state", state}});
    }));

    http_->post("/logout", filled([this](const http::Request& request, http::Response& response) {
        session_.revoke(request.cookie(kSessionCookie), nowSeconds());
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
                page(request, "{{t.delete.title}}", assets_.render("session.html", {{"fingerprint", htmlEscape(user)}}),
                    assets_.render("confirm-delete.html", accountValues(user))));
            return;
        }
        options_.deleteAccount(user);
        session_.revoke(request.cookie(kSessionCookie), nowSeconds());
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
            + "\" href=\"/lang/" + language.code + "?back=" + percentEncode(sameSitePath(here))
            + "\"" + (current ? " aria-current=\"true\"" : "") + ">" + htmlEscape(language.name)
            + "</a></li>\n";
    }
    return "  <details class=\"lang\">\n    <summary class=\"lang-now\" aria-label=\""
        + htmlEscape(messages_.text("switch.title", lang)) + "\">"
        + htmlEscape(messages_.language(lang).name) + "</summary>\n    <ul class=\"lang-list\">\n"
        + list + "    </ul>\n  </details>\n";
}

std::map<std::string, std::string> PortalApi::accountValues(const std::string& user)
{
    const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
    const NodeSettings::Values values = settings();
    const std::string note = approval.has_value() && !approval->message.empty()
        ? approval->message
        : values.registrationMessage;

    std::string mailbox = "{{t.facts.unknown}}";
    std::string devices = "{{t.facts.unknown}}";
    if (const std::optional<MailboxUsage> usage = options_.accountUsage(user);
        usage.has_value()) {
        mailbox = bytesHuman(usage->usedBytes) + " of " + bytesHuman(usage->quotaBytes);
        devices = std::to_string(usage->devices);
    }

    const std::string descriptor
        = encodeServerDescriptor({options_.serverFingerprint, values.facades, values.reseeds});
    return {
        {"descriptor",
            assets_.render(
                "descriptor.html", {{"text", htmlEscape(descriptor)}, {"qr", bazarish::qr::svg(descriptor)}})},
        {"message", notice(note, "is-waiting")},
        {"mailbox", htmlEscape(mailbox)},
        {"devices", htmlEscape(devices)},
    };
}

std::string PortalApi::signInPanel(const std::string& error, http::Response& response)
{
    const std::int64_t now = nowSeconds();
    const std::vector<std::string> facades = settings().facades;
    const auto pasteOnly = [&]() {
        return assets_.render("signin.html",
            {
                {"challenge", htmlEscape(login_.issue(now))},
                {"error", notice(error, "is-error")},
                {"scan", std::string()},
            });
    };
    if (facades.empty() || !isB32I2pHost(facades.front())) {
        return pasteOnly();
    }
    const std::string& facade = facades.front();
    const std::string challenge = login_.issue(now, loginrelay::callbackUrl(facade));
    const std::string token = newSignInToken();
    const Bytes key = newLinkKey();
    if (!options_.logins->expect(challenge, token, key, now)) {
        return pasteOnly();
    }
    setCookie(response, kSignInCookie, token, kSignInCookieAttributes);
    return assets_.render("signin.html",
        {
            {"challenge", htmlEscape(challenge)},
            {"error", notice(error, "is-error")},
            {"scan", signInScan(assets_, facade, challenge, key)},
        });
}

std::string PortalApi::homePage(const http::Request& request, const std::string& user,
    const std::string& error, http::Response& response)
{
    if (user.empty()) {
        return page(request, "{{t.signin.action}}", std::string(), signInPanel(error, response));
    }

    const std::string session
        = assets_.render("session.html", {{"fingerprint", htmlEscape(user)}});
    if (const std::optional<GrantStore::Ban> ban = grants_.peekBan(user); ban.has_value()) {
        return page(request, "{{t.banned.title}}", session,
            assets_.render("banned.html", {{"message", htmlEscape(ban->reason)}}));
    }

    const std::map<std::string, std::string> account = accountValues(user);
    const std::optional<GrantStore::Approval> approval = grants_.peekApproval(user);
    if (approval.has_value() && approval->pending()) {
        return page(request, "{{t.waiting.title}}", session, assets_.render("waiting.html", account));
    }
    return page(request, "{{t.registered.title}}", session,
        assets_.render(settings().requireApproval ? "registered-approval.html" : "registered.html",
            account));
}

}  // namespace bazarish::service
