// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "Html.hpp"
#include "ServiceClient.hpp"

#include <bazarish/HttpServer.hpp>
#include <bazarish/Log.hpp>

#include <functional>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <stdexcept>
#include <string>
#include <vector>

namespace bazarish::admin {

namespace {

constexpr const char* kCookieName = "admin_session";

std::int64_t nowSeconds()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
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

std::string humanizeUptime(std::int64_t seconds)
{
    if (seconds < 0) {
        seconds = 0;
    }
    const long long days = seconds / 86400;
    seconds %= 86400;
    const long long hours = seconds / 3600;
    seconds %= 3600;
    const long long minutes = seconds / 60;
    const long long secs = seconds % 60;
    char buffer[64];
    if (days > 0) {
        std::snprintf(buffer, sizeof(buffer), "%lldd %lldh %lldm", days, hours, minutes);
    } else if (hours > 0) {
        std::snprintf(buffer, sizeof(buffer), "%lldh %lldm", hours, minutes);
    } else if (minutes > 0) {
        std::snprintf(buffer, sizeof(buffer), "%lldm %llds", minutes, secs);
    } else {
        std::snprintf(buffer, sizeof(buffer), "%llds", secs);
    }
    return buffer;
}

std::string flashBanner(const std::string& code)
{
    std::string text;
    if (code == "quotaok") {
        text = "Quota applied.";
    } else if (code == "i2pok") {
        text = "I2P destination updated.";
    } else if (code == "loggedout") {
        text = "Signed out.";
    } else {
        return {};
    }
    return "<p class=\"flash\">" + htmlEscape(text) + "</p>";
}

// Renders one service row from its probe result.
std::string serviceRow(const ServiceEntry& service, const HealthResult& health)
{
    std::string row = "<tr><td><strong>" + htmlEscape(service.name) + "</strong><br>"
        + "<span class=\"muted\">" + htmlEscape(service.kind) + " &middot; "
        + htmlEscape(service.url) + "</span></td>";
    if (health.reachable) {
        row += "<td class=\"up\">UP</td>";
        row += "<td>" + htmlEscape(health.version) + "</td>";
        row += "<td>" + htmlEscape(humanizeUptime(health.uptime)) + "</td>";
        row += "<td>" + htmlEscape(bytesHuman(health.ramBytes)) + " / "
            + htmlEscape(bytesHuman(health.ramPeakBytes)) + "</td>";
    } else {
        row += "<td class=\"down\">DOWN</td>";
        std::string note = health.error;
        if (health.status != 0) {
            note += " (HTTP " + std::to_string(health.status) + ")";
        }
        row += "<td colspan=\"3\"><span class=\"muted\">" + htmlEscape(note) + "</span></td>";
    }
    row += "<td>" + std::to_string(health.latencyMs) + " ms</td></tr>";
    return row;
}

std::string resultPage(const OpResult& result, const std::string& action)
{
    std::string body;
    if (result.ok) {
        body += "<p class=\"flash\">" + htmlEscape(action) + ": ok.</p>";
    } else {
        body += "<p class=\"err\">" + htmlEscape(action) + " failed: " + htmlEscape(result.message)
            + (result.status != 0 ? " (HTTP " + std::to_string(result.status) + ")" : "")
            + "</p>";
    }
    body += "<p><a href=\"/\">Back to dashboard</a></p>";
    return htmlPage("Result", body);
}

}  // namespace

HttpApi::HttpApi(Config config, const Identity& identity, HttpApiOptions options)
    : config_(std::move(config))
    , identity_(identity)
    , options_(std::move(options))
    , auth_(config_.audience, config_.admin)
    , sessions_(options_.sessionTtlSeconds)
{
}

HttpApi::~HttpApi() = default;

void HttpApi::registerRoutes()
{
    // The sign-in page: a fresh challenge to sign in the client, and a box to
    // paste the resulting blob back. No backend is contacted to log in.
    const auto loginPage = [this](const std::string& error) -> std::string {
        const std::string challenge = auth_.issueChallenge(nowSeconds());
        std::string body;
        if (!error.empty()) {
            body += "<p class=\"err\">" + htmlEscape(error) + "</p>";
        }
        body += "<p>Sign in with your Bazarish key. Copy this challenge, sign it in your client "
                "(Signature), and paste the result below. The key never enters the browser.</p>";
        body += "<pre>" + htmlEscape(challenge) + "</pre>";
        body += "<form method=\"post\" action=\"/login\">";
        body += "<input type=\"hidden\" name=\"challenge\" value=\"" + htmlEscape(challenge)
            + "\">";
        body += "<label>Signed blob</label><textarea name=\"blob\" rows=\"6\"></textarea>";
        body += "<button>Sign in</button></form>";
        return htmlPage("Sign in", body);
    };

    http_->get("/login", filled([loginPage](const http::Request&, http::Response& response) {
        sendHtml(response, loginPage(std::string()));
    }));

    http_->post("/login", filled([this, loginPage](
                              const http::Request& request, http::Response& response) {
        try {
            auth_.login(request.query("challenge"), request.query("blob"),
                nowSeconds());
            const std::string token = sessions_.create(nowSeconds());
            response.headers["Set-Cookie"]
                = std::string(kCookieName) + "=" + token + "; HttpOnly; SameSite=Strict; Path=/";
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            sendHtml(response, loginPage(error.what()), 401);
        }
    }));

    http_->post("/logout", filled([this](const http::Request& request, http::Response& response) {
        sessions_.destroy(cookieValue(request, kCookieName));
        response.headers["Set-Cookie"]
            = std::string(kCookieName) + "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
        redirectTo(response, "/login?msg=loggedout");
    }));

    // Probes every service concurrently (one slow/down service cannot stall the
    // dashboard) and returns the status table body rows. Shared by the full page
    // render and the /api/status partial the page polls every few seconds.
    const auto renderRows = [this]() -> std::string {
        std::vector<std::future<HealthResult>> probes;
        probes.reserve(config_.services.size());
        for (std::size_t i = 0; i < config_.services.size(); ++i) {
            probes.push_back(std::async(std::launch::async,
                [this, i]() { return probeHealth(config_.services[i], identity_); }));
        }
        std::string rows;
        if (config_.services.empty()) {
            rows += "<tr><td colspan=\"6\" class=\"muted\">No services configured.</td></tr>";
        }
        for (std::size_t i = 0; i < config_.services.size(); ++i) {
            rows += serviceRow(config_.services[i], probes[i].get());
        }
        return rows;
    };

    // The status table rows alone, for the in-page poller. Session-guarded like
    // the dashboard; a 401 tells the page to bounce to the sign-in screen.
    http_->get("/api/status", filled([this, renderRows](
                                  const http::Request& request, http::Response& response) {
        if (!sessions_.valid(cookieValue(request, kCookieName), nowSeconds())) {
            response.status = 401;
            return;
        }
        response.contentType = "text/html; charset=utf-8";
        response.body = renderRows();
    }));

    http_->get("/", filled([this, renderRows](
                        const http::Request& request, http::Response& response) {
        if (!sessions_.valid(cookieValue(request, kCookieName), nowSeconds())) {
            redirectTo(response, "/login");
            return;
        }

        std::string body = flashBanner(request.query("msg"));
        body += "<form method=\"post\" action=\"/logout\" style=\"float:right\">"
                "<button>Sign out</button></form>";
        body += "<h2>Services</h2><table><thead><tr><th>Service</th><th>Status</th>"
                "<th>Version</th><th>Uptime</th><th>RAM (now / peak)</th><th>Latency</th></tr>"
                "</thead><tbody id=\"svcrows\">";
        body += renderRows();
        body += "</tbody></table><p class=\"muted\">Live - refreshes every 5s.</p>";

        // Management: a quota form and an I2P-dest form, both server-core, built
        // from the configured services.
        std::string quotaOptions;
        std::string i2pOptions;
        for (const ServiceEntry& service : config_.services) {
            if (service.kind != "server-core") {
                continue;
            }
            const std::string option = "<option value=\"" + htmlEscape(service.name) + "\">"
                + htmlEscape(service.name) + "</option>";
            quotaOptions += option;
            i2pOptions += option;
        }

        // Accounts frozen on a moderated service node. Only rendered when a node
        // actually has someone waiting, so an open-registration deployment never
        // sees this section.
        for (const ServiceEntry& service : config_.services) {
            if (service.kind != "service-node") {
                continue;
            }
            const PendingResult pending = listPending(service, identity_);
            if (!pending.ok || pending.accounts.empty()) {
                continue;
            }
            body += "<h2>Awaiting approval - " + htmlEscape(service.name) + "</h2>";
            body += "<table><tr><th>User</th><th>Requested</th><th></th></tr>";
            for (const PendingAccount& account : pending.accounts) {
                body += "<tr><td><code>" + htmlEscape(account.user) + "</code></td>";
                body += "<td>" + std::to_string(account.requestedAt) + "</td>";
                body += "<td><form method=\"post\" action=\"/manage/approve\">";
                body += "<input type=\"hidden\" name=\"service\" value=\""
                    + htmlEscape(service.name) + "\">";
                body += "<input type=\"hidden\" name=\"user\" value=\"" + htmlEscape(account.user)
                    + "\">";
                body += "<button>Approve</button></form></td></tr>";
            }
            body += "</table>";
        }

        if (!quotaOptions.empty()) {
            body += "<h2>Set user quota</h2>";
            body += "<form method=\"post\" action=\"/manage/quota\">";
            body += "<label>Service</label><select name=\"service\">" + quotaOptions + "</select>";
            body += "<label>User fingerprint</label><input name=\"user\" required>";
            body += "<label>Quota (bytes)</label><input name=\"quotaBytes\" type=\"number\" "
                    "min=\"0\" required>";
            body += "<button>Apply quota</button></form>";
        }
        if (!i2pOptions.empty()) {
            body += "<h2>Personal I2P destination (server-core)</h2>";
            body += "<form method=\"post\" action=\"/manage/i2p-dest\">";
            body += "<label>Service</label><select name=\"service\">" + i2pOptions + "</select>";
            body += "<label>User fingerprint</label><input name=\"user\" required>";
            body += "<label>Transient offline key (base64) - leave empty to revoke</label>"
                    "<textarea name=\"transient\" rows=\"3\"></textarea>";
            body += "<label>Expires (unix seconds) - only when provisioning</label>"
                    "<input name=\"expiresUnix\" type=\"number\" min=\"0\">";
            body += "<button>Apply</button></form>";
        }

        // Poll the status partial and swap the table body in place, so the live
        // figures refresh without reloading the page or disturbing the forms.
        body += "<script>setInterval(function(){"
                "fetch('/api/status',{headers:{'Accept':'text/html'}}).then(function(r){"
                "if(!r.ok){window.location='/login';return null;}return r.text();})"
                ".then(function(h){if(h!==null){"
                "document.getElementById('svcrows').innerHTML=h;}})"
                ".catch(function(){});},5000);</script>";

        sendHtml(response, htmlPage("Dashboard", body, /*wide=*/true));
    }));

    const auto findService = [this](const std::string& name) -> const ServiceEntry* {
        for (const ServiceEntry& service : config_.services) {
            if (service.name == name) {
                return &service;
            }
        }
        return nullptr;
    };

    http_->post("/manage/quota", filled([this, findService](const http::Request& request,
                                     http::Response& response) {
        if (!sessions_.valid(cookieValue(request, kCookieName), nowSeconds())) {
            redirectTo(response, "/login");
            return;
        }
        const ServiceEntry* const service = findService(request.query("service"));
        if (service == nullptr || service->kind != "server-core") {
            sendHtml(response, resultPage({false, 0, "unknown service"}, "Set quota"), 400);
            return;
        }
        const std::uint64_t quotaBytes
            = std::strtoull(request.query("quotaBytes").c_str(), nullptr, 10);
        const OpResult result
            = setQuota(*service, identity_, request.query("user"), quotaBytes);
        if (result.ok) {
            redirectTo(response, "/?msg=quotaok");
        } else {
            sendHtml(response, resultPage(result, "Set quota"), 502);
        }
    }));

    http_->post("/manage/approve", filled([this, findService](const http::Request& request,
                                       http::Response& response) {
        if (!sessions_.valid(cookieValue(request, kCookieName), nowSeconds())) {
            redirectTo(response, "/login");
            return;
        }
        const ServiceEntry* const service = findService(request.query("service"));
        if (service == nullptr || service->kind != "service-node") {
            sendHtml(response, resultPage({false, 0, "unknown service"}, "Approve account"), 400);
            return;
        }
        const OpResult result
            = approveAccount(*service, identity_, request.query("user"));
        if (result.ok) {
            redirectTo(response, "/?msg=approved");
        } else {
            sendHtml(response, resultPage(result, "Approve account"), 502);
        }
    }));

    http_->post("/manage/i2p-dest", filled([this, findService](const http::Request& request,
                                        http::Response& response) {
        if (!sessions_.valid(cookieValue(request, kCookieName), nowSeconds())) {
            redirectTo(response, "/login");
            return;
        }
        const ServiceEntry* const service = findService(request.query("service"));
        if (service == nullptr || service->kind != "server-core") {
            sendHtml(response, resultPage({false, 0, "unknown service"}, "Set I2P dest"), 400);
            return;
        }
        const std::string transient = request.query("transient");
        const std::string expiresParam = request.query("expiresUnix");
        const std::int64_t expiresUnix
            = expiresParam.empty() ? 0 : std::strtoll(expiresParam.c_str(), nullptr, 10);
        const OpResult result = setI2pDest(
            *service, identity_, request.query("user"), transient, expiresUnix);
        if (result.ok) {
            redirectTo(response, "/?msg=i2pok");
        } else {
            sendHtml(response, resultPage(result, "Set I2P dest"), 502);
        }
    }));
}

bool HttpApi::listen(const std::string& host, const int port)
{
    if (bindToAnyPort(host, port) <= 0) {
        return false;
    }
    return listenAfterBind();
}

int HttpApi::bindToAnyPort(const std::string& host)
{
    return bindToAnyPort(host, 0);  // 0: the kernel picks the port
}

int HttpApi::bindToAnyPort(const std::string& host, const int port)
{
    http::Server::Options options;
    options.host = host;
    options.port = port;
    http_ = std::make_unique<http::Server>(options);
    registerRoutes();
    try {
        const int bound = http_->start();
        running_ = bound > 0;
        return bound;
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

bool HttpApi::listenAfterBind()
{
    // The engine serves on its own threads; this call is what keeps the caller's
    // thread (a main()) parked until stop().
    std::unique_lock<std::mutex> lock(stopMutex_);
    stopCv_.wait(lock, [this]() { return stopping_; });
    return true;
}

bool HttpApi::isRunning() const
{
    return running_;
}

void HttpApi::stop()
{
    if (http_) {
        http_->stop();
    }
    running_ = false;
    {
        const std::lock_guard<std::mutex> lock(stopMutex_);
        stopping_ = true;
    }
    stopCv_.notify_all();
}

}  // namespace bazarish::admin
