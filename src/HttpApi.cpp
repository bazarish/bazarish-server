// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "Html.hpp"
#include "ServiceClient.hpp"

#include <httplib/httplib.h>

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
    , http_(std::make_unique<httplib::Server>())
{
    registerRoutes();
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

    http_->Get("/login", [loginPage](const httplib::Request&, httplib::Response& response) {
        sendHtml(response, loginPage(std::string()));
    });

    http_->Post("/login", [this, loginPage](
                              const httplib::Request& request, httplib::Response& response) {
        try {
            auth_.login(request.get_param_value("challenge"), request.get_param_value("blob"),
                nowSeconds());
            const std::string token = sessions_.create(nowSeconds());
            response.set_header("Set-Cookie",
                std::string(kCookieName) + "=" + token + "; HttpOnly; SameSite=Strict; Path=/");
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            sendHtml(response, loginPage(error.what()), 401);
        }
    });

    http_->Post("/logout", [this](const httplib::Request& request, httplib::Response& response) {
        sessions_.destroy(cookieValue(request, kCookieName));
        response.set_header("Set-Cookie",
            std::string(kCookieName) + "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
        redirectTo(response, "/login?msg=loggedout");
    });

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
    http_->Get("/api/status", [this, renderRows](
                                  const httplib::Request& request, httplib::Response& response) {
        if (!sessions_.valid(cookieValue(request, kCookieName), nowSeconds())) {
            response.status = 401;
            return;
        }
        response.set_content(renderRows(), "text/html; charset=utf-8");
    });

    http_->Get("/", [this, renderRows](
                        const httplib::Request& request, httplib::Response& response) {
        if (!sessions_.valid(cookieValue(request, kCookieName), nowSeconds())) {
            redirectTo(response, "/login");
            return;
        }

        std::string body = flashBanner(request.get_param_value("msg"));
        body += "<form method=\"post\" action=\"/logout\" style=\"float:right\">"
                "<button>Sign out</button></form>";
        body += "<h2>Services</h2><table><thead><tr><th>Service</th><th>Status</th>"
                "<th>Version</th><th>Uptime</th><th>RAM (now / peak)</th><th>Latency</th></tr>"
                "</thead><tbody id=\"svcrows\">";
        body += renderRows();
        body += "</tbody></table><p class=\"muted\">Live - refreshes every 5s.</p>";

        // Management: a quota form (server-core + blob-storage) and an I2P-dest
        // form (server-core), built from the configured services.
        std::string quotaOptions;
        std::string i2pOptions;
        for (const ServiceEntry& service : config_.services) {
            const std::string option = "<option value=\"" + htmlEscape(service.name) + "\">"
                + htmlEscape(service.name) + "</option>";
            if (service.kind == "server-core" || service.kind == "blob-storage") {
                quotaOptions += option;
            }
            if (service.kind == "server-core") {
                i2pOptions += option;
            }
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
    });

    const auto findService = [this](const std::string& name) -> const ServiceEntry* {
        for (const ServiceEntry& service : config_.services) {
            if (service.name == name) {
                return &service;
            }
        }
        return nullptr;
    };

    http_->Post("/manage/quota", [this, findService](const httplib::Request& request,
                                     httplib::Response& response) {
        if (!sessions_.valid(cookieValue(request, kCookieName), nowSeconds())) {
            redirectTo(response, "/login");
            return;
        }
        const ServiceEntry* const service = findService(request.get_param_value("service"));
        if (service == nullptr
            || (service->kind != "server-core" && service->kind != "blob-storage")) {
            sendHtml(response, resultPage({false, 0, "unknown service"}, "Set quota"), 400);
            return;
        }
        const std::uint64_t quotaBytes
            = std::strtoull(request.get_param_value("quotaBytes").c_str(), nullptr, 10);
        const OpResult result
            = setQuota(*service, identity_, request.get_param_value("user"), quotaBytes);
        if (result.ok) {
            redirectTo(response, "/?msg=quotaok");
        } else {
            sendHtml(response, resultPage(result, "Set quota"), 502);
        }
    });

    http_->Post("/manage/i2p-dest", [this, findService](const httplib::Request& request,
                                        httplib::Response& response) {
        if (!sessions_.valid(cookieValue(request, kCookieName), nowSeconds())) {
            redirectTo(response, "/login");
            return;
        }
        const ServiceEntry* const service = findService(request.get_param_value("service"));
        if (service == nullptr || service->kind != "server-core") {
            sendHtml(response, resultPage({false, 0, "unknown service"}, "Set I2P dest"), 400);
            return;
        }
        const std::string transient = request.get_param_value("transient");
        const std::string expiresParam = request.get_param_value("expiresUnix");
        const std::int64_t expiresUnix
            = expiresParam.empty() ? 0 : std::strtoll(expiresParam.c_str(), nullptr, 10);
        const OpResult result = setI2pDest(
            *service, identity_, request.get_param_value("user"), transient, expiresUnix);
        if (result.ok) {
            redirectTo(response, "/?msg=i2pok");
        } else {
            sendHtml(response, resultPage(result, "Set I2P dest"), 502);
        }
    });
}

bool HttpApi::listen(const std::string& host, const int port)
{
    return http_->listen(host, port);
}

int HttpApi::bindToAnyPort(const std::string& host)
{
    return http_->bind_to_any_port(host);
}

bool HttpApi::listenAfterBind()
{
    return http_->listen_after_bind();
}

bool HttpApi::isRunning() const
{
    return http_->is_running();
}

void HttpApi::stop()
{
    http_->stop();
}

}  // namespace bazarish::admin
