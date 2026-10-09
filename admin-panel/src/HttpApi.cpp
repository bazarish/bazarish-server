// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "ServiceClient.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/WebAssets.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace http = bazarish::http;

using bazarish::htmlEscape;
using bazarish::nowSeconds;
using bazarish::http::filled;

const char* const kCookieName = "adminsession";
const char* const kCookieAttributes = "; HttpOnly; SameSite=Strict; Path=/";

void setSessionCookie(http::Response& response, const std::string& token)
{
    response.headers["Set-Cookie"] = std::string(kCookieName) + "=" + token + kCookieAttributes;
}

void clearSessionCookie(http::Response& response)
{
    response.headers["Set-Cookie"]
        = std::string(kCookieName) + "=" + kCookieAttributes + "; Max-Age=0";
}

void sendHtml(http::Response& response, const std::string& html, const int status = 200)
{
    response.status = status;
    response.contentType = "text/html; charset=utf-8";
    response.headers["Cache-Control"] = "no-store";
    response.body = html;
}

void sendJson(http::Response& response, const std::string& body, const int status = 200)
{
    response.status = status;
    response.contentType = "application/json";
    response.headers["Cache-Control"] = "no-store";
    response.body = body;
}

void sendError(http::Response& response, const int status, const std::string& message)
{
    sendJson(response, nlohmann::json{{"error", message}}.dump(), status);
}

std::string notice(const std::string& text)
{
    if (text.empty()) {
        return {};
    }
    return "<p class=\"notice is-error\">" + htmlEscape(text) + "</p>";
}

void redirectTo(http::Response& response, const std::string& location)
{
    response.status = 303;
    response.headers["Location"] = location;
}

std::string urlEncoded(const std::string& text)
{
    static const char* const kHexDigits = "0123456789ABCDEF";
    constexpr unsigned kNibbleBits = 4;
    constexpr unsigned kLowNibble = 0x0F;
    std::string out;
    for (const unsigned char c : text) {
        const bool unreserved = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHexDigits[c >> kNibbleBits]);
            out.push_back(kHexDigits[c & kLowNibble]);
        }
    }
    return out;
}

std::string settingsPathOf(const std::string& kind)
{
    if (kind == bazarish::admin::kServerCoreKind) {
        return "/v1/messaging/settings";
    }
    if (kind == bazarish::admin::kServiceNodeKind) {
        return "/v1/account/settings";
    }
    if (kind == bazarish::admin::kFacadeKind) {
        return "/settings";
    }
    return {};
}

std::string restartPathOf(const std::string& kind)
{
    if (kind == bazarish::admin::kServerCoreKind) {
        return "/v1/messaging/restart";
    }
    if (kind == bazarish::admin::kServiceNodeKind) {
        return "/v1/account/restart";
    }
    if (kind == bazarish::admin::kFacadeKind) {
        return "/restart";
    }
    return {};
}

std::string humanizeUptime(const std::int64_t seconds)
{
    using bazarish::kSecondsPerDay;
    using bazarish::kSecondsPerHour;
    using bazarish::kSecondsPerMinute;
    if (seconds >= kSecondsPerDay) {
        return std::to_string(seconds / kSecondsPerDay) + "d "
            + std::to_string((seconds % kSecondsPerDay) / kSecondsPerHour) + "h";
    }
    if (seconds >= kSecondsPerHour) {
        return std::to_string(seconds / kSecondsPerHour) + "h "
            + std::to_string((seconds % kSecondsPerHour) / kSecondsPerMinute) + "m";
    }
    return std::to_string(seconds / kSecondsPerMinute) + "m";
}

}  // namespace

namespace bazarish::admin {

HttpApi::HttpApi(std::shared_ptr<PanelSettings> settings, const Identity& identity,
    bazarish::tls::Credential credential, HttpApiOptions options)
    : settings_(std::move(settings))
    , identity_(identity)
    , credential_(std::move(credential))
    , options_(std::move(options))
    , auth_(settings_)
    , sessions_(options_.sessionTtlSeconds)
    , assets_(options_.assetsDirectory)
{
}

HttpApi::~HttpApi() = default;

std::optional<ServiceEntry> HttpApi::serviceOfKind(
    const std::string& fleet, const std::string& kind) const
{
    for (const Fleet& candidate : settings_->get().fleets) {
        if (!fleet.empty() && candidate.name != fleet) {
            continue;
        }
        for (const ServiceEntry& service : candidate.services) {
            if (service.kind == kind) {
                return service;
            }
        }
        if (!fleet.empty()) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

void HttpApi::proxyToNode(const std::string& fleet, http::Response& response,
    const std::string& method, const std::string& path, const std::string& body)
{
    const std::optional<ServiceEntry> node = serviceOfKind(fleet, kServiceNodeKind);
    if (!node.has_value()) {
        sendError(response, 503, "this deployment has no service node the panel can reach");
        return;
    }
    const JsonResult result = callJson(*node, identity_, credential_, method, path, body);
    if (result.status == 0) {
        bazarish::log::warn("service-node unreachable: {}", result.error);
        sendError(response, 502, result.error.empty() ? "service-node unreachable" : result.error);
        return;
    }
    sendJson(response, result.body, result.status);
}

void HttpApi::registerRoutes()
{
    for (const std::string& name : assets_.published()) {
        const WebAssets::File& file = assets_.file(name);
        http_->get("/" + name, [&file](const http::Request& request) {
            return serveWebAsset(file, request);
        });
    }

    const auto signedIn = [this](const http::Request& request) {
        return sessions_.valid(request.cookie(kCookieName), nowSeconds());
    };

    const auto loginPage = [this](const std::string& error) {
        return assets_.render("login.html",
            {
                {"challenge", auth_.issueChallenge(nowSeconds())},
                {"error", notice(error)},
            });
    };

    const auto setupPage = [this](const std::string& error) {
        return assets_.render("setup.html",
            {
                {"challenge", auth_.issueChallenge(nowSeconds())},
                {"error", notice(error)},
            });
    };

    http_->get("/setup", filled([this, setupPage](
                             const http::Request&, http::Response& response) {
        if (!settings_->unclaimed()) {
            redirectTo(response, "/login");
            return;
        }
        sendHtml(response, setupPage(std::string()));
    }));

    http_->post("/setup", filled([this, setupPage](
                              const http::Request& request, http::Response& response) {
        if (!settings_->unclaimed()) {
            redirectTo(response, "/login");
            return;
        }
        try {
            const std::string fingerprint = auth_.verify(
                request.param("challenge"), request.param("blob"), nowSeconds());
            if (!settings_->claim(fingerprint)) {
                redirectTo(response, "/login");
                return;
            }
            bazarish::log::info("this panel is now administered by {}", fingerprint);
            setSessionCookie(response, sessions_.create(nowSeconds()));
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            bazarish::log::warn("panel setup refused: {}", error.what());
            sendHtml(response, setupPage(error.what()), 401);
        }
    }));

    http_->get("/login", filled([this, signedIn, loginPage](
                             const http::Request& request, http::Response& response) {
        if (settings_->unclaimed()) {
            redirectTo(response, "/setup");
            return;
        }
        if (signedIn(request)) {
            redirectTo(response, "/");
            return;
        }
        sendHtml(response, loginPage(std::string()));
    }));

    http_->post("/login", filled([this, loginPage](
                              const http::Request& request, http::Response& response) {
        if (settings_->unclaimed()) {
            redirectTo(response, "/setup");
            return;
        }
        try {
            auth_.login(request.param("challenge"), request.param("blob"), nowSeconds());
            setSessionCookie(response, sessions_.create(nowSeconds()));
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            bazarish::log::warn("panel sign-in refused: {}", error.what());
            sendHtml(response, loginPage(error.what()), 401);
        }
    }));

    http_->post("/logout", filled([this](const http::Request& request, http::Response& response) {
        sessions_.destroy(request.cookie(kCookieName));
        clearSessionCookie(response);
        redirectTo(response, "/login");
    }));

    http_->get("/", filled([this, signedIn](
                        const http::Request& request, http::Response& response) {
        if (settings_->unclaimed()) {
            redirectTo(response, "/setup");
            return;
        }
        if (!signedIn(request)) {
            redirectTo(response, "/login");
            return;
        }
        sendHtml(response, assets_.render("index.html", {{"version", options_.version}}));
    }));

    const auto api = [this, signedIn](auto handler) {
        return filled([this, signedIn, handler](
                          const http::Request& request, http::Response& response) {
            if (!signedIn(request)) {
                sendError(response, 401, "not signed in");
                return;
            }
            try {
                handler(request, response);
            } catch (const nlohmann::json::exception& error) {
                sendError(response, 400, error.what());
            }
        });
    };

    http_->get("/api/services", api([this](const http::Request&, http::Response& response) {
        const Config panel = settings_->get();
        std::vector<std::pair<std::string, ServiceEntry>> all;
        for (const Fleet& fleet : panel.fleets) {
            for (const ServiceEntry& service : fleet.services) {
                all.emplace_back(fleet.name, service);
            }
        }
        std::vector<std::future<HealthResult>> probes;
        probes.reserve(all.size());
        for (const auto& [fleet, service] : all) {
            probes.push_back(std::async(std::launch::async,
                [this, service]() { return probeHealth(service, identity_, credential_); }));
        }
        nlohmann::json services = nlohmann::json::array();
        for (std::size_t i = 0; i < all.size(); ++i) {
            const HealthResult health = probes[i].get();
            services.push_back(nlohmann::json{
                {"fleet", all[i].first},
                {"name", all[i].second.name},
                {"kind", all[i].second.kind},
                {"url", all[i].second.url},
                {"up", health.reachable},
                {"status", health.status},
                {"error", health.error},
                {"latencyMs", health.latencyMs},
                {"version", health.version},
                {"uptime", humanizeUptime(health.uptime)},
                {"ramBytes", health.ramBytes},
                {"ramPeakBytes", health.ramPeakBytes},
                {"requestsLastMinute", health.requestsLastMinute},
                {"requestsLastHour", health.requestsLastHour},
                {"requestsLastDay", health.requestsLastDay},
                {"inFlight", health.inFlight},
                {"sessions", health.sessions},
                {"destinations", health.destinations},
                {"streams", health.streams},
                {"refused", health.refused},
                {"router", health.router},
            });
        }
        nlohmann::json fleets = nlohmann::json::array();
        for (const Fleet& fleet : panel.fleets) {
            fleets.push_back(fleet.name);
        }
        sendJson(response, nlohmann::json{{"services", services}, {"fleets", fleets}}.dump());
    }));

    http_->get("/api/users", api([this](const http::Request& request, http::Response& response) {
        std::string query = "/v1/account/users?q=" + urlEncoded(request.query("q"))
            + "&state=" + urlEncoded(request.query("state"));
        if (const std::string limit = request.query("limit"); !limit.empty()) {
            query += "&limit=" + urlEncoded(limit);
        }
        if (const std::string offset = request.query("offset"); !offset.empty()) {
            query += "&offset=" + urlEncoded(offset);
        }
        proxyToNode(request.query("fleet"), response, "GET", query, std::string());
    }));

    http_->post("/api/approve", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body);
        proxyToNode(request.query("fleet"), response, "POST", "/v1/account/approve",
            nlohmann::json{{"user", body.at("user")}}.dump());
    }));

    http_->post("/api/undelegate", api([this](
                                       const http::Request& request, http::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body);
        proxyToNode(request.query("fleet"), response, "POST", "/v1/account/undelegate",
            nlohmann::json{{"user", body.at("user")},
                {"message", body.value("message", std::string())}}
                .dump());
    }));

    http_->post("/api/delete", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body);
        proxyToNode(request.query("fleet"), response, "DELETE",
            "/v1/account/user?user=" + urlEncoded(body.at("user").get<std::string>()), {});
    }));

    http_->post("/api/ban", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body);
        proxyToNode(request.query("fleet"), response, "POST", "/v1/account/ban",
            nlohmann::json{{"user", body.at("user")}, {"reason", body.value("reason", std::string())}}
                .dump());
    }));

    http_->post("/api/unban", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body);
        proxyToNode(request.query("fleet"), response, "POST", "/v1/account/unban",
            nlohmann::json{{"user", body.at("user")}}.dump());
    }));

    http_->get("/api/account", api([this](
                                   const http::Request& request, http::Response& response) {
        const std::optional<ServiceEntry> core
            = serviceOfKind(request.query("fleet"), kServerCoreKind);
        if (!core.has_value()) {
            sendError(response, 503, "no server-core configured in this panel");
            return;
        }
        const JsonResult account = callJson(*core, identity_, credential_, "GET",
            "/v1/messaging/account?user=" + urlEncoded(request.query("user")));
        if (account.status == 0) {
            bazarish::log::warn("server-core unreachable: {}", account.error);
            sendError(response, 502,
                account.error.empty() ? "server-core unreachable" : account.error);
            return;
        }
        sendJson(response, account.body, account.status);
    }));

    http_->get("/api/settings", api([this](
                                    const http::Request& request, http::Response& response) {
        const std::optional<ServiceEntry> node
            = serviceOfKind(request.query("fleet"), kServiceNodeKind);
        if (!node.has_value()) {
            sendError(response, 503, "this deployment has no service node the panel can reach");
            return;
        }
        const JsonResult settings
            = callJson(*node, identity_, credential_, "GET", "/v1/account/settings");
        if (!settings.ok) {
            bazarish::log::warn("service-node settings unavailable: {}", settings.error);
            sendJson(response, settings.body, settings.status == 0 ? 502 : settings.status);
            return;
        }
        nlohmann::json merged = nlohmann::json::parse(settings.body);
        merged["diskUsedBytes"] = nullptr;
        merged["diskError"] = "no server-core configured in this panel";
        if (const std::optional<ServiceEntry> core
            = serviceOfKind(request.query("fleet"), kServerCoreKind);
            core.has_value()) {
            const JsonResult disk
                = callJson(*core, identity_, credential_, "GET", "/v1/messaging/storage");
            if (disk.ok) {
                merged["diskUsedBytes"] = nlohmann::json::parse(disk.body).at("usedBytes");
                merged["diskError"] = "";
            } else {
                bazarish::log::warn("storage usage unavailable: {}", disk.error);
                merged["diskError"] = disk.error.empty() ? "server-core unreachable" : disk.error;
            }
        }
        sendJson(response, merged.dump());
    }));

    http_->put("/api/settings", api([this](const http::Request& request, http::Response& response) {
        proxyToNode(request.query("fleet"), response, "PUT", "/v1/account/settings", request.body);
    }));

    const auto toService = [this](const http::Request& request, http::Response& response,
                               const std::string& method, const bool restarting) {
        const std::string kind = request.query("kind");
        const std::string path = restarting ? restartPathOf(kind) : settingsPathOf(kind);
        if (path.empty()) {
            sendError(response, 400, "the panel does not know a service of kind \"" + kind + "\"");
            return;
        }
        const std::optional<ServiceEntry> service = serviceOfKind(request.query("fleet"), kind);
        if (!service.has_value()) {
            sendError(response, 503, "this deployment has no " + kind + " the panel can reach");
            return;
        }
        const JsonResult result
            = callJson(*service, identity_, credential_, method, path, request.body);
        if (result.status == 0) {
            bazarish::log::warn("{} unreachable: {}", kind, result.error);
            sendError(response, 502, result.error.empty() ? kind + " unreachable" : result.error);
            return;
        }
        sendJson(response, result.body, result.status);
    };

    http_->get("/api/service-settings", api([toService](
                                            const http::Request& request,
                                            http::Response& response) {
        toService(request, response, "GET", false);
    }));

    http_->put("/api/service-settings", api([toService](
                                            const http::Request& request,
                                            http::Response& response) {
        toService(request, response, "PUT", false);
    }));

    http_->post("/api/restart", api([toService](
                                    const http::Request& request, http::Response& response) {
        toService(request, response, "POST", true);
    }));

    http_->get("/api/panel", api([this](const http::Request&, http::Response& response) {
        const Config panel = settings_->get();
        sendJson(response,
            nlohmann::json{
                {"admins", panel.admins},
                {"consumer",
                    {{"name", panel.consumer.name}, {"place", panel.consumer.place},
                        {"role", panel.consumer.role}}},
                {"listen", {{"host", panel.listenHost}, {"port", panel.listenPort}}},
                {"fleets", fleetsJson(panel.fleets)},
                {"fingerprint", identity_.fingerprint()},
                {"configPath", settings_->configPath().string()},
                {"stateDir", panel.stateDir},
                {"assetsDir", panel.assetsDir},
                {"version", options_.version},
            }
                .dump());
    }));

    http_->post("/api/panel/restart", api([this](
                                          const http::Request&, http::Response& response) {
        if (!options_.requestRestart) {
            sendError(response, 503,
                "this panel cannot restart itself: it was started without a supervisor");
            return;
        }
        bazarish::log::info("restarting at the operator's request");
        options_.requestRestart();
        sendJson(response, R"({"restarting":true})");
    }));

    http_->put("/api/panel", api([this](const http::Request& request, http::Response& response) {
        try {
            const nlohmann::json body = nlohmann::json::parse(request.body);
            Config panel = settings_->get();
            if (body.contains("admins")) {
                std::vector<std::string> admins;
                for (const nlohmann::json& entry : body.at("admins")) {
                    const std::string fingerprint = entry.get<std::string>();
                    if (fingerprint.empty()) {
                        continue;
                    }
                    if (!isFingerprint(fingerprint)) {
                        throw std::invalid_argument(
                            "not a 52-character fingerprint: " + fingerprint);
                    }
                    admins.push_back(fingerprint);
                }
                if (admins.empty()) {
                    throw std::invalid_argument("a panel needs at least one administrator");
                }
                panel.admins = std::move(admins);
            }
            if (body.contains("consumer")) {
                const nlohmann::json& consumer = body.at("consumer");
                service::LoginConsumer wanted;
                wanted.name = consumer.value("name", panel.consumer.name);
                wanted.place = consumer.value("place", panel.consumer.place);
                wanted.role = consumer.value("role", panel.consumer.role);
                try {
                    service::requireUsableConsumer(wanted);
                } catch (const std::exception& error) {
                    throw std::invalid_argument(error.what());
                }
                panel.consumer = wanted;
            }
            readEndpointInto(body, "listen", panel.listenHost, panel.listenPort);
            if (body.contains("fleets")) {
                std::vector<Fleet> fleets;
                for (const nlohmann::json& entry : body.at("fleets")) {
                    Fleet fleet;
                    fleet.name = entry.value("name", std::string());
                    for (const nlohmann::json& item : entry.at("services")) {
                        ServiceEntry service;
                        service.name = item.value("name", std::string());
                        service.kind = item.value("kind", std::string());
                        service.url = item.value("url", std::string());
                        service.pin = item.value("pin", std::string());
                        if (!isKnownServiceKind(service.kind)) {
                            throw std::invalid_argument(
                                "the panel does not know a service of kind \"" + service.kind
                                + "\"");
                        }
                        if (service.url.empty() || service.name.empty()) {
                            throw std::invalid_argument("a service needs a name and a URL");
                        }
                        if (service.url.rfind("https://", 0) != 0) {
                            throw std::invalid_argument(
                                "a service is reached over https: " + service.url);
                        }
                        if (service.pin.empty()) {
                            throw std::invalid_argument(
                                "a service is named by the key it presents: " + service.name);
                        }
                        fleet.services.push_back(std::move(service));
                    }
                    fleets.push_back(std::move(fleet));
                }
                panel.fleets = std::move(fleets);
            }
            settings_->set(panel);
            sendJson(response, nlohmann::json{{"admins", panel.admins}}.dump());
        } catch (const std::invalid_argument& error) {
            sendError(response, 400, error.what());
        } catch (const nlohmann::json::exception& error) {
            sendError(response, 400, error.what());
        } catch (const std::exception& error) {
            sendError(response, 500, error.what());
        }
    }));

    http_->put("/api/quota", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body);
        proxyToNode(request.query("fleet"), response, "PUT", "/v1/account/quota",
            nlohmann::json{{"user", body.at("user")}, {"quotaBytes", body.at("quotaBytes")}}
                .dump());
    }));
}

int HttpApi::bind(const std::string& host, const int port)
{
    http::Server::Options options;
    options.host = host;
    options.port = port;
    http_ = std::make_unique<http::Server>(options);
    registerRoutes();
    try {
        return http_->start();
    } catch (const std::exception& error) {
        bazarish::log::error("cannot listen on {}:{}: {}", host, port, error.what());
        return 0;
    }
}

void HttpApi::wait()
{
    stopGate_.wait();
}

void HttpApi::stop()
{
    stopGate_.stop();
    if (http_) {
        http_->stop();
    }
}

}  // namespace bazarish::admin
