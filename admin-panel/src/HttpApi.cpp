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
// The attributes every one of this panel's cookies carries. Written once: three
// copies of a cookie line are three places for one of them to lose a flag.
const char* const kCookieAttributes = "; HttpOnly; SameSite=Strict; Path=/";

void sendHtml(http::Response& response, const std::string& html, const int status = 200)
{
    response.status = status;
    response.contentType = "text/html; charset=utf-8";
    // The sign-in page carries a single-use challenge, and the app pages carry
    // whatever the fleet looked like a moment ago. Neither is worth caching.
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

// The one refusal a sign-in page shows. The text is whatever the verifier threw,
// and a verifier that could not parse what arrived quotes it back - so it is
// escaped here. It was not, and a challenge field holding markup put that markup
// in the page, in the panel's own origin, for whoever had been made to post it.
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

// Percent-encodes a value for a query string: a fingerprint is safe either way,
// but a search box takes whatever the operator types.
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
    HttpApiOptions options)
    : settings_(std::move(settings))
    , identity_(identity)
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
    // By value: the deployment list is a live setting, so a pointer into it
    // would outlive the snapshot it came from.
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
            return std::nullopt;  // named, and it has none of this kind
        }
    }
    return std::nullopt;
}

// Passes a call through to the service that owns the accounts, and hands its
// answer back untouched. The panel holds no user state of its own: what it shows
// is what the node says, one request ago.
void HttpApi::proxyToNode(const std::string& fleet, http::Response& response,
    const std::string& method, const std::string& path, const std::string& body)
{
    const std::optional<ServiceEntry> node = serviceOfKind(fleet, "service-node");
    if (!node.has_value()) {
        sendError(response, 503, "this deployment has no service node the panel can reach");
        return;
    }
    const JsonResult result = callJson(*node, identity_, method, path, body);
    if (result.status == 0) {
        bazarish::log::warn("service-node unreachable: {}", result.error);
        sendError(response, 502, result.error.empty() ? "service-node unreachable" : result.error);
        return;
    }
    sendJson(response, result.body, result.status);
}

void HttpApi::registerRoutes()
{
    // The panel's own files, answered from memory.
    for (const std::string& name : assets_.published()) {
        const WebAssets::File& file = assets_.file(name);
        http_->get("/" + name, [&file](const http::Request& request) {
            return serveWebAsset(file, request);
        });
    }

    const auto signedIn = [this](const http::Request& request) {
        return sessions_.valid(request.cookie(kCookieName), nowSeconds());
    };

    // Signing in needs no scripts and no backend: the panel verifies the blob
    // itself, so a fleet that is entirely down can still be logged into.
    const auto loginPage = [this](const std::string& error) {
        return assets_.render("login.html",
            {
                {"challenge", auth_.issueChallenge(nowSeconds())},
                {"error", notice(error)},
            });
    };

    // A panel nobody owns yet. The wizard is the whole installation: sign once,
    // and the key that signed administers this panel from here on.
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
            // Whoever signs first: on an unclaimed panel there is no list for
            // anyone to be on, so this checks the signature and nothing else.
            const std::string fingerprint = auth_.verify(
                request.param("challenge"), request.param("blob"), nowSeconds());
            if (!settings_->claim(fingerprint)) {
                redirectTo(response, "/login");
                return;
            }
            bazarish::log::info("this panel is now administered by {}", fingerprint);
            const std::string token = sessions_.create(nowSeconds());
            response.headers["Set-Cookie"]
                = std::string(kCookieName) + "=" + token + kCookieAttributes;
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
        try {
            auth_.login(request.param("challenge"), request.param("blob"), nowSeconds());
            const std::string token = sessions_.create(nowSeconds());
            response.headers["Set-Cookie"]
                = std::string(kCookieName) + "=" + token + kCookieAttributes;
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            bazarish::log::warn("panel sign-in refused: {}", error.what());
            sendHtml(response, loginPage(error.what()), 401);
        }
    }));

    http_->post("/logout", filled([this](const http::Request& request, http::Response& response) {
        sessions_.destroy(request.cookie(kCookieName));
        response.headers["Set-Cookie"]
            = std::string(kCookieName) + "=" + kCookieAttributes + "; Max-Age=0";
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

    // Everything below is the app talking to the panel. A stale session gets a
    // 401 the page turns into a bounce to the sign-in screen.
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

    // Every service probed at once: one service being down must not hold the
    // page on the ones that are up.
    http_->get("/api/services", api([this](const http::Request&, http::Response& response) {
        // Every service of every deployment at once: one being down must not hold
        // the page on the ones that are up, and an operator watching two servers
        // wants both on the same screen.
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
                [this, service]() { return probeHealth(service, identity_); }));
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
                // A facade reports what it is carrying; the others report nothing
                // here and the panel shows nothing for them.
                {"requestsLastMinute", health.requestsLastMinute},
                {"requestsLastHour", health.requestsLastHour},
                {"requestsLastDay", health.requestsLastDay},
                {"inFlight", health.inFlight},
            });
        }
        nlohmann::json fleets = nlohmann::json::array();
        for (const Fleet& fleet : panel.fleets) {
            fleets.push_back(fleet.name);
        }
        sendJson(response, nlohmann::json{{"services", services}, {"fleets", fleets}}.dump());
    }));

    // The account list, searched and paged by the node itself.
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

    http_->get("/api/user", api([this](const http::Request& request, http::Response& response) {
        proxyToNode(request.query("fleet"), response, "GET",
            "/v1/account/user?user=" + urlEncoded(request.query("user")), {});
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
        proxyToNode(body.value("fleet", std::string()), response, "DELETE",
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

    // One account as the messaging server sees it: what its mailbox holds and how
    // many devices are collecting it. Neither is known to the node.
    http_->get("/api/account", api([this](
                                   const http::Request& request, http::Response& response) {
        const std::optional<ServiceEntry> core
            = serviceOfKind(request.query("fleet"), "server-core");
        if (!core.has_value()) {
            sendError(response, 503, "no server-core configured in this panel");
            return;
        }
        const JsonResult account = callJson(*core, identity_, "GET",
            "/v1/messaging/account?user=" + urlEncoded(request.query("user")));
        if (account.status == 0) {
            bazarish::log::warn("server-core unreachable: {}", account.error);
            sendError(response, 502,
                account.error.empty() ? "server-core unreachable" : account.error);
            return;
        }
        sendJson(response, account.body, account.status);
    }));

    // The settings an operator turns, plus the two numbers that say whether they
    // still fit: what the quotas promise, and what the messaging server's disk
    // actually holds. The second is measured by the server that owns the disk.
    http_->get("/api/settings", api([this](
                                    const http::Request& request, http::Response& response) {
        const std::optional<ServiceEntry> node
            = serviceOfKind(request.query("fleet"), "service-node");
        if (!node.has_value()) {
            sendError(response, 503, "this deployment has no service node the panel can reach");
            return;
        }
        const JsonResult settings = callJson(*node, identity_, "GET", "/v1/account/settings");
        if (!settings.ok) {
            bazarish::log::warn("service-node settings unavailable: {}", settings.error);
            sendJson(response, settings.body, settings.status == 0 ? 502 : settings.status);
            return;
        }
        nlohmann::json merged = nlohmann::json::parse(settings.body);
        // A storage figure nobody could measure is reported as unknown, not as
        // zero: "no data" and "nothing stored" are not the same answer.
        merged["diskUsedBytes"] = nullptr;
        merged["diskError"] = "no server-core configured in this panel";
        if (const std::optional<ServiceEntry> core
            = serviceOfKind(request.query("fleet"), "server-core");
            core.has_value()) {
            const JsonResult disk = callJson(*core, identity_, "GET", "/v1/messaging/storage");
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

    // The configuration of one service, straight from the service that owns it.
    // The panel knows only which path each kind answers on: the settings
    // themselves are the service's, and so is every rule about them.
    const auto serviceSettingsPath = [](const std::string& kind) -> std::string {
        if (kind == "server-core") {
            return "/v1/messaging/settings";
        }
        if (kind == "service-node") {
            return "/v1/account/settings";
        }
        if (kind == "facade") {
            return "/settings";
        }
        return {};
    };
    const auto restartPath = [](const std::string& kind) -> std::string {
        if (kind == "server-core") {
            return "/v1/messaging/restart";
        }
        if (kind == "service-node") {
            return "/v1/account/restart";
        }
        if (kind == "facade") {
            return "/restart";
        }
        return {};
    };

    const auto toService = [this, serviceSettingsPath, restartPath](const http::Request& request,
                               http::Response& response, const std::string& method,
                               const bool restarting) {
        const std::string kind = request.query("kind");
        const std::string path
            = restarting ? restartPath(kind) : serviceSettingsPath(kind);
        if (path.empty()) {
            sendError(response, 400, "the panel does not know a service of kind \"" + kind + "\"");
            return;
        }
        const std::optional<ServiceEntry> service = serviceOfKind(request.query("fleet"), kind);
        if (!service.has_value()) {
            sendError(response, 503, "this deployment has no " + kind + " the panel can reach");
            return;
        }
        const JsonResult result = callJson(*service, identity_, method, path, request.body);
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

    // A service is restarted from here rather than over SSH: a setting only a
    // start reads is otherwise saved and inert until somebody opens a terminal.
    http_->post("/api/restart", api([toService](
                                    const http::Request& request, http::Response& response) {
        toService(request, response, "POST", true);
    }));

    // The panel's own settings - the ones no service knows about: who may sign
    // in, the words it signs under, the deployments it manages, where it listens.
    // Beside them the facts an operator can only read, so one page answers "what
    // is this panel" without an SSH session.
    http_->get("/api/panel", api([this](const http::Request&, http::Response& response) {
        const Config panel = settings_->get();
        nlohmann::json fleets = nlohmann::json::array();
        for (const Fleet& fleet : panel.fleets) {
            nlohmann::json services = nlohmann::json::array();
            for (const ServiceEntry& service : fleet.services) {
                services.push_back({{"name", service.name}, {"kind", service.kind},
                    {"url", service.url}});
            }
            fleets.push_back({{"name", fleet.name}, {"services", services}});
        }
        sendJson(response,
            nlohmann::json{
                {"admins", panel.admins},
                {"consumer",
                    {{"name", panel.consumer.name}, {"place", panel.consumer.place},
                        {"role", panel.consumer.role}}},
                {"listen", {{"host", panel.listenHost}, {"port", panel.listenPort}}},
                {"fleets", fleets},
                {"fingerprint", identity_.fingerprint()},
                {"canRestart", static_cast<bool>(options_.requestRestart)},
                {"configPath", settings_->configPath().string()},
                {"stateDir", panel.stateDir},
                {"assetsDir", panel.assetsDir},
                {"version", options_.version},
            }
                .dump());
    }));

    // The panel restarts itself for the same reason it restarts the others: a
    // listener written into the file is inert until the process reads it again.
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
                // Emptying the list would hand the panel back to the setup
                // wizard - to whoever reaches it first. That is not a setting.
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
            if (body.contains("listen")) {
                const nlohmann::json& listen = body.at("listen");
                const std::string host = listen.value("host", panel.listenHost);
                const int port = listen.value("port", panel.listenPort);
                if (host.empty()) {
                    throw std::invalid_argument("a listener needs a host to bind");
                }
                if (port < bazarish::kMinPort || port > bazarish::kMaxPort) {
                    throw std::invalid_argument("a port is between "
                        + std::to_string(bazarish::kMinPort) + " and "
                        + std::to_string(bazarish::kMaxPort));
                }
                panel.listenHost = host;
                panel.listenPort = port;
            }
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
                        if (!isKnownServiceKind(service.kind)) {
                            throw std::invalid_argument(
                                "the panel does not know a service of kind \"" + service.kind
                                + "\"");
                        }
                        if (service.url.empty() || service.name.empty()) {
                            throw std::invalid_argument("a service needs a name and a URL");
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
            // A change that could not be written would be lost at the next
            // start; saying so beats pretending it stuck.
            sendError(response, 500, error.what());
        }
    }));

    // The quota belongs to the node that grants it; the panel only carries the
    // operator's number over.
    http_->put("/api/quota", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body);
        proxyToNode(request.query("fleet"), response, "PUT", "/v1/account/quota",
            nlohmann::json{{"user", body.at("user")}, {"quotaBytes", body.at("quotaBytes")}}
                .dump());
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
