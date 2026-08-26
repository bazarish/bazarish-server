// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "ServiceClient.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/WebAssets.hpp>

#include <nlohmann/json.hpp>

#include <ctime>
#include <exception>
#include <functional>
#include <future>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace http = bazarish::http;

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

const char* const kCookieName = "adminsession";

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
    constexpr std::int64_t kSecondsPerMinute = 60;
    constexpr std::int64_t kSecondsPerHour = 3600;
    constexpr std::int64_t kSecondsPerDay = 86400;
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

HttpApi::HttpApi(Config config, const Identity& identity, HttpApiOptions options)
    : config_(std::move(config))
    , identity_(identity)
    , options_(std::move(options))
    , auth_(config_.audience, config_.admins)
    , sessions_(options_.sessionTtlSeconds)
    , assets_(options_.assetsDirectory)
{
}

HttpApi::~HttpApi() = default;

const ServiceEntry* HttpApi::serviceOfKind(const std::string& fleet, const std::string& kind) const
{
    for (const Fleet& candidate : config_.fleets) {
        if (!fleet.empty() && candidate.name != fleet) {
            continue;
        }
        for (const ServiceEntry& service : candidate.services) {
            if (service.kind == kind) {
                return &service;
            }
        }
        if (!fleet.empty()) {
            return nullptr;  // named, and it has none of this kind
        }
    }
    return nullptr;
}

// Passes a call through to the service that owns the accounts, and hands its
// answer back untouched. The panel holds no user state of its own: what it shows
// is what the node says, one request ago.
void HttpApi::proxyToNode(const std::string& fleet, http::Response& response,
    const std::string& method, const std::string& path, const std::string& body)
{
    const ServiceEntry* const node = serviceOfKind(fleet, "service-node");
    if (node == nullptr) {
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
        http_->get("/" + name, [&file](const http::Request&) {
            http::Response response;
            response.contentType = file.contentType;
            response.body = file.body;
            return response;
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
                {"error", error.empty() ? std::string()
                                        : "<p class=\"notice is-error\">" + error + "</p>"},
            });
    };

    http_->get("/login", filled([this, signedIn, loginPage](
                             const http::Request& request, http::Response& response) {
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
                = std::string(kCookieName) + "=" + token + "; HttpOnly; SameSite=Strict; Path=/";
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            bazarish::log::warn("panel sign-in refused: {}", error.what());
            sendHtml(response, loginPage(error.what()), 401);
        }
    }));

    http_->post("/logout", filled([this](const http::Request& request, http::Response& response) {
        sessions_.destroy(request.cookie(kCookieName));
        response.headers["Set-Cookie"]
            = std::string(kCookieName) + "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
        redirectTo(response, "/login");
    }));

    http_->get("/", filled([this, signedIn](
                        const http::Request& request, http::Response& response) {
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
        std::vector<std::pair<const Fleet*, const ServiceEntry*>> all;
        for (const Fleet& fleet : config_.fleets) {
            for (const ServiceEntry& service : fleet.services) {
                all.emplace_back(&fleet, &service);
            }
        }
        std::vector<std::future<HealthResult>> probes;
        probes.reserve(all.size());
        for (const auto& [fleet, service] : all) {
            probes.push_back(std::async(std::launch::async,
                [this, service]() { return probeHealth(*service, identity_); }));
        }
        nlohmann::json services = nlohmann::json::array();
        for (std::size_t i = 0; i < all.size(); ++i) {
            const HealthResult health = probes[i].get();
            services.push_back(nlohmann::json{
                {"fleet", all[i].first->name},
                {"name", all[i].second->name},
                {"kind", all[i].second->kind},
                {"url", all[i].second->url},
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
        for (const Fleet& fleet : config_.fleets) {
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
        const ServiceEntry* const core = serviceOfKind(request.query("fleet"), "server-core");
        if (core == nullptr) {
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
        const ServiceEntry* const node = serviceOfKind(request.query("fleet"), "service-node");
        if (node == nullptr) {
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
        if (const ServiceEntry* const core = serviceOfKind(request.query("fleet"), "server-core");
            core != nullptr) {
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
