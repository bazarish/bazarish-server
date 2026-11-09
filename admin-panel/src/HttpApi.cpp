// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include <FleetRoutes.hpp>
#include <LoginRelay.hpp>
#include <QrSvg.hpp>
#include <SignInScan.hpp>
#include <WebFace.hpp>

#include "FleetSync.hpp"
#include "ServiceClient.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/JsonRead.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Percent.hpp>
#include <bazarish/WebAssets.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <string>
#include <utility>
#include <vector>

using bazarish::server::clearCookie;
using bazarish::server::newSignInToken;
using bazarish::server::notice;
using bazarish::server::redirectTo;
using bazarish::server::sendHtml;
using bazarish::server::sendJson;
using bazarish::server::sendJsonText;
using bazarish::server::setCookie;
using bazarish::server::signInScan;

namespace {

namespace http = bazarish::http;
namespace fleet = bazarish::fleet;

using bazarish::htmlEscape;
using bazarish::nowSeconds;
using bazarish::http::filled;

const char* const kCookieName = "adminsession";
const char* const kCookieAttributes = "; HttpOnly; SameSite=Strict; Path=/";
const char* const kSignInCookie = "adminsignin";
const char* const kSignInCookieAttributes = "; HttpOnly; SameSite=Strict; Path=/login";

void sendError(http::Response& response, const int status, const std::string& message)
{
    sendJson(response, nlohmann::json{{"error", message}}, status);
}

void setSessionCookie(http::Response& response, const std::string& token)
{
    setCookie(response, kCookieName, token, kCookieAttributes);
}

void clearSessionCookie(http::Response& response)
{
    clearCookie(response, kCookieName, kCookieAttributes);
}

nlohmann::json linkErrorsOf(const bazarish::admin::GatewayLinking& linking)
{
    nlohmann::json errors = nlohmann::json::array();
    if (!linking.error.empty()) {
        errors.push_back(linking.error);
    }
    for (const bazarish::admin::GatewayRepoint& gateway : linking.gateways) {
        if (!gateway.error.empty()) {
            errors.push_back("gateway \"" + gateway.name + "\": " + gateway.error);
        }
    }
    return errors;
}

nlohmann::json syncedFleets(const std::vector<bazarish::admin::Fleet>& fleets,
    const bazarish::Identity& identity, const bazarish::tls::Credential& credential)
{
    nlohmann::json descriptors = nlohmann::json::array();
    nlohmann::json links = nlohmann::json::array();
    for (const bazarish::admin::Fleet& fleet : fleets) {
        const std::string error = bazarish::admin::publishFacades(fleet, identity, credential);
        if (!error.empty()) {
            descriptors.push_back({{"fleet", fleet.name}, {"error", error}});
        }
        for (const nlohmann::json& linkError :
            linkErrorsOf(bazarish::admin::linkGateways(fleet, identity, credential))) {
            links.push_back({{"fleet", fleet.name}, {"error", linkError}});
        }
    }
    return {{"descriptorErrors", descriptors}, {"gatewayLinkErrors", links}};
}

std::string settingsPathOf(const std::string& kind)
{
    if (kind == bazarish::admin::kServerCoreKind) {
        return fleet::kMessagingSettings;
    }
    if (kind == bazarish::admin::kServiceNodeKind) {
        return fleet::kAccountSettings;
    }
    if (kind == bazarish::admin::kFacadeKind || kind == bazarish::admin::kGatewayKind) {
        return fleet::kOpsSettings;
    }
    return {};
}

std::string restartPathOf(const std::string& kind)
{
    if (kind == bazarish::admin::kServerCoreKind) {
        return fleet::kMessagingRestart;
    }
    if (kind == bazarish::admin::kServiceNodeKind) {
        return fleet::kAccountRestart;
    }
    if (kind == bazarish::admin::kFacadeKind || kind == bazarish::admin::kGatewayKind) {
        return fleet::kOpsRestart;
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

std::optional<Fleet> HttpApi::fleetNamed(const std::string& fleet) const
{
    for (const Fleet& candidate : settings_->get().fleets) {
        if (fleet.empty() || candidate.name == fleet) {
            return candidate;
        }
    }
    return std::nullopt;
}

std::optional<ServiceEntry> HttpApi::serviceNamed(
    const std::string& fleet, const std::string& name) const
{
    const std::optional<Fleet> found = fleetNamed(fleet);
    if (!found.has_value()) {
        return std::nullopt;
    }
    for (const ServiceEntry& service : found->services) {
        if (service.name == name) {
            return service;
        }
    }
    return std::nullopt;
}

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

std::string HttpApi::loginFacade(const ServiceEntry& node)
{
    const JsonResult settings
        = callJson(node, identity_, credential_, "GET", fleet::kAccountSettings);
    if (!settings.ok) {
        bazarish::log::warn("sign-in shows no code: the service node did not answer ({})",
            failureText(settings));
        return {};
    }
    const nlohmann::json facades = bazarish::parseJson(settings.body).at("facades");
    if (facades.empty() || !isB32I2pHost(facades.front().get<std::string>())) {
        return {};
    }
    return facades.front().get<std::string>();
}

std::string HttpApi::loginForm(const std::string& error, http::Response& response)
{
    const std::int64_t now = nowSeconds();
    const std::optional<ServiceEntry> node = serviceOfKind(std::string(), kServiceNodeKind);
    const std::string facade = node.has_value() ? loginFacade(*node) : std::string();
    std::string scan;
    if (!facade.empty()) {
        const std::string challenge = auth_.issueChallenge(now, loginrelay::callbackUrl(facade));
        const std::string token = newSignInToken();
        const Bytes key = newLinkKey();
        const JsonResult expected = callJson(*node, identity_, credential_, "POST",
            fleet::kLoginExpect,
            nlohmann::json{{"challenge", challenge}, {"token", token}, {"key", linkKeyText(key)}}
                .dump());
        if (expected.ok) {
            setCookie(response, kSignInCookie, token, kSignInCookieAttributes);
            scan = signInScan(assets_, facade, challenge, key);
        } else {
            bazarish::log::warn("sign-in shows no code: the service node refused it ({})",
                failureText(expected));
        }
    }
    const std::string challenge = auth_.issueChallenge(now);
    return assets_.render("login.html",
        {
            {"challenge", htmlEscape(challenge)},
            {"error", notice(error, "is-error")},
            {"scan", scan},
        });
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
    sendJsonText(response, result.body, result.status);
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
        const std::optional<std::string> holder
            = sessions_.holder(request.cookie(kCookieName), nowSeconds());
        if (!holder.has_value()) {
            return false;
        }
        const std::vector<std::string> admins = settings_->get().admins;
        return std::find(admins.begin(), admins.end(), *holder) != admins.end();
    };

    const auto setupPage = [this](const std::string& error) {
        return assets_.render("setup.html",
            {
                {"challenge", auth_.issueChallenge(nowSeconds())},
                {"error", notice(error, "is-error")},
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
            setSessionCookie(response, sessions_.create(fingerprint, nowSeconds()));
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            bazarish::log::warn("panel setup refused: {}", error.what());
            sendHtml(response, setupPage(error.what()), 401);
            return;
        }
        try {
            for (const nlohmann::json& failures :
                syncedFleets(settings_->get().fleets, identity_, credential_)) {
                for (const nlohmann::json& failure : failures) {
                    bazarish::log::warn("deployment {}: {}", failure.at("fleet").get<std::string>(),
                        failure.at("error").get<std::string>());
                }
            }
        } catch (const std::exception& error) {
            bazarish::log::warn("the deployments were not written: {}", error.what());
        }
    }));

    http_->get("/login", filled([this, signedIn](
                             const http::Request& request, http::Response& response) {
        if (settings_->unclaimed()) {
            redirectTo(response, "/setup");
            return;
        }
        if (signedIn(request)) {
            redirectTo(response, "/");
            return;
        }
        sendHtml(response, loginForm(std::string(), response));
    }));

    http_->get("/login/wait", filled([this](const http::Request& request, http::Response& response) {
        const std::optional<ServiceEntry> node = serviceOfKind(std::string(), kServiceNodeKind);
        if (!node.has_value()) {
            sendJson(response, nlohmann::json{{"state", "gone"}});
            return;
        }
        const JsonResult claimed = callJson(*node, identity_, credential_, "POST", fleet::kLoginClaim,
            nlohmann::json{{"nonce", request.query("nonce")},
                {"token", request.cookie(kSignInCookie)}}
                .dump());
        if (!claimed.ok) {
            sendError(response, 502, failureText(claimed));
            return;
        }
        const nlohmann::json claim = bazarish::parseJson(claimed.body);
        std::string state = claim.at("state").get<std::string>();
        if (state == "signed") {
            try {
                const std::string fingerprint = auth_.login(claim.at("challenge").get<std::string>(),
                    claim.at("blob").get<std::string>(), nowSeconds());
                setSessionCookie(response, sessions_.create(fingerprint, nowSeconds()));
                state = "signedIn";
            } catch (const std::exception& error) {
                bazarish::log::warn("panel sign-in refused: {}", error.what());
                state = "gone";
            }
        }
        sendJson(response, nlohmann::json{{"state", state}});
    }));

    http_->post("/login", filled([this](
                              const http::Request& request, http::Response& response) {
        if (settings_->unclaimed()) {
            redirectTo(response, "/setup");
            return;
        }
        try {
            const std::string fingerprint
                = auth_.login(request.param("challenge"), request.param("blob"), nowSeconds());
            setSessionCookie(response, sessions_.create(fingerprint, nowSeconds()));
            redirectTo(response, "/");
        } catch (const std::exception& error) {
            bazarish::log::warn("panel sign-in refused: {}", error.what());
            sendHtml(response, loginForm(error.what(), response), 401);
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
        sendJson(response, nlohmann::json{{"services", services}, {"fleets", fleets}});
    }));

    http_->get("/api/users", api([this](const http::Request& request, http::Response& response) {
        std::string query = "/v1/account/users?q=" + percentEncode(request.query("q"))
            + "&state=" + percentEncode(request.query("state"));
        if (const std::string limit = request.query("limit"); !limit.empty()) {
            query += "&limit=" + percentEncode(limit);
        }
        if (const std::string offset = request.query("offset"); !offset.empty()) {
            query += "&offset=" + percentEncode(offset);
        }
        proxyToNode(request.query("fleet"), response, "GET", query, std::string());
    }));

    http_->post("/api/qr", api([](const http::Request& request, http::Response& response) {
        const nlohmann::json body = bazarish::parseJson(request.body);
        sendJson(response, nlohmann::json{{"svg", qr::svg(body.at("text").get<std::string>())}});
    }));

    http_->post("/api/approve", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = bazarish::parseJson(request.body);
        proxyToNode(request.query("fleet"), response, "POST", fleet::kAccountApprove,
            nlohmann::json{{"user", body.at("user")}}.dump());
    }));

    http_->post("/api/undelegate", api([this](
                                       const http::Request& request, http::Response& response) {
        const nlohmann::json body = bazarish::parseJson(request.body);
        proxyToNode(request.query("fleet"), response, "POST", fleet::kAccountUndelegate,
            nlohmann::json{{"user", body.at("user")},
                {"message", body.value("message", std::string())}}
                .dump());
    }));

    http_->post("/api/delete", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = bazarish::parseJson(request.body);
        proxyToNode(request.query("fleet"), response, "DELETE",
            "/v1/account/user?user=" + percentEncode(body.at("user").get<std::string>()), {});
    }));

    http_->post("/api/ban", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = bazarish::parseJson(request.body);
        proxyToNode(request.query("fleet"), response, "POST", fleet::kAccountBan,
            nlohmann::json{{"user", body.at("user")}, {"reason", body.value("reason", std::string())}}
                .dump());
    }));

    http_->post("/api/unban", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = bazarish::parseJson(request.body);
        proxyToNode(request.query("fleet"), response, "POST", fleet::kAccountUnban,
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
            "/v1/messaging/account?user=" + percentEncode(request.query("user")));
        if (account.status == 0) {
            bazarish::log::warn("server-core unreachable: {}", account.error);
            sendError(response, 502,
                account.error.empty() ? "server-core unreachable" : account.error);
            return;
        }
        sendJsonText(response, account.body, account.status);
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
            = callJson(*node, identity_, credential_, "GET", fleet::kAccountSettings);
        if (!settings.ok) {
            bazarish::log::warn("service-node settings unavailable: {}", settings.error);
            sendJsonText(response, settings.body, settings.status == 0 ? 502 : settings.status);
            return;
        }
        nlohmann::json merged = bazarish::parseJson(settings.body);
        merged["diskUsedBytes"] = nullptr;
        merged["diskError"] = "no server-core configured in this panel";
        if (const std::optional<ServiceEntry> core
            = serviceOfKind(request.query("fleet"), kServerCoreKind);
            core.has_value()) {
            const JsonResult disk
                = callJson(*core, identity_, credential_, "GET", fleet::kMessagingStorage);
            if (disk.ok) {
                merged["diskUsedBytes"] = bazarish::parseJson(disk.body).at("usedBytes");
                merged["diskError"] = "";
            } else {
                bazarish::log::warn("storage usage unavailable: {}", disk.error);
                merged["diskError"] = disk.error.empty() ? "server-core unreachable" : disk.error;
            }
        }
        sendJson(response, merged);
    }));

    http_->put("/api/settings", api([this](const http::Request& request, http::Response& response) {
        proxyToNode(request.query("fleet"), response, "PUT", fleet::kAccountSettings, request.body);
    }));

    const auto toService = [this](const http::Request& request, http::Response& response,
                               const std::string& method, const bool restarting) {
        const std::string name = request.query("service");
        const std::string kind = request.query("kind");
        std::optional<ServiceEntry> service;
        if (!name.empty()) {
            service = serviceNamed(request.query("fleet"), name);
        } else if (kind == kServerCoreKind || kind == kServiceNodeKind) {
            service = serviceOfKind(request.query("fleet"), kind);
        } else {
            sendError(response, 400,
                "a deployment has one " + std::string(kServerCoreKind) + " and one "
                    + kServiceNodeKind + "; anything else is asked for by name");
            return;
        }
        if (!service.has_value()) {
            sendError(response, 503,
                "this deployment has no " + (name.empty() ? kind : "\"" + name + "\"")
                    + " the panel can reach");
            return;
        }
        const std::string path
            = restarting ? restartPathOf(service->kind) : settingsPathOf(service->kind);
        if (path.empty()) {
            sendError(response, 400, "a " + service->kind + " has no settings of its own here");
            return;
        }
        const JsonResult result
            = callJson(*service, identity_, credential_, method, path, request.body);
        if (result.status == 0) {
            bazarish::log::warn("{} unreachable: {}", service->name, result.error);
            sendError(response, 502,
                result.error.empty() ? service->name + " unreachable" : result.error);
            return;
        }
        const bool linksGateways = service->kind == kServerCoreKind || service->kind == kFacadeKind;
        const std::optional<Fleet> fleet = fleetNamed(request.query("fleet"));
        if (method != "PUT" || restarting || !result.ok || !linksGateways || !fleet.has_value()) {
            sendJsonText(response, result.body, result.status);
            return;
        }
        nlohmann::json answer = bazarish::parseJson(result.body);
        answer["gatewayLinkErrors"] = linkErrorsOf(linkGateways(*fleet, identity_, credential_));
        sendJson(response, answer, result.status);
    };

    http_->get("/api/facades", api([this](const http::Request& request,
                                       http::Response& response) {
        const std::optional<Fleet> fleet = fleetNamed(request.query("fleet"));
        if (!fleet.has_value()) {
            sendError(response, 404, "no such deployment");
            return;
        }
        nlohmann::json described = nlohmann::json::array();
        std::string describedError = "this deployment has no service node";
        if (const std::optional<ServiceEntry> node = serviceOfKind(fleet->name, kServiceNodeKind);
            node.has_value()) {
            const JsonResult shown
                = callJson(*node, identity_, credential_, "GET", fleet::kAccountSettings);
            if (shown.ok) {
                described = bazarish::parseJson(shown.body).value(
                    "facades", nlohmann::json::array());
                describedError.clear();
            } else {
                describedError = failureText(shown);
            }
        }
        const std::vector<FacadeReport> reports = facadeReports(*fleet, identity_, credential_);
        nlohmann::json facades = nlohmann::json::array();
        std::size_t next = 0;
        for (const ServiceEntry& service : fleet->services) {
            if (service.kind != kFacadeKind) {
                continue;
            }
            const FacadeReport& report = reports.at(next++);
            bool inDescriptor = false;
            for (const nlohmann::json& address : described) {
                inDescriptor
                    = inDescriptor || (!report.address.empty() && address == report.address);
            }
            facades.push_back({
                {"name", service.name},
                {"ops", service.url},
                {"address", report.address},
                {"error", report.error},
                {"inDescriptor", inDescriptor},
            });
        }
        sendJson(response,
            nlohmann::json{{"facades", facades}, {"descriptor", described},
                {"descriptorError", describedError}});
    }));

    http_->post("/api/facade/new-address", api([this](const http::Request& request,
                                                  http::Response& response) {
        const std::optional<Fleet> fleet = fleetNamed(request.query("fleet"));
        const std::optional<ServiceEntry> facade
            = serviceNamed(request.query("fleet"), request.query("service"));
        if (!fleet.has_value() || !facade.has_value() || facade->kind != kFacadeKind) {
            sendError(response, 404, "this deployment has no such facade");
            return;
        }
        const JsonResult minted
            = callJson(*facade, identity_, credential_, "POST", "/new-address");
        if (!minted.ok) {
            sendError(response, minted.status == 0 ? 502 : minted.status, failureText(minted));
            return;
        }
        const nlohmann::json answer = bazarish::parseJson(minted.body);
        const std::string address = answer.at("address").get<std::string>();
        const std::string previous = answer.at("previousAddress").get<std::string>();
        bazarish::log::info("facade {} has a new address", facade->name);
        const std::string descriptorError = publishFacades(
            *fleet, identity_, credential_, {{facade->name, address}});
        nlohmann::json gateways = nlohmann::json::array();
        for (const GatewayRepoint& repointed : repointGateways(
                 settings_->get().fleets, previous, address, identity_, credential_)) {
            gateways.push_back({{"name", repointed.name}, {"changed", repointed.changed},
                {"error", repointed.error}});
        }
        sendJson(response,
            nlohmann::json{{"address", address}, {"previousAddress", previous},
                {"descriptorError", descriptorError}, {"gateways", gateways}});
    }));

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
            });
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
        sendJson(response, nlohmann::json{{"restarting", true}});
    }));

    http_->put("/api/panel", api([this](const http::Request& request, http::Response& response) {
        try {
            const nlohmann::json body = bazarish::parseJson(request.body);
            const Config panel = settings_->update([&body](Config& edited) {
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
                    edited.admins = std::move(admins);
                }
                if (body.contains("consumer")) {
                    const nlohmann::json& consumer = body.at("consumer");
                    service::LoginConsumer wanted;
                    wanted.name = consumer.value("name", edited.consumer.name);
                    wanted.place = consumer.value("place", edited.consumer.place);
                    wanted.role = consumer.value("role", edited.consumer.role);
                    try {
                        service::requireUsableConsumer(wanted);
                    } catch (const std::exception& error) {
                        throw std::invalid_argument(error.what());
                    }
                    edited.consumer = wanted;
                }
                readEndpointInto(body, "listen", edited.listenHost, edited.listenPort);
                if (body.contains("fleets")) {
                    edited.fleets = fleetsFromJson(body.at("fleets"));
                }
            });
            nlohmann::json answer = syncedFleets(panel.fleets, identity_, credential_);
            answer["admins"] = panel.admins;
            sendJson(response, answer);
        } catch (const std::invalid_argument& error) {
            sendError(response, 400, error.what());
        } catch (const nlohmann::json::exception& error) {
            sendError(response, 400, error.what());
        } catch (const std::exception& error) {
            sendError(response, 500, error.what());
        }
    }));

    http_->put("/api/quota", api([this](const http::Request& request, http::Response& response) {
        const nlohmann::json body = bazarish::parseJson(request.body);
        proxyToNode(request.query("fleet"), response, "PUT", fleet::kAccountQuota,
            nlohmann::json{{"user", body.at("user")}, {"quotaBytes", body.at("quotaBytes")}}
                .dump());
    }));
}

int HttpApi::bind(const std::string& host, const int port)
{
    http::Server::Options options;
    options.denyFraming = true;
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
