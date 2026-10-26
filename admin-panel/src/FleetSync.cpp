// Bazarish project (c) 2026
#include "FleetSync.hpp"

#include "ServiceClient.hpp"

#include <bazarish/Tls.hpp>

#include <nlohmann/json.hpp>

#include <exception>
#include <future>
#include <utility>

namespace bazarish::admin {

namespace {

constexpr const char* kFacadeSettingsPath = "/settings";
constexpr const char* kGatewaySettingsPath = "/settings";
constexpr const char* kNodeSettingsPath = "/v1/account/settings";
constexpr const char* kServerSettingsPath = "/v1/messaging/settings";
constexpr const char* kSchemeMark = "://";

FacadeReport reportOf(const ServiceEntry& facade, const Identity& identity,
    const tls::Credential& credential)
{
    FacadeReport report;
    report.name = facade.name;
    const JsonResult shown = callJson(facade, identity, credential, "GET", kFacadeSettingsPath);
    if (!shown.ok) {
        report.error = failureText(shown);
        return report;
    }
    try {
        report.address = nlohmann::json::parse(shown.body).value("address", std::string());
    } catch (const std::exception& error) {
        report.error = error.what();
        return report;
    }
    if (report.address.empty()) {
        report.error = "it reports no address: it is older than this panel";
    }
    return report;
}

bool everyInterface(const std::string& host)
{
    return host.empty() || host == "0.0.0.0" || host == "::" || host == "[::]";
}

// A listener on every interface is dialled where the panel reaches the same service.
nlohmann::json dialledAt(const nlohmann::json& listen, const ServiceEntry& service)
{
    const std::string host = listen.value("host", std::string());
    return {{"host", everyInterface(host) ? hostOf(service.url) : host},
        {"port", listen.value("port", 0)}, {"pin", service.pin}};
}

bool listening(const nlohmann::json& listen)
{
    return listen.is_object() && listen.value("port", 0) > 0;
}

}  // namespace

std::string hostOf(const std::string& url)
{
    const std::size_t mark = url.find(kSchemeMark);
    const std::size_t start
        = mark == std::string::npos ? 0 : mark + std::char_traits<char>::length(kSchemeMark);
    const std::size_t end = url.find_first_of(":/", start);
    return url.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

std::vector<FacadeReport> facadeReports(
    const Fleet& fleet, const Identity& identity, const tls::Credential& credential)
{
    std::vector<std::future<FacadeReport>> asked;
    for (const ServiceEntry& service : fleet.services) {
        if (service.kind != kFacadeKind) {
            continue;
        }
        asked.push_back(std::async(std::launch::async, [service, &identity, &credential]() {
            return reportOf(service, identity, credential);
        }));
    }
    std::vector<FacadeReport> reports;
    reports.reserve(asked.size());
    for (std::future<FacadeReport>& answer : asked) {
        reports.push_back(answer.get());
    }
    return reports;
}

std::string publishFacades(const Fleet& fleet, const Identity& identity,
    const tls::Credential& credential, const std::map<std::string, std::string>& known)
{
    const ServiceEntry* node = nullptr;
    for (const ServiceEntry& service : fleet.services) {
        if (service.kind == kServiceNodeKind) {
            node = &service;
        }
    }
    if (node == nullptr) {
        return {};
    }

    Fleet unknown{fleet.name, {}};
    for (const ServiceEntry& service : fleet.services) {
        if (service.kind == kFacadeKind && !known.contains(service.name)) {
            unknown.services.push_back(service);
        }
    }
    std::map<std::string, std::string> addresses = known;
    for (const FacadeReport& report : facadeReports(unknown, identity, credential)) {
        if (!report.error.empty()) {
            return "facade \"" + report.name + "\" did not give its address (" + report.error
                + "), so the descriptor was left as it was";
        }
        addresses[report.name] = report.address;
    }

    nlohmann::json ordered = nlohmann::json::array();
    for (const ServiceEntry& service : fleet.services) {
        if (service.kind == kFacadeKind) {
            ordered.push_back(addresses.at(service.name));
        }
    }
    if (ordered.empty()) {
        return "this deployment has no facade, so the descriptor keeps the addresses it has";
    }
    const JsonResult written = callJson(*node, identity, credential, "PUT", kNodeSettingsPath,
        nlohmann::json{{"facades", ordered}}.dump());
    if (!written.ok) {
        return "the service node did not take the addresses: " + failureText(written);
    }
    return {};
}

GatewayLinking linkGateways(
    const Fleet& fleet, const Identity& identity, const tls::Credential& credential)
{
    GatewayLinking linking;
    nlohmann::json pins = nlohmann::json::array();
    for (const ServiceEntry& service : fleet.services) {
        if (service.kind == kGatewayKind) {
            pins.push_back(service.pin);
        }
    }
    nlohmann::json server = nullptr;
    for (const ServiceEntry& service : fleet.services) {
        if (service.kind != kServerCoreKind) {
            continue;
        }
        const JsonResult shown = callJson(service, identity, credential, "GET", kServerSettingsPath);
        if (!shown.ok) {
            linking.error = "server-core did not show its settings: " + failureText(shown);
            return linking;
        }
        const nlohmann::json settings = nlohmann::json::parse(shown.body);
        if (settings.value("gateways", nlohmann::json::array()) != pins) {
            const JsonResult written = callJson(service, identity, credential, "PUT",
                kServerSettingsPath, nlohmann::json{{"gateways", pins}}.dump());
            if (!written.ok) {
                linking.error = "server-core did not take the gateways: " + failureText(written);
                return linking;
            }
        }
        const nlohmann::json listen = settings.value("gatewayListen", nlohmann::json());
        if (listening(listen)) {
            server = dialledAt(listen, service);
        }
    }
    nlohmann::json direct = nlohmann::json::array();
    for (const ServiceEntry& service : fleet.services) {
        if (service.kind != kFacadeKind) {
            continue;
        }
        const JsonResult shown = callJson(service, identity, credential, "GET", kFacadeSettingsPath);
        if (!shown.ok) {
            linking.error = "facade \"" + service.name + "\" did not show its settings ("
                + failureText(shown) + "), so the gateways were left as they were";
            return linking;
        }
        const nlohmann::json settings = nlohmann::json::parse(shown.body);
        const nlohmann::json listen = settings.value("directListen", nlohmann::json());
        const std::string address = settings.value("address", std::string());
        if (!listening(listen) || address.empty()) {
            continue;
        }
        nlohmann::json route = dialledAt(listen, service);
        route["dest"] = address;
        direct.push_back(std::move(route));
    }
    for (const ServiceEntry& service : fleet.services) {
        if (service.kind != kGatewayKind) {
            continue;
        }
        GatewayRepoint result;
        result.name = service.name;
        const JsonResult shown = callJson(service, identity, credential, "GET", kGatewaySettingsPath);
        if (!shown.ok) {
            result.error = failureText(shown);
            linking.gateways.push_back(std::move(result));
            continue;
        }
        const nlohmann::json settings = nlohmann::json::parse(shown.body);
        if (settings.value("server", nlohmann::json()) != server
            || settings.value("direct", nlohmann::json::array()) != direct) {
            const JsonResult written = callJson(service, identity, credential, "PUT",
                kGatewaySettingsPath, nlohmann::json{{"server", server}, {"direct", direct}}.dump());
            result.changed = written.ok;
            if (!written.ok) {
                result.error = failureText(written);
            }
        }
        linking.gateways.push_back(std::move(result));
    }
    return linking;
}

std::vector<GatewayRepoint> repointGateways(const std::vector<Fleet>& fleets,
    const std::string& from, const std::string& to, const Identity& identity,
    const tls::Credential& credential)
{
    std::vector<GatewayRepoint> results;
    for (const Fleet& fleet : fleets) {
        for (const ServiceEntry& service : fleet.services) {
            if (service.kind != kGatewayKind) {
                continue;
            }
            GatewayRepoint result;
            result.name = service.name;
            const JsonResult shown
                = callJson(service, identity, credential, "GET", kGatewaySettingsPath);
            if (!shown.ok) {
                result.error = failureText(shown);
                results.push_back(std::move(result));
                continue;
            }
            nlohmann::json direct;
            try {
                direct = nlohmann::json::parse(shown.body).at("direct");
            } catch (const std::exception& error) {
                result.error = error.what();
                results.push_back(std::move(result));
                continue;
            }
            for (nlohmann::json& route : direct) {
                if (route.value("dest", std::string()) == from) {
                    route["dest"] = to;
                    result.changed = true;
                }
            }
            if (result.changed) {
                const JsonResult written = callJson(service, identity, credential, "PUT",
                    kGatewaySettingsPath, nlohmann::json{{"direct", direct}}.dump());
                if (!written.ok) {
                    result.changed = false;
                    result.error = failureText(written);
                }
            }
            results.push_back(std::move(result));
        }
    }
    return results;
}

}  // namespace bazarish::admin
