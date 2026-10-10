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
        report.url = nlohmann::json::parse(shown.body).value("url", std::string());
    } catch (const std::exception& error) {
        report.error = error.what();
        return report;
    }
    if (report.url.empty()) {
        report.error = "it reports no address: it is older than this panel";
    }
    return report;
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
    std::map<std::string, std::string> urls = known;
    for (const FacadeReport& report : facadeReports(unknown, identity, credential)) {
        if (!report.error.empty()) {
            return "facade \"" + report.name + "\" did not give its address (" + report.error
                + "), so the descriptor was left as it was";
        }
        urls[report.name] = report.url;
    }

    nlohmann::json ordered = nlohmann::json::array();
    for (const ServiceEntry& service : fleet.services) {
        if (service.kind == kFacadeKind) {
            ordered.push_back(urls.at(service.name));
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

std::vector<GatewayRepoint> repointGateways(const std::vector<Fleet>& fleets,
    const std::string& fromUrl, const std::string& toUrl, const Identity& identity,
    const tls::Credential& credential)
{
    const std::string from = hostOf(fromUrl);
    const std::string to = hostOf(toUrl);
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
