// Bazarish project (c) 2026
#include "FleetSetup.hpp"

#include <StateIdentity.hpp>

#include <bazarish/ConfigFile.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Tls.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::setup {

namespace {

namespace fs = std::filesystem;

constexpr const char* kLoopback = "127.0.0.1";
constexpr int kCorePort = 8420;
constexpr int kCoreOpsPort = 8428;
constexpr int kCoreGatewayPort = 8424;
constexpr int kNodePort = 8421;
constexpr int kNodeOpsPort = 8427;
constexpr int kFacadePort = 8419;
constexpr int kFacadeDirectPort = 8418;
constexpr int kFacadeOpsPort = 8429;
constexpr int kGatewayOpsPort = 8439;
constexpr int kJsonIndent = 2;

constexpr const char* kCoreName = "server-core";
constexpr const char* kNodeName = "service-node";
constexpr const char* kFacadeName = "facade";
constexpr const char* kPanelName = "admin-panel";
constexpr const char* kGatewayName = "gateway";
constexpr const char* kServerCardName = "server-card.der";

nlohmann::json endpoint(const int port)
{
    return {{"host", kLoopback}, {"port", port}};
}

nlohmann::json pinned(const int port, const std::string& pin)
{
    nlohmann::json reached = endpoint(port);
    reached["pin"] = pin;
    return reached;
}

std::string tlsUrl(const std::string& host, const int port)
{
    return "https://" + host + ":" + std::to_string(port);
}

std::string tlsUrl(const int port)
{
    return tlsUrl(kLoopback, port);
}

std::string dialledHost(const std::string& host)
{
    return host.empty() || host == "0.0.0.0" || host == "::" ? kLoopback : host;
}

nlohmann::json fleetEntry(const char* kind, const std::string& url, const std::string& pin)
{
    return {{"name", kind}, {"kind", kind}, {"url", url}, {"pin", pin}};
}

std::vector<std::string> withEntry(std::vector<std::string> list, const std::string& entry)
{
    if (std::find(list.begin(), list.end(), entry) == list.end()) {
        list.push_back(entry);
    }
    return list;
}

void writeConfig(const fs::path& path, const nlohmann::json& config)
{
    writePrivateFile(path, config.dump(kJsonIndent) + "\n");
}

}  // namespace

bool setUpFleet(const Layout& layout)
{
    const auto configOf = [&layout](const char* name) {
        return layout.configDir / (std::string(name) + ".json");
    };
    const auto stateOf = [&layout](const char* name) { return layout.stateDir / name; };
    for (const char* name : {kCoreName, kNodeName, kFacadeName, kPanelName}) {
        if (fs::exists(configOf(name))) {
            return false;
        }
    }

    ConfigFile gateway(configOf(kGatewayName));
    const ConfigView gatewaySettings(gateway.read());
    const fs::path gatewayState = gatewaySettings.text("state");

    const std::string corePin = tls::selfSigned(stateOf(kCoreName)).pin;
    const std::string nodePin = tls::selfSigned(stateOf(kNodeName)).pin;
    const std::string facadePin = tls::selfSigned(stateOf(kFacadeName)).pin;
    const std::string panelPin = tls::selfSigned(stateOf(kPanelName)).pin;
    const std::string gatewayPin = tls::selfSigned(gatewayState).pin;
    const std::string nodeFingerprint
        = server::loadOrCreateIdentity(stateOf(kNodeName)).fingerprint();
    const std::string panelFingerprint
        = server::loadOrCreateIdentity(stateOf(kPanelName)).fingerprint();
    const nlohmann::json panelOperators = nlohmann::json::array({panelFingerprint});
    const nlohmann::json panelClients = nlohmann::json::array({panelPin});

    std::optional<ConfigView::Endpoint> gatewayOps = gatewaySettings.endpoint("opsListen");
    if (!gatewayOps.has_value()) {
        gatewayOps = ConfigView::Endpoint{kLoopback, kGatewayOpsPort};
        gateway.set({"opsListen"}, endpoint(kGatewayOpsPort));
    }
    gateway.set({"operators"}, withEntry(gatewaySettings.list("operators"), panelFingerprint));
    gateway.set({"opsClients"}, withEntry(gatewaySettings.list("opsClients"), panelPin));

    writeConfig(configOf(kNodeName),
        {{"state", stateOf(kNodeName).string()},
            {"serverCard", (stateOf(kCoreName) / kServerCardName).string()},
            {"listen", endpoint(kNodePort)}, {"opsListen", endpoint(kNodeOpsPort)},
            {"messaging", pinned(kCoreOpsPort, corePin)}, {"operators", panelOperators},
            {"opsClients", panelClients},
            {"portal", {{"assets", layout.portalAssets.string()}}}});
    writeConfig(configOf(kFacadeName),
        {{"state", stateOf(kFacadeName).string()}, {"listen", endpoint(kFacadePort)},
            {"directListen", endpoint(kFacadeDirectPort)},
            {"opsListen", endpoint(kFacadeOpsPort)}, {"messaging", pinned(kCorePort, corePin)},
            {"serviceNode", pinned(kNodePort, nodePin)}, {"operators", panelOperators},
            {"opsClients", panelClients}});
    writeConfig(configOf(kCoreName),
        {{"state", stateOf(kCoreName).string()}, {"listen", endpoint(kCorePort)},
            {"opsListen", endpoint(kCoreOpsPort)}, {"gatewayListen", endpoint(kCoreGatewayPort)},
            {"operators", nlohmann::json::array({nodeFingerprint, panelFingerprint})},
            {"opsClients", nlohmann::json::array({nodePin, panelPin})},
            {"serviceNode", {{"url", tlsUrl(kNodePort)}, {"pin", nodePin}}}});
    writeConfig(configOf(kPanelName),
        {{"state", stateOf(kPanelName).string()}, {"assets", layout.panelAssets.string()},
            {"listen", endpoint(kPanelPort)},
            {"fleets",
                nlohmann::json::array({{{"name", layout.fleetName},
                    {"services",
                        nlohmann::json::array({fleetEntry(kCoreName, tlsUrl(kCoreOpsPort), corePin),
                            fleetEntry(kNodeName, tlsUrl(kNodeOpsPort), nodePin),
                            fleetEntry(kFacadeName, tlsUrl(kFacadeOpsPort), facadePin),
                            fleetEntry(kGatewayName,
                                tlsUrl(dialledHost(gatewayOps->host), gatewayOps->port),
                                gatewayPin)})}}})}});
    return true;
}

}  // namespace bazarish::setup
