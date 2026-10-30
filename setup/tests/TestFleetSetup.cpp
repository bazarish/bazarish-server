// Bazarish project (c) 2026
#include "FleetSetup.hpp"

#include <StateIdentity.hpp>

#include <bazarish/ConfigFile.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Tls.hpp>

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

namespace {

namespace fs = std::filesystem;

constexpr const char* kGatewayToken = "token-the-operator-handed-out";
constexpr const char* kOtherPanelFingerprint = "another-panel-administers-this-gateway";
constexpr const char* kOtherPanelPin = "another-panel-key";
constexpr int kOtherOpsPort = 9439;

bazarish::setup::Layout layoutUnder(const fs::path& root)
{
    return {root / "etc", root / "state", "/assets/panel", "/assets/portal", "box"};
}

void writeGateway(
    const bazarish::setup::Layout& layout, nlohmann::json extra = nlohmann::json::object())
{
    fs::create_directories(layout.configDir);
    extra.update({{"basePath", "/secret"}, {"token", kGatewayToken},
        {"state", (layout.stateDir / "gateway").string()}});
    bazarish::writePrivateFile(layout.configDir / "gateway.json", extra.dump());
}

nlohmann::json configOf(const bazarish::setup::Layout& layout, const std::string& name)
{
    return bazarish::ConfigFile(layout.configDir / (name + ".json")).read();
}

std::string pinOf(const fs::path& state)
{
    return bazarish::tls::selfSigned(state).pin;
}

std::string reached(const nlohmann::json& endpoint)
{
    return "https://" + endpoint.at("host").get<std::string>() + ":"
        + std::to_string(endpoint.at("port").get<int>());
}

bool reachedAt(const nlohmann::json& link, const nlohmann::json& listen, const std::string& pin)
{
    return link.at("host") == listen.at("host") && link.at("port") == listen.at("port")
        && link.at("pin") == pin;
}

}  // namespace

int main()
{
    const fs::path root = fs::temp_directory_path() / "bazarish-fleet-setup-test";
    fs::remove_all(root);

    const bazarish::setup::Layout layout = layoutUnder(root / "fresh");
    writeGateway(layout);
    CHECK(bazarish::setup::setUpFleet(layout));

    const nlohmann::json core = configOf(layout, "server-core");
    const nlohmann::json node = configOf(layout, "service-node");
    const nlohmann::json facade = configOf(layout, "facade");
    const nlohmann::json panel = configOf(layout, "admin-panel");
    const nlohmann::json gateway = configOf(layout, "gateway");

    const std::string corePin = pinOf(core.at("state").get<std::string>());
    const std::string nodePin = pinOf(node.at("state").get<std::string>());
    const std::string facadePin = pinOf(facade.at("state").get<std::string>());
    const std::string panelPin = pinOf(panel.at("state").get<std::string>());
    const std::string gatewayPin = pinOf(gateway.at("state").get<std::string>());
    const std::string nodeFingerprint
        = bazarish::server::loadOrCreateIdentity(node.at("state").get<std::string>())
              .fingerprint();
    const std::string panelFingerprint
        = bazarish::server::loadOrCreateIdentity(panel.at("state").get<std::string>())
              .fingerprint();

    CHECK(core.at("operators") == nlohmann::json::array({nodeFingerprint, panelFingerprint}));
    CHECK(core.at("opsClients") == nlohmann::json::array({nodePin, panelPin}));
    CHECK(core.at("serviceNode").at("url") == reached(node.at("listen")));
    CHECK(core.at("serviceNode").at("pin") == nodePin);

    CHECK(reachedAt(node.at("messaging"), core.at("opsListen"), corePin));
    CHECK(node.at("serverCard") == (fs::path(core.at("state")) / "server-card.der").string());
    CHECK(node.at("portal").at("assets") == "/assets/portal");
    CHECK(!node.at("portal").contains("listen"));

    CHECK(reachedAt(facade.at("messaging"), core.at("listen"), corePin));
    CHECK(reachedAt(facade.at("serviceNode"), node.at("listen"), nodePin));

    for (const nlohmann::json* operated : {&node, &facade, &gateway}) {
        CHECK(operated->at("operators") == nlohmann::json::array({panelFingerprint}));
        CHECK(operated->at("opsClients") == nlohmann::json::array({panelPin}));
    }
    CHECK(gateway.at("token") == kGatewayToken);

    CHECK(panel.at("assets") == "/assets/panel");
    CHECK(!panel.contains("admin"));
    CHECK(panel.at("fleets").size() == 1);
    CHECK(panel.at("fleets")[0].at("name") == "box");
    const nlohmann::json& services = panel.at("fleets")[0].at("services");
    CHECK(services.size() == 4);
    const auto entry = [&services](const std::string& kind) {
        for (const nlohmann::json& service : services) {
            if (service.at("kind") == kind) {
                return service;
            }
        }
        throw std::runtime_error("the fleet has no " + kind);
    };
    CHECK(entry("server-core").at("url") == reached(core.at("opsListen")));
    CHECK(entry("server-core").at("pin") == corePin);
    CHECK(entry("service-node").at("url") == reached(node.at("opsListen")));
    CHECK(entry("service-node").at("pin") == nodePin);
    CHECK(entry("facade").at("url") == reached(facade.at("opsListen")));
    CHECK(entry("facade").at("pin") == facadePin);
    CHECK(entry("gateway").at("url") == reached(gateway.at("opsListen")));
    CHECK(entry("gateway").at("pin") == gatewayPin);

    const std::string written = bazarish::readFileText(layout.configDir / "admin-panel.json");
    CHECK(!bazarish::setup::setUpFleet(layout));
    CHECK(bazarish::readFileText(layout.configDir / "admin-panel.json") == written);
    CHECK(configOf(layout, "server-core") == core);

    const bazarish::setup::Layout administered = layoutUnder(root / "administered");
    writeGateway(administered,
        {{"opsListen", {{"host", "0.0.0.0"}, {"port", kOtherOpsPort}}},
            {"operators", {kOtherPanelFingerprint}}, {"opsClients", {kOtherPanelPin}}});
    CHECK(bazarish::setup::setUpFleet(administered));
    {
        const nlohmann::json kept = configOf(administered, "gateway");
        const std::string addedPin
            = pinOf(configOf(administered, "admin-panel").at("state").get<std::string>());
        CHECK(kept.at("opsListen").at("host") == "0.0.0.0");
        CHECK(kept.at("opsListen").at("port") == kOtherOpsPort);
        CHECK(kept.at("operators").size() == 2);
        CHECK(kept.at("operators")[0] == kOtherPanelFingerprint);
        CHECK(kept.at("opsClients") == nlohmann::json::array({kOtherPanelPin, addedPin}));
        const nlohmann::json listed
            = configOf(administered, "admin-panel").at("fleets")[0].at("services");
        CHECK(listed[3].at("url") == "https://127.0.0.1:" + std::to_string(kOtherOpsPort));
    }

    const bazarish::setup::Layout partial = layoutUnder(root / "partial");
    writeGateway(partial);
    const std::string gatewayBefore = bazarish::readFileText(partial.configDir / "gateway.json");
    bazarish::writePrivateFile(partial.configDir / "facade.json", "{}\n");
    CHECK(!bazarish::setup::setUpFleet(partial));
    CHECK(bazarish::readFileText(partial.configDir / "gateway.json") == gatewayBefore);
    CHECK(!fs::exists(partial.configDir / "server-core.json"));

    fs::remove_all(root);
    std::printf("TestFleetSetup OK\n");
    return 0;
}
