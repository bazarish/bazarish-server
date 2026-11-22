// Bazarish project (c) 2026
#include "Setup.hpp"
#include "TestUtil.hpp"

#include <StateIdentity.hpp>

#include <bazarish/ConfigFile.hpp>
#include <bazarish/Links.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Tls.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;
using bazarish::setup::Kind;
using bazarish::setup::Layout;

constexpr const char* kCoreAddress = "10.0.0.1";
constexpr const char* kServiceAddress = "10.0.0.2";
constexpr const char* kFacadeAddress = "10.0.0.3";
constexpr const char* kGatewayAddress = "10.0.0.4";
constexpr const char* kOtherGatewayAddress = "10.0.0.5";
constexpr const char* kGatewayFront = "https://gw.example";

Layout layoutUnder(const fs::path& root)
{
    return {root / "etc", root / "state", "/assets/panel", "/assets/portal", ""};
}

nlohmann::json configOf(const Layout& layout, const Kind kind)
{
    return bazarish::ConfigFile(layout.configDir / (bazarish::setup::kindName(kind) + ".json"))
        .read();
}

std::string stateOf(const Layout& layout, const Kind kind)
{
    return configOf(layout, kind).at("state").get<std::string>();
}

std::string pinOf(const Layout& layout, const Kind kind)
{
    return bazarish::tls::selfSigned(stateOf(layout, kind)).pin;
}

std::string fingerprintOf(const Layout& layout, const Kind kind)
{
    return bazarish::server::loadOrCreateIdentity(stateOf(layout, kind)).fingerprint();
}

bool holds(const nlohmann::json& list, const std::string& entry)
{
    return std::find(list.begin(), list.end(), entry) != list.end();
}

std::string url(const std::string& host, const int port)
{
    return "https://" + host + ":" + std::to_string(port);
}

std::string socketUrl(const nlohmann::json& config, const std::string& key)
{
    return url(config.at(key).at("host").get<std::string>(), config.at(key).at("port").get<int>());
}

bool reaches(const nlohmann::json& link, const nlohmann::json& socket, const std::string& pin)
{
    return link.at("host") == socket.at("host") && link.at("port") == socket.at("port")
        && link.at("pin") == pin;
}

nlohmann::json entryOf(const nlohmann::json& panel, const std::string& name)
{
    for (const nlohmann::json& service : panel.at("services")) {
        if (service.at("name") == name) {
            return service;
        }
    }
    return nullptr;
}

bazarish::setup::Peer peerOf(const std::string& token)
{
    return bazarish::setup::peerFromToken(token);
}

void checkAllLinked(const Layout& layout)
{
    const nlohmann::json core = configOf(layout, Kind::eServerCore);
    const nlohmann::json service = configOf(layout, Kind::eServerService);
    const nlohmann::json facade = configOf(layout, Kind::eFacade);
    const nlohmann::json panel = configOf(layout, Kind::eAdminPanel);
    const nlohmann::json gateway = configOf(layout, Kind::eGateway);
    const std::string corePin = pinOf(layout, Kind::eServerCore);
    const std::string servicePin = pinOf(layout, Kind::eServerService);
    const std::string panelPin = pinOf(layout, Kind::eAdminPanel);
    const std::string panelFingerprint = fingerprintOf(layout, Kind::eAdminPanel);

    CHECK(core.at("operators").size() == 2);
    CHECK(holds(core.at("operators"), fingerprintOf(layout, Kind::eServerService)));
    CHECK(holds(core.at("operators"), panelFingerprint));
    CHECK(core.at("opsClients").size() == 2);
    CHECK(holds(core.at("opsClients"), servicePin));
    CHECK(holds(core.at("opsClients"), panelPin));
    CHECK(core.at("serverService").at("url") == socketUrl(service, "listen"));
    CHECK(core.at("serverService").at("pin") == servicePin);

    CHECK(reaches(service.at("messaging"), core.at("opsListen"), corePin));
    CHECK(service.at("portal").at("assets") == "/assets/portal");
    CHECK(reaches(facade.at("messaging"), core.at("listen"), corePin));
    CHECK(reaches(facade.at("serverService"), service.at("listen"), servicePin));

    for (const nlohmann::json* operated : {&service, &facade, &gateway}) {
        CHECK(operated->at("operators") == nlohmann::json::array({panelFingerprint}));
        CHECK(operated->at("opsClients") == nlohmann::json::array({panelPin}));
    }
    CHECK(gateway.at("basePath").get<std::string>().size() > 1);

    CHECK(panel.at("assets") == "/assets/panel");
    CHECK(!panel.contains("admin"));
    CHECK(panel.at("services").size() == 4);
    for (const Kind kind :
        {Kind::eServerCore, Kind::eServerService, Kind::eFacade, Kind::eGateway}) {
        const nlohmann::json entry = entryOf(panel, bazarish::setup::kindName(kind));
        CHECK(entry.is_object());
        CHECK(entry.at("kind") == bazarish::setup::kindName(kind));
        CHECK(entry.at("url") == socketUrl(configOf(layout, kind), "opsListen"));
        CHECK(entry.at("pin") == pinOf(layout, kind));
    }
    for (const Kind kind : bazarish::setup::kKinds) {
        CHECK(bazarish::setup::missing(layout, kind).empty());
    }
}

void checkOneHost(const fs::path& root, const std::vector<Kind>& order)
{
    const Layout layout = layoutUnder(root);
    for (const Kind kind : order) {
        CHECK(bazarish::setup::init(layout, kind).contains(kind));
    }
    checkAllLinked(layout);

    std::vector<std::string> written;
    for (const Kind kind : bazarish::setup::kKinds) {
        written.push_back(configOf(layout, kind).dump());
        CHECK(bazarish::setup::init(layout, kind).empty());
    }
    for (std::size_t at = 0; at < written.size(); ++at) {
        CHECK(configOf(layout, bazarish::setup::kKinds[at]).dump() == written.at(at));
    }
}

void checkListenRelinksHere(const fs::path& root)
{
    const Layout layout = layoutUnder(root);
    for (const Kind kind :
        {Kind::eServerCore, Kind::eServerService, Kind::eFacade, Kind::eAdminPanel}) {
        CHECK(!bazarish::setup::init(layout, kind).empty());
    }
    CHECK_THROWS(bazarish::setup::token(layout, Kind::eServerCore));
    CHECK_THROWS(bazarish::setup::listenOn(layout, Kind::eServerCore, "0.0.0.0"));
    CHECK_THROWS(bazarish::setup::listenOn(layout, Kind::eServerCore, "core.example"));
    CHECK_THROWS(bazarish::setup::listenOn(layout, Kind::eAdminPanel, kCoreAddress));

    const bazarish::setup::Changed changed
        = bazarish::setup::listenOn(layout, Kind::eServerCore, kCoreAddress);
    CHECK(changed
        == bazarish::setup::Changed({Kind::eServerCore, Kind::eServerService, Kind::eFacade,
            Kind::eAdminPanel}));
    const nlohmann::json core = configOf(layout, Kind::eServerCore);
    for (const char* key : {"listen", "opsListen", "gatewayListen"}) {
        CHECK(core.at(key).at("host") == kCoreAddress);
    }
    CHECK(configOf(layout, Kind::eServerService).at("messaging").at("host") == kCoreAddress);
    CHECK(configOf(layout, Kind::eFacade).at("messaging").at("host") == kCoreAddress);
    CHECK(entryOf(configOf(layout, Kind::eAdminPanel), "server-core").at("url")
        == socketUrl(core, "opsListen"));
    CHECK(configOf(layout, Kind::eFacade).at("serverService").at("host") == "127.0.0.1");
    CHECK(bazarish::setup::listenOn(layout, Kind::eServerCore, kCoreAddress).empty());
}

void checkHosts(const fs::path& root)
{
    const Layout coreHost = layoutUnder(root / "core");
    const Layout serviceHost = layoutUnder(root / "service");
    const Layout facadeHost = layoutUnder(root / "facade");
    const Layout gatewayHost = layoutUnder(root / "gateway");
    const Layout otherGatewayHost = layoutUnder(root / "other-gateway");

    CHECK(!bazarish::setup::init(coreHost, Kind::eServerCore).empty());
    CHECK(!bazarish::setup::init(coreHost, Kind::eAdminPanel).empty());
    CHECK(bazarish::setup::missing(coreHost, Kind::eServerCore)
        == std::vector<std::string>{"server-service"});
    CHECK(!bazarish::setup::listenOn(coreHost, Kind::eServerCore, kCoreAddress).empty());
    const std::string coreToken = bazarish::setup::token(coreHost, Kind::eServerCore);
    const std::string panelToken = bazarish::setup::token(coreHost, Kind::eAdminPanel);
    CHECK(coreToken.starts_with("server-core:"));
    CHECK(peerOf(coreToken).pin == pinOf(coreHost, Kind::eServerCore));
    CHECK_THROWS(bazarish::setup::join(coreHost, peerOf(coreToken)));
    CHECK_THROWS(peerOf("server-core"));
    CHECK_THROWS(peerOf("router:e30"));
    CHECK_THROWS(peerOf("server-core:e30"));
    CHECK_THROWS(bazarish::setup::join(layoutUnder(root / "empty"), peerOf(coreToken)));

    CHECK(!bazarish::setup::init(serviceHost, Kind::eServerService).empty());
    CHECK(bazarish::setup::missing(serviceHost, Kind::eServerService)
        == std::vector<std::string>{"server-core"});
    CHECK(bazarish::setup::join(serviceHost, peerOf(coreToken))
        == bazarish::setup::Changed{Kind::eServerService});
    CHECK(bazarish::setup::missing(serviceHost, Kind::eServerService).empty());
    const nlohmann::json service = configOf(serviceHost, Kind::eServerService);
    CHECK(service.at("messaging").at("host") == kCoreAddress);
    CHECK(service.at("messaging").at("port")
        == configOf(coreHost, Kind::eServerCore).at("opsListen").at("port"));
    CHECK(service.at("messaging").at("pin") == pinOf(coreHost, Kind::eServerCore));
    CHECK(!bazarish::setup::join(serviceHost, peerOf(panelToken)).empty());
    CHECK(configOf(serviceHost, Kind::eServerService).at("operators")
        == nlohmann::json::array({fingerprintOf(coreHost, Kind::eAdminPanel)}));
    CHECK(!bazarish::setup::listenOn(serviceHost, Kind::eServerService, kServiceAddress).empty());
    const std::string serviceToken = bazarish::setup::token(serviceHost, Kind::eServerService);

    CHECK(!bazarish::setup::join(coreHost, peerOf(serviceToken)).empty());
    const nlohmann::json core = configOf(coreHost, Kind::eServerCore);
    CHECK(core.at("serverService").at("url")
        == socketUrl(configOf(serviceHost, Kind::eServerService), "listen"));
    CHECK(holds(core.at("operators"), fingerprintOf(serviceHost, Kind::eServerService)));
    CHECK(holds(core.at("opsClients"), pinOf(serviceHost, Kind::eServerService)));
    CHECK(bazarish::setup::missing(coreHost, Kind::eServerCore).empty());
    CHECK(entryOf(configOf(coreHost, Kind::eAdminPanel), "server-service").at("url")
        == socketUrl(configOf(serviceHost, Kind::eServerService), "opsListen"));

    CHECK(!bazarish::setup::init(facadeHost, Kind::eFacade).empty());
    CHECK(!bazarish::setup::join(facadeHost, peerOf(coreToken)).empty());
    CHECK(bazarish::setup::missing(facadeHost, Kind::eFacade)
        == std::vector<std::string>{"server-service"});
    CHECK(!bazarish::setup::join(facadeHost, peerOf(serviceToken)).empty());
    CHECK(!bazarish::setup::join(facadeHost, peerOf(panelToken)).empty());
    CHECK(bazarish::setup::missing(facadeHost, Kind::eFacade).empty());
    const nlohmann::json facade = configOf(facadeHost, Kind::eFacade);
    CHECK(facade.at("messaging").at("host") == kCoreAddress);
    CHECK(facade.at("serverService").at("host") == kServiceAddress);
    CHECK(facade.at("operators")
        == nlohmann::json::array({fingerprintOf(coreHost, Kind::eAdminPanel)}));
    CHECK(!bazarish::setup::listenOn(facadeHost, Kind::eFacade, kFacadeAddress).empty());
    CHECK(!bazarish::setup::join(coreHost,
        peerOf(bazarish::setup::token(facadeHost, Kind::eFacade))).empty());
    CHECK(entryOf(configOf(coreHost, Kind::eAdminPanel), std::string("facade-") + kFacadeAddress)
              .at("pin")
        == pinOf(facadeHost, Kind::eFacade));

    for (const auto& [host, address] : {std::pair{gatewayHost, kGatewayAddress},
             std::pair{otherGatewayHost, kOtherGatewayAddress}}) {
        CHECK(!bazarish::setup::init(host, Kind::eGateway).empty());
        CHECK(!bazarish::setup::join(host, peerOf(panelToken)).empty());
        CHECK(!bazarish::setup::listenOn(host, Kind::eGateway, address).empty());
        CHECK(!bazarish::setup::join(coreHost,
            peerOf(bazarish::setup::token(host, Kind::eGateway))).empty());
        CHECK(entryOf(configOf(coreHost, Kind::eAdminPanel), std::string("gateway-") + address)
                  .is_object());
    }
    CHECK(bazarish::setup::join(coreHost,
        peerOf(bazarish::setup::token(gatewayHost, Kind::eGateway))).empty());
    CHECK(configOf(coreHost, Kind::eAdminPanel).at("services").size() == 5);

    CHECK_THROWS(bazarish::setup::gatewayLink(gatewayHost));
    CHECK_THROWS(bazarish::setup::setGatewayAddress(gatewayHost, "gw.example/path"));
    CHECK(bazarish::setup::setGatewayAddress(gatewayHost, kGatewayFront)
        == bazarish::setup::Changed{Kind::eGateway});
    const nlohmann::json gateway = configOf(gatewayHost, Kind::eGateway);
    CHECK(bazarish::setup::gatewayLink(gatewayHost)
        == bazarish::gatewayLink(kGatewayFront + gateway.at("basePath").get<std::string>(),
            fingerprintOf(gatewayHost, Kind::eGateway)));
    CHECK(bazarish::setup::status(gatewayHost).at(0).at("link")
        == bazarish::setup::gatewayLink(gatewayHost));
}

}  // namespace

int main()
try {
    const testutil::ScratchDir scratch("setup-test");
    const fs::path& root = scratch.path();

    checkOneHost(root / "in-order",
        {Kind::eGateway, Kind::eServerCore, Kind::eServerService, Kind::eFacade,
            Kind::eAdminPanel});
    checkOneHost(root / "panel-first",
        {Kind::eAdminPanel, Kind::eFacade, Kind::eServerService, Kind::eGateway,
            Kind::eServerCore});
    checkListenRelinksHere(root / "relinked");
    checkHosts(root / "hosts");

    std::printf("TestSetup OK\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
