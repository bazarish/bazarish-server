// Bazarish project (c) 2026
#include "FleetSync.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Tls.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::admin;

namespace {

namespace http = bazarish::http;

constexpr const char* kFacadeA = "aaaa.b32.i2p";
constexpr const char* kFacadeB = "bbbb.b32.i2p";
constexpr const char* kFacadeBRenewed = "cccc.b32.i2p";

std::unique_ptr<http::Server> serving(const tls::Credential& credential)
{
    http::Server::Options options;
    options.certificate = credential.certificate.string();
    options.key = credential.key.string();
    options.port = 0;
    options.threads = 1;
    return std::make_unique<http::Server>(options);
}

http::Response json(const nlohmann::json& body)
{
    return http::Response{200, "application/json", {}, body.dump()};
}

ServiceEntry entry(const std::string& name, const std::string& kind, const int port,
    const std::string& pin)
{
    return ServiceEntry{name, kind, "https://127.0.0.1:" + std::to_string(port), pin};
}

}  // namespace

int main()
{
    CHECK(hostOf("http://abc.b32.i2p/x/y") == "abc.b32.i2p");
    CHECK(hostOf("http://h:8080/p") == "h");
    CHECK(hostOf("abc.b32.i2p") == "abc.b32.i2p");

    const Identity panel = Identity::generate();
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-panel-sync-test";
    std::filesystem::remove_all(root);
    const tls::Credential services = tls::selfSigned(root / "services");
    const tls::Credential panelKeys = tls::selfSigned(root / "panel");

    std::mutex guard;
    std::vector<nlohmann::json> nodeWrites;
    const auto node = serving(services);
    node->put("/v1/account/settings", [&](const http::Request& request) {
        const std::lock_guard<std::mutex> lock(guard);
        nodeWrites.push_back(nlohmann::json::parse(request.body));
        return json({{"ok", true}});
    });
    const int nodePort = node->start();

    std::atomic<int> askedA{0};
    const auto facadeA = serving(services);
    facadeA->get("/settings", [&](const http::Request&) {
        ++askedA;
        return json({{"address", kFacadeA}, {"logLevel", "info"}});
    });
    const int facadeAPort = facadeA->start();

    std::atomic<int> askedB{0};
    const auto facadeB = serving(services);
    facadeB->get("/settings", [&](const http::Request&) {
        ++askedB;
        return json({{"address", kFacadeB}});
    });
    const int facadeBPort = facadeB->start();

    const nlohmann::json routes = nlohmann::json::array({
        {{"dest", "bbbb.b32.i2p"}, {"host", "10.0.0.2"}, {"port", 8418}, {"pin", "ab"}},
        {{"dest", "other.b32.i2p"}, {"host", "10.0.0.3"}, {"port", 8418}, {"pin", "cd"}},
    });
    std::vector<nlohmann::json> gatewayWrites;
    const auto gateway = serving(services);
    gateway->get("/settings", [&](const http::Request&) { return json({{"direct", routes}}); });
    gateway->put("/settings", [&](const http::Request& request) {
        const std::lock_guard<std::mutex> lock(guard);
        gatewayWrites.push_back(nlohmann::json::parse(request.body));
        return json({{"ok", true}});
    });
    const int gatewayPort = gateway->start();

    std::vector<nlohmann::json> idleWrites;
    const auto idle = serving(services);
    idle->get("/settings", [&](const http::Request&) {
        return json({{"direct", nlohmann::json::array()}});
    });
    idle->put("/settings", [&](const http::Request& request) {
        const std::lock_guard<std::mutex> lock(guard);
        idleWrites.push_back(nlohmann::json::parse(request.body));
        return json({{"ok", true}});
    });
    const int idlePort = idle->start();

    const std::string pin = services.pin;
    Fleet home{"home",
        {entry("node", kServiceNodeKind, nodePort, pin),
            entry("second", kFacadeKind, facadeBPort, pin),
            entry("first", kFacadeKind, facadeAPort, pin),
            entry("edge", kGatewayKind, gatewayPort, pin)}};

    CHECK(publishFacades(home, panel, panelKeys).empty());
    CHECK(nodeWrites.size() == 1);
    CHECK(nodeWrites.back() == nlohmann::json({{"facades", {kFacadeB, kFacadeA}}}));

    const std::vector<FacadeReport> reports = facadeReports(home, panel, panelKeys);
    CHECK(reports.size() == 2);
    CHECK(reports[0].name == "second");
    CHECK(reports[0].address == kFacadeB);
    CHECK(reports[1].address == kFacadeA);

    const int askedBBefore = askedB.load();
    CHECK(publishFacades(home, panel, panelKeys, {{"second", kFacadeBRenewed}}).empty());
    CHECK(askedB.load() == askedBBefore);
    CHECK(nodeWrites.back() == nlohmann::json({{"facades", {kFacadeBRenewed, kFacadeA}}}));

    Fleet broken = home;
    broken.services[1].url = "https://127.0.0.1:" + std::to_string(idlePort + 1);
    broken.services[1].pin = panelKeys.pin;
    const std::size_t writesBefore = nodeWrites.size();
    CHECK(!publishFacades(broken, panel, panelKeys).empty());
    CHECK(nodeWrites.size() == writesBefore);

    const Fleet facadeless{"bare", {entry("node", kServiceNodeKind, nodePort, pin)}};
    CHECK(!publishFacades(facadeless, panel, panelKeys).empty());
    CHECK(nodeWrites.size() == writesBefore);

    const Fleet nodeless{"edge-only", {entry("first", kFacadeKind, facadeAPort, pin)}};
    const int askedABefore = askedA.load();
    CHECK(publishFacades(nodeless, panel, panelKeys).empty());
    CHECK(askedA.load() == askedABefore);

    const Fleet away{"away", {entry("quiet", kGatewayKind, idlePort, pin)}};
    const std::vector<GatewayRepoint> repointed
        = repointGateways({home, away}, kFacadeB, kFacadeBRenewed, panel, panelKeys);
    CHECK(repointed.size() == 2);
    CHECK(repointed[0].name == "edge");
    CHECK(repointed[0].changed);
    CHECK(repointed[0].error.empty());
    CHECK(repointed[1].name == "quiet");
    CHECK(!repointed[1].changed);
    CHECK(repointed[1].error.empty());
    CHECK(idleWrites.empty());
    CHECK(gatewayWrites.size() == 1);
    const nlohmann::json& written = gatewayWrites.front().at("direct");
    CHECK(written.size() == 2);
    CHECK(written[0].at("dest") == "cccc.b32.i2p");
    CHECK(written[0].at("host") == "10.0.0.2");
    CHECK(written[1].at("dest") == "other.b32.i2p");

    nlohmann::json coreSettings = {{"gatewayListen", {{"host", "0.0.0.0"}, {"port", 8424}}},
        {"gateways", nlohmann::json::array()}};
    int coreWrites = 0;
    const auto core = serving(services);
    core->get("/v1/messaging/settings", [&](const http::Request&) {
        const std::lock_guard<std::mutex> lock(guard);
        return json(coreSettings);
    });
    core->put("/v1/messaging/settings", [&](const http::Request& request) {
        const std::lock_guard<std::mutex> lock(guard);
        ++coreWrites;
        coreSettings.update(nlohmann::json::parse(request.body));
        return json(coreSettings);
    });
    const int corePort = core->start();

    const auto directFacade = serving(services);
    directFacade->get("/settings", [&](const http::Request&) {
        return json(
            {{"address", kFacadeA}, {"directListen", {{"host", "10.0.0.7"}, {"port", 8418}}}});
    });
    const int directFacadePort = directFacade->start();

    nlohmann::json linkedSettings = {{"server", nullptr}, {"direct", nlohmann::json::array()}};
    int linkedWrites = 0;
    const auto linked = serving(services);
    linked->get("/settings", [&](const http::Request&) {
        const std::lock_guard<std::mutex> lock(guard);
        return json(linkedSettings);
    });
    linked->put("/settings", [&](const http::Request& request) {
        const std::lock_guard<std::mutex> lock(guard);
        ++linkedWrites;
        linkedSettings.update(nlohmann::json::parse(request.body));
        return json(linkedSettings);
    });
    const int linkedPort = linked->start();

    ServiceEntry linkedEntry = entry("home-gateway", kGatewayKind, linkedPort, pin);
    const Fleet family{"family",
        {entry("server-core", kServerCoreKind, corePort, pin),
            entry("with-direct", kFacadeKind, directFacadePort, pin),
            entry("without-direct", kFacadeKind, facadeBPort, pin), linkedEntry}};
    const GatewayLinking first = linkGateways(family, panel, panelKeys);
    CHECK(first.error.empty());
    CHECK(first.gateways.size() == 1);
    CHECK(first.gateways[0].changed);
    CHECK(coreWrites == 1);
    CHECK(coreSettings.at("gateways") == nlohmann::json::array({pin}));
    CHECK(linkedWrites == 1);
    CHECK(linkedSettings.at("server")
        == nlohmann::json({{"host", "127.0.0.1"}, {"port", 8424}, {"pin", pin}}));
    CHECK(linkedSettings.at("direct")
        == nlohmann::json::array({{{"dest", "aaaa.b32.i2p"}, {"host", "10.0.0.7"},
            {"port", 8418}, {"pin", pin}}}));

    const GatewayLinking again = linkGateways(family, panel, panelKeys);
    CHECK(again.error.empty());
    CHECK(!again.gateways[0].changed);
    CHECK(coreWrites == 1);
    CHECK(linkedWrites == 1);

    {
        const std::lock_guard<std::mutex> lock(guard);
        coreSettings["gatewayListen"] = nullptr;
    }
    CHECK(linkGateways(family, panel, panelKeys).gateways[0].changed);
    CHECK(linkedSettings.at("server").is_null());
    CHECK(linkedSettings.at("direct").size() == 1);

    node->stop();
    facadeA->stop();
    facadeB->stop();
    gateway->stop();
    idle->stop();
    core->stop();
    directFacade->stop();
    linked->stop();
    std::filesystem::remove_all(root);
    std::printf("TestFleetSync: all checks passed\n");
    return 0;
}
