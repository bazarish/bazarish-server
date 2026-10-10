// Bazarish project (c) 2026
#include "HttpApi.hpp"
#include "PanelSettings.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Portal.hpp>
#include <bazarish/Tls.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

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

constexpr const char* kOldUrl = "http://aaaa.b32.i2p/1111";
constexpr const char* kNewUrl = "http://cccc.b32.i2p/3333";
constexpr const char* kChallengeField = "name=\"challenge\" value=\"";

std::string formEncoded(const std::string& text)
{
    std::string out;
    for (const unsigned char c : text) {
        if (std::isalnum(c) != 0 || c == '-' || c == '_' || c == '.') {
            out.push_back(static_cast<char>(c));
        } else {
            static const char* const kHex = "0123456789ABCDEF";
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0xF]);
        }
    }
    return out;
}

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

struct Panel {
    int port = 0;
    std::string cookie;

    http::ClientResponse ask(const std::string& method, const std::string& target,
        const nlohmann::json& body = nullptr) const
    {
        http::ClientRequest request;
        request.method = method;
        request.target = target;
        request.headers = {{"Cookie", "adminsession=" + cookie}};
        if (!body.is_null()) {
            request.body = body.dump();
            request.contentType = "application/json";
        }
        return http::request("127.0.0.1", port, request, {});
    }
};

std::string signIn(const int port, const Identity& admin)
{
    http::ClientRequest page;
    page.method = "GET";
    page.target = "/login";
    const http::ClientResponse shown = http::request("127.0.0.1", port, page, {});
    const std::size_t start = shown.body.find(kChallengeField);
    CHECK(start != std::string::npos);
    const std::size_t from = start + std::char_traits<char>::length(kChallengeField);
    const std::string challenge = shown.body.substr(from, shown.body.find('"', from) - from);

    http::ClientRequest login;
    login.method = "POST";
    login.target = "/login";
    login.contentType = "application/x-www-form-urlencoded";
    login.body = "challenge=" + formEncoded(challenge) + "&blob="
        + formEncoded(service::signLoginBlob(
            admin, static_cast<std::int64_t>(std::time(nullptr)), challenge));
    const http::ClientResponse answered = http::request("127.0.0.1", port, login, {});
    CHECK(answered.status == 303);
    for (const auto& [name, value] : answered.headers) {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == "set-cookie") {
            const std::size_t equals = value.find('=');
            return value.substr(equals + 1, value.find(';') - equals - 1);
        }
    }
    CHECK(false);
    return {};
}

}  // namespace

int main()
{
    bazarish::log::setLevel(bazarish::log::Level::eError);
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-panel-fleet-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const tls::Credential services = tls::selfSigned(root / "services");
    const tls::Credential panelKeys = tls::selfSigned(root / "panel");

    std::mutex guard;
    nlohmann::json described = nlohmann::json::array();
    const auto node = serving(services);
    node->get("/v1/account/settings", [&](const http::Request&) {
        const std::lock_guard<std::mutex> lock(guard);
        return json({{"facades", described}});
    });
    node->put("/v1/account/settings", [&](const http::Request& request) {
        const std::lock_guard<std::mutex> lock(guard);
        described = nlohmann::json::parse(request.body).at("facades");
        return json({{"ok", true}});
    });
    const int nodePort = node->start();

    std::string facadeUrl = kOldUrl;
    const auto facade = serving(services);
    facade->get("/settings", [&](const http::Request&) {
        const std::lock_guard<std::mutex> lock(guard);
        return json({{"url", facadeUrl}});
    });
    facade->post("/new-address", [&](const http::Request&) {
        const std::lock_guard<std::mutex> lock(guard);
        const std::string previous = facadeUrl;
        facadeUrl = kNewUrl;
        return json({{"url", kNewUrl}, {"previousUrl", previous}, {"restarting", true}});
    });
    const int facadePort = facade->start();

    nlohmann::json routes = nlohmann::json::array(
        {{{"dest", "aaaa.b32.i2p"}, {"host", "127.0.0.1"}, {"port", 8418}, {"pin", "ab"}}});
    std::atomic<int> gatewayRestarts{0};
    const auto gateway = serving(services);
    gateway->get("/settings", [&](const http::Request&) {
        const std::lock_guard<std::mutex> lock(guard);
        return json({{"direct", routes}, {"streamPool", 4}});
    });
    gateway->put("/settings", [&](const http::Request& request) {
        const std::lock_guard<std::mutex> lock(guard);
        const nlohmann::json body = nlohmann::json::parse(request.body);
        if (body.contains("direct")) {
            routes = body.at("direct");
        }
        return json({{"direct", routes}});
    });
    gateway->post("/restart", [&](const http::Request&) {
        ++gatewayRestarts;
        return json({{"restarting", true}});
    });
    const int gatewayPort = gateway->start();

    const auto at = [](const int port) { return "https://127.0.0.1:" + std::to_string(port); };
    const Identity admin = Identity::generate();
    const std::filesystem::path configPath = root / "admin-panel.json";
    { std::ofstream(configPath) << "{}\n"; }
    Config initial;
    initial.admins = {admin.fingerprint()};
    initial.consumer
        = service::LoginConsumer{"Bazarish admin panel", {"http://127.0.0.1"}, "Administrator"};
    initial.fleets = {Fleet{"home",
        {ServiceEntry{"node", kServiceNodeKind, at(nodePort), services.pin},
            ServiceEntry{"front", kFacadeKind, at(facadePort), services.pin},
            ServiceEntry{"edge", kGatewayKind, at(gatewayPort), services.pin}}}};
    const auto settings = std::make_shared<PanelSettings>(configPath, initial);

    HttpApiOptions options;
    options.version = "test";
    options.assetsDirectory = std::filesystem::path(BAZARISH_PANEL_WEB_DIR);
    const Identity panelIdentity = Identity::generate();
    HttpApi api(settings, panelIdentity, panelKeys, options);
    Panel panel;
    panel.port = api.bind("127.0.0.1", 0);
    CHECK(panel.port > 0);
    std::thread serverThread([&api]() { api.wait(); });
    panel.cookie = signIn(panel.port, admin);

    {
        const http::ClientResponse listed = panel.ask("GET", "/api/facades?fleet=home");
        CHECK(listed.status == 200);
        const nlohmann::json body = nlohmann::json::parse(listed.body);
        CHECK(body.at("facades").size() == 1);
        CHECK(body.at("facades")[0].at("address") == kOldUrl);
        CHECK(body.at("facades")[0].at("inDescriptor") == false);
    }

    {
        nlohmann::json twice = nlohmann::json::parse(panel.ask("GET", "/api/panel").body);
        nlohmann::json& list = twice.at("fleets")[0].at("services");
        list.push_back(list[1]);
        const http::ClientResponse refused
            = panel.ask("PUT", "/api/panel", {{"fleets", twice.at("fleets")}});
        CHECK(refused.status == 400);
        CHECK(settings->get().fleets[0].services.size() == 3);
        CHECK(described.empty());

        list.erase(list.end() - 1);
        const http::ClientResponse saved
            = panel.ask("PUT", "/api/panel", {{"fleets", twice.at("fleets")}});
        CHECK(saved.status == 200);
        CHECK(nlohmann::json::parse(saved.body).at("descriptorErrors").empty());
        CHECK(described == nlohmann::json::array({kOldUrl}));
        const nlohmann::json listed
            = nlohmann::json::parse(panel.ask("GET", "/api/facades?fleet=home").body);
        CHECK(listed.at("facades")[0].at("inDescriptor") == true);
    }

    CHECK(panel.ask("GET", "/api/service-settings?fleet=home&kind=facade").status == 400);
    CHECK(panel.ask("GET", "/api/service-settings?fleet=home&service=nobody").status == 503);
    {
        const http::ClientResponse shown
            = panel.ask("GET", "/api/service-settings?fleet=home&service=edge");
        CHECK(shown.status == 200);
        CHECK(nlohmann::json::parse(shown.body).at("streamPool") == 4);
    }

    {
        const http::ClientResponse renewed
            = panel.ask("POST", "/api/facade/new-address?fleet=home&service=front");
        CHECK(renewed.status == 200);
        const nlohmann::json body = nlohmann::json::parse(renewed.body);
        CHECK(body.at("url") == kNewUrl);
        CHECK(body.at("previousUrl") == kOldUrl);
        CHECK(body.at("descriptorError") == "");
        CHECK(body.at("gateways").size() == 1);
        CHECK(body.at("gateways")[0].at("changed") == true);
        CHECK(described == nlohmann::json::array({kNewUrl}));
        CHECK(routes[0].at("dest") == "cccc.b32.i2p");
        CHECK(panel.ask("POST", "/api/facade/new-address?fleet=home&service=edge").status
            == 404);
    }

    CHECK(panel.ask("POST", "/api/restart?fleet=home&service=edge").status == 200);
    CHECK(gatewayRestarts == 1);

    Panel stranger = panel;
    stranger.cookie = "not-a-session";
    CHECK(stranger.ask("GET", "/api/facades?fleet=home").status == 401);

    api.stop();
    serverThread.join();
    node->stop();
    facade->stop();
    gateway->stop();
    std::filesystem::remove_all(root);
    std::printf("TestPanelFleet OK\n");
    return 0;
}
