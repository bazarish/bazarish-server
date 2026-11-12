// Bazarish project (c) 2026
#include "HttpApi.hpp"
#include "PanelSettings.hpp"
#include "TestUtil.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Percent.hpp>
#include <bazarish/Portal.hpp>
#include <bazarish/Tls.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::admin;

namespace {

namespace http = bazarish::http;

constexpr const char* kOldAddress = "aaaa.b32.i2p";
constexpr const char* kNewAddress = "cccc.b32.i2p";
constexpr const char* kChallengeField = "name=\"challenge\" value=\"";

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

std::string signIn(const int port, const Identity& admin, const std::string& path = "/login")
{
    http::ClientRequest page;
    page.method = "GET";
    page.target = path;
    const http::ClientResponse shown = http::request("127.0.0.1", port, page, {});
    const std::size_t start = shown.body.find(kChallengeField);
    CHECK(start != std::string::npos);
    const std::size_t from = start + std::char_traits<char>::length(kChallengeField);
    const std::string challenge = shown.body.substr(from, shown.body.find('"', from) - from);

    http::ClientRequest login;
    login.method = "POST";
    login.target = path;
    login.contentType = "application/x-www-form-urlencoded";
    login.body = "challenge=" + bazarish::percentEncode(challenge) + "&blob="
        + bazarish::percentEncode(service::signLoginBlob(
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
        = testutil::freshDir("panel-services-test");
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
    nlohmann::json expected;
    nlohmann::json claimed = {{"state", "waiting"}, {"challenge", ""}, {"blob", ""}};
    nlohmann::json askedClaim;
    node->post("/v1/login/expect", [&](const http::Request& request) {
        const std::lock_guard<std::mutex> lock(guard);
        expected = nlohmann::json::parse(request.body);
        CHECK(linkKeyFromText(expected.at("key").get<std::string>()).size() == kLinkKeyBytes);
        return json({{"ok", true}});
    });
    node->post("/v1/login/claim", [&](const http::Request& request) {
        const std::lock_guard<std::mutex> lock(guard);
        askedClaim = nlohmann::json::parse(request.body);
        return json(claimed);
    });
    const int nodePort = node->start();

    std::string facadeAddress = kOldAddress;
    const auto facade = serving(services);
    facade->get("/settings", [&](const http::Request&) {
        const std::lock_guard<std::mutex> lock(guard);
        return json(
            {{"address", facadeAddress}, {"directListen", {{"host", "0.0.0.0"}, {"port", 8418}}}});
    });
    facade->post("/new-address", [&](const http::Request&) {
        const std::lock_guard<std::mutex> lock(guard);
        const std::string previous = facadeAddress;
        facadeAddress = kNewAddress;
        return json({{"address", kNewAddress}, {"previousAddress", previous}, {"restarting", true}});
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
    initial.services = {ServiceEntry{"node", kServiceNodeKind, at(nodePort), services.pin},
        ServiceEntry{"front", kFacadeKind, at(facadePort), services.pin},
        ServiceEntry{"edge", kGatewayKind, at(gatewayPort), services.pin}};
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
        const http::ClientResponse listed = panel.ask("GET", "/api/facades");
        CHECK(listed.status == 200);
        const nlohmann::json body = nlohmann::json::parse(listed.body);
        CHECK(body.at("facades").size() == 1);
        CHECK(body.at("facades")[0].at("address") == kOldAddress);
        CHECK(body.at("facades")[0].at("inDescriptor") == false);
    }

    {
        const Identity colleague = Identity::generate();
        Config both = settings->get();
        both.admins.push_back(colleague.fingerprint());
        settings->set(both);
        Panel theirs = panel;
        theirs.cookie = signIn(panel.port, colleague);
        CHECK(theirs.ask("GET", "/api/panel").status == 200);
        Config only = settings->get();
        only.admins = {admin.fingerprint()};
        settings->set(only);
        CHECK(theirs.ask("GET", "/api/panel").status == 401);
        CHECK(panel.ask("GET", "/api/panel").status == 200);
    }

    {
        nlohmann::json twice = nlohmann::json::parse(panel.ask("GET", "/api/panel").body);
        nlohmann::json& list = twice.at("services");
        CHECK(list.size() == 3);
        list.push_back(list[1]);
        const http::ClientResponse refused
            = panel.ask("PUT", "/api/panel", {{"services", list}});
        CHECK(refused.status == 400);
        CHECK(settings->get().services.size() == 3);
        CHECK(described.empty());

        list.erase(list.end() - 1);
        const http::ClientResponse saved
            = panel.ask("PUT", "/api/panel", {{"services", list}});
        CHECK(saved.status == 200);
        CHECK(nlohmann::json::parse(saved.body).at("descriptorErrors").empty());
        CHECK(described == nlohmann::json::array({kOldAddress}));
        const nlohmann::json listed
            = nlohmann::json::parse(panel.ask("GET", "/api/facades").body);
        CHECK(listed.at("facades")[0].at("inDescriptor") == true);
        const std::lock_guard<std::mutex> lock(guard);
        CHECK(routes == nlohmann::json::array({{{"dest", "aaaa.b32.i2p"}, {"host", "127.0.0.1"},
                            {"port", 8418}, {"pin", services.pin}}}));
    }

    CHECK(panel.ask("GET", "/api/service-settings?kind=facade").status == 400);
    CHECK(panel.ask("GET", "/api/service-settings?service=nobody").status == 503);
    {
        const http::ClientResponse shown
            = panel.ask("GET", "/api/service-settings?service=edge");
        CHECK(shown.status == 200);
        CHECK(nlohmann::json::parse(shown.body).at("streamPool") == 4);
    }

    {
        const http::ClientResponse renewed
            = panel.ask("POST", "/api/facade/new-address?service=front");
        CHECK(renewed.status == 200);
        const nlohmann::json body = nlohmann::json::parse(renewed.body);
        CHECK(body.at("address") == kNewAddress);
        CHECK(body.at("previousAddress") == kOldAddress);
        CHECK(!body.contains("url"));
        CHECK(body.at("descriptorError") == "");
        CHECK(body.at("gateways").size() == 1);
        CHECK(body.at("gateways")[0].at("changed") == true);
        CHECK(described == nlohmann::json::array({kNewAddress}));
        CHECK(routes[0].at("dest") == "cccc.b32.i2p");
        CHECK(panel.ask("POST", "/api/facade/new-address?service=edge").status
            == 404);
    }

    CHECK(panel.ask("POST", "/api/restart?service=edge").status == 200);
    CHECK(gatewayRestarts == 1);

    Panel stranger = panel;
    stranger.cookie = "not-a-session";
    CHECK(stranger.ask("GET", "/api/facades").status == 401);

    {
        const std::string facadeHost = std::string(52, 'f') + ".b32.i2p";
        {
            const std::lock_guard<std::mutex> lock(guard);
            described = nlohmann::json::array({facadeHost});
        }
        http::ClientRequest page;
        page.method = "GET";
        page.target = "/login";
        const http::ClientResponse shown = http::request("127.0.0.1", panel.port, page, {});
        CHECK(shown.status == 200);
        CHECK(shown.body.find("class=\"qr-code\"><svg") != std::string::npos);
        const std::size_t start = shown.body.find(kChallengeField)
            + std::char_traits<char>::length(kChallengeField);
        const std::string pasted = shown.body.substr(start, shown.body.find('"', start) - start);
        CHECK(!service::readLoginCallback(pasted).has_value());
        CHECK(shown.body.find("<div data-signin-tabs hidden>") != std::string::npos);
        const std::string challenge = [&]() {
            const std::lock_guard<std::mutex> lock(guard);
            return expected.at("challenge").get<std::string>();
        }();
        const std::optional<service::LoginCallback> callback = service::readLoginCallback(challenge);
        CHECK(callback.has_value() && callback->host == facadeHost);
        std::string token;
        for (const auto& [name, value] : shown.headers) {
            if (value.starts_with("adminsignin=")) {
                token = value.substr(std::strlen("adminsignin="), value.find(';') - std::strlen("adminsignin="));
                CHECK(value.find("Path=/login") != std::string::npos);
            }
        }
        CHECK(!token.empty());
        const std::string nonce
            = nlohmann::json::parse(service::decodeLoginChallenge(challenge)).at("nonce").get<std::string>();
        {
            const std::lock_guard<std::mutex> lock(guard);
            CHECK(expected.at("challenge") == challenge);
            CHECK(expected.at("token") == token);
        }
        const auto wait = [&](const std::string& cookie) {
            http::ClientRequest asked;
            asked.method = "GET";
            asked.target = "/login/wait?nonce=" + nonce;
            asked.headers = {{"Cookie", "adminsignin=" + cookie}};
            return http::request("127.0.0.1", panel.port, asked, {});
        };
        CHECK(nlohmann::json::parse(wait(token).body).at("state") == "waiting");
        {
            const std::lock_guard<std::mutex> lock(guard);
            CHECK(askedClaim.at("nonce") == nonce);
            CHECK(askedClaim.at("token") == token);
            claimed = {{"state", "signed"}, {"challenge", challenge},
                {"blob", service::signLoginBlob(admin,
                             static_cast<std::int64_t>(std::time(nullptr)), challenge)}};
        }
        const http::ClientResponse entered = wait(token);
        CHECK(nlohmann::json::parse(entered.body).at("state") == "signedIn");
        std::string session;
        for (const auto& [name, value] : entered.headers) {
            if (value.starts_with("adminsession=")) {
                session = value.substr(std::strlen("adminsession="), value.find(';') - std::strlen("adminsession="));
            }
        }
        Panel scanned{panel.port, session};
        CHECK(scanned.ask("GET", "/api/panel").status == 200);

        const http::ClientResponse again = http::request("127.0.0.1", panel.port, page, {});
        const std::size_t from = again.body.find(kChallengeField)
            + std::char_traits<char>::length(kChallengeField);
        const std::string other = again.body.substr(from, again.body.find('"', from) - from);
        {
            const std::lock_guard<std::mutex> lock(guard);
            claimed = {{"state", "signed"}, {"challenge", other},
                {"blob", service::signLoginBlob(Identity::generate(),
                             static_cast<std::int64_t>(std::time(nullptr)), other)}};
        }
        CHECK(nlohmann::json::parse(wait(token).body).at("state") == "gone");
        {
            const std::lock_guard<std::mutex> lock(guard);
            claimed = {{"state", "waiting"}, {"challenge", ""}, {"blob", ""}};
            described = nlohmann::json::array();
        }
    }

    api.stop();
    serverThread.join();

    {
        {
            const std::lock_guard<std::mutex> lock(guard);
            described = nlohmann::json::array();
            routes = nlohmann::json::array();
        }
        const std::filesystem::path unclaimedPath = root / "unclaimed-panel.json";
        { std::ofstream(unclaimedPath) << "{}\n"; }
        Config unclaimed = initial;
        unclaimed.admins.clear();
        const auto fresh = std::make_shared<PanelSettings>(unclaimedPath, unclaimed);
        HttpApi claimed(fresh, panelIdentity, panelKeys, options);
        const int port = claimed.bind("127.0.0.1", 0);
        CHECK(port > 0);
        std::thread claimedThread([&claimed]() { claimed.wait(); });
        CHECK(!signIn(port, admin, "/setup").empty());
        CHECK(fresh->get().admins == std::vector<std::string>{admin.fingerprint()});
        {
            const std::lock_guard<std::mutex> lock(guard);
            CHECK(described == nlohmann::json::array({kNewAddress}));
            CHECK(routes.size() == 1);
            CHECK(routes[0].at("dest") == kNewAddress);
        }
        claimed.stop();
        claimedThread.join();
    }

    node->stop();
    facade->stop();
    gateway->stop();
    std::filesystem::remove_all(root);
    std::printf("TestPanelServices OK\n");
    return 0;
}
