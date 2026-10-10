// Bazarish project (c) 2026
#include "Gateway.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Tls.hpp>

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/9d41f0c2a7e3";
constexpr const char* kToken = "a-fourth-static-token";
constexpr int kWaitSeconds = 20;
constexpr std::size_t kStreamPool = 1;
constexpr std::size_t kCallPool = 0;
constexpr int kWantedQuantity = 5;
constexpr int kWantedStreamPool = 3;
constexpr int kWantedCallPool = 2;
constexpr const char* kServerDest = "fkc4nkqn6k2bwrqsgbabnkyx4g5s2cp3nvnrdnkqxz4bzcbzrfaa.b32.i2p";

int unusedPort()
{
    boost::asio::io_context io;
    const boost::asio::ip::tcp::acceptor door(
        io, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    return door.local_endpoint().port();
}

i2p::RouterConfig borrowedFrom(const int port)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayToken = kToken;
    config.gatewayTls = false;
    return config;
}

bool waitFor(const std::function<bool()>& done)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kWaitSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return done();
}

bool routedLocally(const i2p::Router& router, const std::string& host)
{
    for (const i2p::LocalDestination& destination : router.localDestinations()) {
        if (destination.host == host) {
            return destination.localRoute;
        }
    }
    return false;
}

http::ClientResponse askOps(const int port, const std::string& pin, const std::string& method,
    const std::string& path, const Identity* signer, const std::string& body = {})
{
    http::ClientRequest out;
    out.method = method;
    out.target = path;
    out.body = body;
    if (!body.empty()) {
        out.contentType = "application/json";
    }
    if (signer != nullptr) {
        out.headers = auth::signRequest(
            *signer, nowSeconds(), method, path, Bytes(body.begin(), body.end()));
    }
    http::ClientOptions options;
    options.tls = true;
    options.pin = pin;
    return http::request("127.0.0.1", port, out, options);
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-ops-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const std::filesystem::path configPath = root / "gateway.json";
    {
        std::ofstream config(configPath);
        config << nlohmann::json{
            {"basePath", kPath},
            {"token", kToken},
            {"state", (root / "state").string()},
            {"i2p", {{"privacy", "minimal"}, {"tunnelQuantity", i2p::kDefaultTunnelQuantity}}},
            {"pools", {{"stream", kStreamPool}, {"call", kCallPool}}},
        }.dump(2);
    }
    Settings settings = Settings::from(ConfigView(ConfigFile(configPath).read()));
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.notFoundBody = "<html>nothing</html>";
    const Identity operatorIdentity = Identity::generate();
    settings.operators.push_back(operatorIdentity.fingerprint());
    settings.opsHost = "127.0.0.1";
    settings.opsPort = unusedPort();

    const tls::Credential server = tls::selfSigned(root / "server");
    http::Server::Options serverOptions;
    serverOptions.port = 0;
    serverOptions.threads = 1;
    serverOptions.certificate = server.certificate.string();
    serverOptions.key = server.key.string();
    http::Server listener(serverOptions);
    listener.get("/v1/server/card", [](const http::Request&) {
        return http::Response{200, "application/json", {}, R"({"card":"here"})"};
    });
    const int listenerPort = listener.start();
    CHECK(listenerPort > 0);

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));
    std::atomic<int> restarts{0};
    Gateway gateway(settings, engine, OpsControl{configPath, [&restarts]() { ++restarts; }});
    const int port = gateway.start();
    CHECK(port > 0);
    CHECK(gateway.pooled() == kStreamPool + kCallPool);

    const std::string pin = tls::selfSigned(settings.stateDir).pin;
    const Identity stranger = Identity::generate();
    CHECK(askOps(settings.opsPort, pin, "GET", "/settings", nullptr).status == 403);
    CHECK(askOps(settings.opsPort, pin, "GET", "/settings", &stranger).status == 403);

    const http::ClientResponse shown
        = askOps(settings.opsPort, pin, "GET", "/settings", &operatorIdentity);
    CHECK(shown.status == 200);
    CHECK(shown.body.find(kToken) == std::string::npos);
    CHECK(shown.body.find(kPath) == std::string::npos);
    const nlohmann::json before = nlohmann::json::parse(shown.body);
    CHECK(before.at("i2pPrivacy") == "minimal");
    CHECK(before.at("callPrivacy") == "minimal");
    CHECK(before.at("streamPool") == kStreamPool);
    CHECK(before.at("callPool") == kCallPool);
    CHECK(before.at("direct").empty());

    for (const nlohmann::json& wrong : {nlohmann::json{{"i2pTunnelQuantity", 0}},
             nlohmann::json{{"streamPool", kMaxPoolDepth + 1}},
             nlohmann::json{{"callPool", -1}}, nlohmann::json{{"i2pPrivacy", "short"}},
             nlohmann::json{{"i2pPrivacy", "max"},
                 {"direct", {{{"dest", kServerDest}, {"host", "127.0.0.1"}, {"port", 1}}}}}}) {
        CHECK(askOps(settings.opsPort, pin, "PUT", "/settings", &operatorIdentity, wrong.dump())
                  .status
            == 400);
    }
    CHECK(Settings::from(ConfigView(ConfigFile(configPath).read())).tunnelPrivacy
        == i2p::Privacy::eMinimal);

    const nlohmann::json wanted = {
        {"i2pPrivacy", "max"},
        {"i2pTunnelQuantity", kWantedQuantity},
        {"streamPool", kWantedStreamPool},
        {"callPool", kWantedCallPool},
        {"direct",
            {{{"dest", kServerDest}, {"host", "127.0.0.1"}, {"port", listenerPort},
                {"pin", server.pin}}}},
    };
    CHECK(askOps(settings.opsPort, pin, "PUT", "/settings", &stranger, wanted.dump()).status
        == 403);
    const http::ClientResponse changed
        = askOps(settings.opsPort, pin, "PUT", "/settings", &operatorIdentity, wanted.dump());
    CHECK(changed.status == 200);
    CHECK(nlohmann::json::parse(changed.body).at("streamPool") == kWantedStreamPool);

    const Settings written = Settings::from(ConfigView(ConfigFile(configPath).read()));
    CHECK(written.tunnelPrivacy == i2p::Privacy::eMax);
    CHECK(written.tunnelQuantity == kWantedQuantity);
    CHECK(written.streamPool == static_cast<std::size_t>(kWantedStreamPool));
    CHECK(written.callPool == static_cast<std::size_t>(kWantedCallPool));
    CHECK(written.direct.size() == 1);
    CHECK(written.direct.front().dest == kServerDest);
    CHECK(written.token == kToken);
    CHECK(written.basePath == kPath);
    CHECK(gateway.pooled() == kStreamPool + kCallPool);

    i2p::Router bob(borrowedFrom(port));
    bob.start();
    const std::shared_ptr<i2p::Endpoint> link = bob.createEndpoint(i2p::EndpointConfig{});
    const std::unique_ptr<i2p::Stream> card
        = link->connect(kServerDest, std::chrono::seconds(kWaitSeconds));
    CHECK(card != nullptr);
    CHECK(waitFor([&]() { return routedLocally(bob, link->routingHost()); }));
    card->close();
    link->stop();
    bob.stop();

    CHECK(askOps(settings.opsPort, pin, "POST", "/restart", nullptr).status == 403);
    CHECK(restarts == 0);
    CHECK(askOps(settings.opsPort, pin, "POST", "/restart", &operatorIdentity).status == 200);
    CHECK(restarts == 1);

    gateway.stop();
    listener.stop();
    std::filesystem::remove_all(root);
    std::printf("TestOpsSettings ok\n");
    return 0;
}
