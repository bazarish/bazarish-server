// Bazarish project (c) 2026
#include "Facade.hpp"
#include "FacadeAddress.hpp"
#include "Load.hpp"
#include "HttpTestUtil.hpp"
#include "TestUtil.hpp"

#include <LoginRelay.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <nlohmann/json.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Tls.hpp>

#include <atomic>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <cstdlib>
#include <string>
#include <map>
#include <utility>

namespace {

using testutil::Headers;
using testutil::call;
using testutil::callTls;
using testutil::signedHeaders;

namespace http = bazarish::http;

constexpr int kDirectPort = 8418;
constexpr int kMovedDirectPort = 8417;
constexpr int kMovedNodePort = 8431;

void installBackend(http::Server& server, const std::string& name)
{
    const http::Handler echo = [name](const http::Request& request) {
        http::Response response;
        response.body = nlohmann::json{
            {"backend", name},
            {"method", request.method},
            {"path", request.path},
            {"body", request.body},
            {"clientHeader", request.header("X-Bazarish-Client")},
            {"alias", request.query("alias")},
        }.dump();
        return response;
    };
    for (const char* const method : {"GET", "POST", "PUT", "DELETE"}) {
        server.route(method, "*", echo);
    }
}

http::Server::Options backendOptions()
{
    http::Server::Options options;
    options.port = 0;
    return options;
}

}  // namespace

void testLoadSample()
{
    bazarish::facade::Load load;
    constexpr std::int64_t kNow = 1'700'000'000;
    load.record(kNow - 2 * 24 * 3600);
    load.record(kNow - 2 * 3600);
    load.record(kNow - 90);
    for (int i = 0; i < 3; ++i) {
        load.record(kNow);
    }

    const bazarish::facade::Load::Sample sample = load.sample(kNow);
    CHECK(sample.lastMinute == 3);
    CHECK(sample.lastHour == 4);
    CHECK(sample.lastDay == 5);
    CHECK(sample.total == 6);
    CHECK(sample.inFlight == 0);

    {
        const bazarish::facade::Load::InFlight one(load);
        const bazarish::facade::Load::InFlight two(load);
        CHECK(load.sample(kNow).inFlight == 2);
    }
    CHECK(load.sample(kNow).inFlight == 0);
}

void testAddress()
{
    const testutil::ScratchDir scratch("facade-test-address");
    const std::filesystem::path& state = scratch.path();

    const bazarish::facade::FacadeAddress first = bazarish::facade::loadAddress(state);
    CHECK(first.address().find(".b32.i2p") != std::string::npos);
    CHECK(first.address().find('/') == std::string::npos);
    CHECK(bazarish::facade::loadAddress(state).address() == first.address());

    const bazarish::facade::FacadeAddress minted = bazarish::facade::mintAddress(state);
    CHECK(minted.address() != first.address());
    CHECK(bazarish::facade::loadAddress(state).address() == minted.address());
}

int main()
try {
    testLoadSample();
    testAddress();
    const testutil::ScratchDir backendScratch("facade-test-backend");
    const std::filesystem::path& backendState = backendScratch.path();
    const bazarish::tls::Credential backendCredential
        = bazarish::tls::selfSigned(backendState);
    http::Server::Options messagingOptions = backendOptions();
    messagingOptions.certificate = backendCredential.certificate.string();
    messagingOptions.key = backendCredential.key.string();
    http::Server messaging(messagingOptions);
    installBackend(messaging, "messaging");
    const int messagingPort = messaging.start();
    CHECK(messagingPort > 0);
    const testutil::ScratchDir nodeScratch("facade-test-node");
    const std::filesystem::path& nodeState = nodeScratch.path();
    const bazarish::tls::Credential nodeCredential = bazarish::tls::selfSigned(nodeState);
    http::Server::Options nodeOptions = backendOptions();
    nodeOptions.certificate = nodeCredential.certificate.string();
    nodeOptions.key = nodeCredential.key.string();
    http::Server serverService(nodeOptions);
    installBackend(serverService, "server-service");
    const int nodePort = serverService.start();
    CHECK(nodePort > 0);

    bazarish::facade::FacadeOptions options;
    options.messaging = {"127.0.0.1", messagingPort, backendCredential.pin};
    options.serverService = {"127.0.0.1", nodePort, nodeCredential.pin};
    options.address = "example.b32.i2p";
    const testutil::ScratchDir configScratch("facade-test");
    const std::filesystem::path& configDir = configScratch.path();
    const std::filesystem::path configPath = configDir / "facade.json";
    {
        std::ofstream config(configPath);
        config << "{\n  \"logLevel\": \"info\"\n}\n";
    }
    bazarish::facade::FacadeSettings::Values facadeValues;
    facadeValues.logLevel = "info";
    facadeValues.messagingHost = "127.0.0.1";
    facadeValues.messagingPort = messagingPort;
    facadeValues.serverServiceHost = "127.0.0.1";
    facadeValues.serverServicePort = nodePort;
    facadeValues.listenHost = "127.0.0.1";
    facadeValues.listenPort = 8419;
    facadeValues.opsHost = "127.0.0.1";
    facadeValues.opsPort = 8429;
    facadeValues.directHost = "127.0.0.1";
    facadeValues.directPort = kDirectPort;
    facadeValues.i2pPrivacy = "max";
    facadeValues.i2pTunnelQuantity = 3;
    facadeValues.i2pLogLevel = "none";
    const auto facadeSettings
        = std::make_shared<bazarish::facade::FacadeSettings>(configPath, facadeValues);
    options.settings = facadeSettings;
    const bazarish::Identity operatorIdentity = bazarish::Identity::generate();
    options.operatorFingerprints = {operatorIdentity.fingerprint()};
    const testutil::ScratchDir facadeScratch("facade-test-own");
    const std::filesystem::path& facadeState = facadeScratch.path();
    options.stateDirectory = facadeState.string();
    std::atomic<int> restarts{0};
    options.requestRestart = [&restarts]() { ++restarts; };
    const bazarish::tls::Credential facadeCredential = bazarish::tls::selfSigned(facadeState);
    options.tlsCertificate = facadeCredential.certificate.string();
    options.tlsKey = facadeCredential.key.string();
    {
        bazarish::facade::Facade unpinned(options);
        CHECK(unpinned.bindOps("127.0.0.1", 0) == 0);
    }
    const bazarish::tls::Credential opsCaller = bazarish::tls::selfSigned(facadeState / "ops-caller");
    options.opsClientPins = {opsCaller.pin};
    bazarish::facade::Facade facade(options);
    const int facadePort = facade.bind("127.0.0.1", 0);
    CHECK(facadePort > 0);
    const int opsPort = facade.bindOps("127.0.0.1", 0);
    CHECK(opsPort > 0);
    const auto opsCall = [&](const std::string& method, const std::string& target,
                             const testutil::Headers& headers = {}, const std::string& body = {}) {
        http::ClientOptions asCaller;
        asCaller.tls = true;
        asCaller.pin = facadeCredential.pin;
        asCaller.certificate = opsCaller.certificate.string();
        asCaller.key = opsCaller.key.string();
        return testutil::call(opsPort, method, target, headers, body, asCaller);
    };
    const int directPort = facade.bindDirect("127.0.0.1", 0);
    CHECK(directPort > 0);

    {
        const std::string sealed = "opaque-frame-bytes";
        const http::ClientResponse direct
            = callTls(directPort, facadeCredential.pin, "POST", "/t", {}, sealed);
        CHECK(direct.status == 200);
        CHECK(nlohmann::json::parse(direct.body).at("backend") == "messaging");
        CHECK(callTls(directPort, facadeCredential.pin, "GET", "/nowhere").status
            == 404);
        CHECK(call(directPort, "POST", "/t", {}, sealed).status == 0);
    }

    {
        const std::string sealed = "opaque-frame-bytes";
        const http::ClientResponse result
            = call(facadePort, "POST", "/t", {}, sealed);
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("backend") == "messaging");
        CHECK(reply.at("method") == "POST");
        CHECK(reply.at("path") == "/t");
        CHECK(reply.at("body") == sealed);
        CHECK(reply.at("clientHeader") == "");
    }

    {
        const http::ClientResponse result = call(facadePort, "GET", "/v1/server/card");
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("backend") == "messaging");
        CHECK(reply.at("path") == "/v1/server/card");
    }

    {
        const http::ClientResponse tunnel = call(facadePort, "POST", "/n", {}, "frame");
        CHECK(tunnel.status == 200);
        CHECK(nlohmann::json::parse(tunnel.body).at("backend") == "server-service");
        CHECK(nlohmann::json::parse(tunnel.body).at("body") == "frame");
        const http::ClientResponse card = call(facadePort, "GET", "/v1/node/card");
        CHECK(card.status == 200);
        CHECK(nlohmann::json::parse(card.body).at("backend") == "server-service");
        CHECK(call(facadePort, "GET", "/n").status == 404);
        CHECK(call(facadePort, "POST", "/v1/node/card", {}, "{}").status == 404);
        CHECK(call(facadePort, "GET", "/t").status == 404);

        const std::string nonce(bazarish::loginrelay::kNonceChars, 'a');
        const http::ClientResponse callback
            = call(facadePort, "POST", bazarish::loginrelay::kCallbackPath, {}, "{}");
        CHECK(callback.status == 200);
        CHECK(nlohmann::json::parse(callback.body).at("backend") == "server-service");
        const http::ClientResponse challenge
            = call(facadePort, "GET", std::string(bazarish::loginrelay::kChallengePrefix) + nonce);
        CHECK(challenge.status == 200);
        CHECK(nlohmann::json::parse(challenge.body).at("backend") == "server-service");
        for (const auto& [method, path] : std::initializer_list<std::pair<std::string, std::string>>{
                 {"GET", bazarish::loginrelay::kCallbackPath},
                 {"POST", std::string(bazarish::loginrelay::kCallbackPath) + "/" + nonce},
                 {"POST", std::string(bazarish::loginrelay::kChallengePrefix) + nonce},
                 {"GET", "/login/c/" + nonce.substr(1)},
                 {"GET", "/login/c/" + nonce + "a"},
                 {"GET", "/login/c/" + std::string(bazarish::loginrelay::kNonceChars, 'A')},
                 {"GET", "/login/c/" + nonce + "/x"},
                 {"POST", "/login"}}) {
            CHECK(call(facadePort, method, path, {}, "{}").status == 404);
        }
    }

    for (const auto& [method, path] : std::initializer_list<std::pair<const char*, const char*>>{
             {"GET", "/"}, {"GET", "/healthz"}, {"GET", "/settings"},
             {"POST", "/v1/messaging/self"}, {"GET", "/v1/messaging/pending"},
             {"POST", "/v1/account/registration"},
             {"POST", "/t/more"}, {"PUT", "/t"}, {"DELETE", "/n"}}) {
        const http::ClientResponse refused = call(facadePort, method, path, {}, "{}");
        CHECK(refused.status == 404);
        CHECK(refused.body.empty());
    }

    {
        CHECK(callTls(opsPort, facadeCredential.pin, "GET", "/healthz").status == 0);
        const http::ClientResponse unauthenticated = opsCall("GET", "/healthz");
        CHECK(unauthenticated.status == 403);
        const http::ClientResponse proxied = opsCall("GET", "/v1/messaging/self");
        CHECK(proxied.status == 404);
    }

    {
        const std::string path = "/settings";
        CHECK(opsCall("GET", path).status == 403);

        const http::ClientResponse shown
            = opsCall("GET", path, signedHeaders(operatorIdentity, "GET", path, {}));
        CHECK(shown.status == 200);
        const nlohmann::json values = nlohmann::json::parse(shown.body);
        CHECK(values.at("address").get<std::string>() == options.address);
        CHECK(!values.contains("url"));
        CHECK(values.at("i2pTunnelQuantity").get<int>() == 3);
        CHECK(values.at("directListen").at("port").get<int>() == kDirectPort);
        CHECK(values.at("serverService").at("port").get<int>() == nodePort);
        CHECK(values.at("i2pLogLevel").get<std::string>() == "none");

        const nlohmann::json wanted = {{"i2pTunnelQuantity", 8}, {"i2pLogLevel", "debug"},
            {"directListen", {{"host", "127.0.0.1"}, {"port", kMovedDirectPort}}},
            {"serverService", {{"host", "127.0.0.1"}, {"port", kMovedNodePort}}}};
        const std::string body = wanted.dump();
        CHECK(opsCall("PUT", path, signedHeaders(operatorIdentity, "PUT", path, body), body)
                  .status
            == 200);
        CHECK(facadeSettings->get().directPort == kMovedDirectPort);
        CHECK(bazarish::i2p::i2pLogLevel() == bazarish::i2p::I2pLogLevel::eDebug);

        std::ifstream written(configPath);
        const nlohmann::json onDisk = nlohmann::json::parse(written);
        CHECK(onDisk.at("i2p").at("tunnelQuantity").get<int>() == 8);
        CHECK(onDisk.at("i2p").at("logLevel").get<std::string>() == "debug");
        CHECK(onDisk.at("directListen").at("port").get<int>() == kMovedDirectPort);
        CHECK(onDisk.at("serverService").at("port").get<int>() == kMovedNodePort);

        const std::string bad = nlohmann::json{{"i2pTunnelQuantity", 0}}.dump();
        CHECK(opsCall("PUT", path, signedHeaders(operatorIdentity, "PUT", path, bad), bad)
                  .status
            == 400);
        CHECK(facadeSettings->get().i2pTunnelQuantity == 8);
        const std::string loud = nlohmann::json{{"i2pLogLevel", "verbose"}}.dump();
        CHECK(opsCall("PUT", path, signedHeaders(operatorIdentity, "PUT", path, loud), loud)
                  .status
            == 400);
        CHECK(facadeSettings->get().i2pLogLevel == "debug");
        const std::string quiet = nlohmann::json{{"i2pLogLevel", "none"}}.dump();
        CHECK(opsCall("PUT", path, signedHeaders(operatorIdentity, "PUT", path, quiet), quiet)
                  .status
            == 200);
        CHECK(bazarish::i2p::i2pLogLevel() == bazarish::i2p::I2pLogLevel::eNone);

        const std::string restart = "/restart";
        CHECK(opsCall("POST", restart).status == 403);
        CHECK(restarts == 0);
        CHECK(opsCall("POST", restart,
                  signedHeaders(operatorIdentity, "POST", restart, {}))
                  .status
            == 200);
        CHECK(restarts == 1);
    }

    {
        const std::string path = "/new-address";
        CHECK(opsCall("POST", path).status == 403);
        const http::ClientResponse renewed = opsCall("POST", path,
            signedHeaders(operatorIdentity, "POST", path, {}));
        CHECK(renewed.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(renewed.body);
        CHECK(reply.at("previousAddress").get<std::string>() == options.address);
        const std::string address = reply.at("address").get<std::string>();
        CHECK(address != options.address);
        CHECK(address.find(".b32.i2p") != std::string::npos);
        CHECK(address.find('/') == std::string::npos);
        CHECK(bazarish::facade::loadAddress(facadeState).address() == address);
        CHECK(restarts == 2);
    }

    facade.stop();
    messaging.stop();
    serverService.stop();
    return 0;
} catch (...) {
    return testutil::failed();
}
