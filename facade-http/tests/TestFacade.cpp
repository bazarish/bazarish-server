// Bazarish project (c) 2026
#include "Facade.hpp"
#include "FacadeAddress.hpp"
#include "Load.hpp"

#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <nlohmann/json.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Tls.hpp>

#include <atomic>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <string>
#include <map>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

namespace {

namespace http = bazarish::http;

using Headers = std::map<std::string, std::string>;

constexpr int kDirectPort = 8418;
constexpr int kMovedDirectPort = 8417;
constexpr int kMovedNodePort = 8431;

http::ClientResponse call(const int port, const std::string& method, const std::string& path,
    const Headers& headers = {}, const std::string& body = {})
{
    http::ClientRequest request;
    request.method = method;
    request.target = path;
    request.headers = headers;
    request.body = body;
    if (!body.empty()) {
        request.contentType = "application/json";
    }
    return http::request("127.0.0.1", port, request, {});
}

http::ClientResponse callTls(const int port, const std::string& pin, const std::string& method,
    const std::string& path, const Headers& headers = {}, const std::string& body = {})
{
    http::ClientRequest request;
    request.method = method;
    request.target = path;
    request.headers = headers;
    request.body = body;
    if (!body.empty()) {
        request.contentType = "application/json";
    }
    http::ClientOptions options;
    options.tls = true;
    options.pin = pin;
    return http::request("127.0.0.1", port, request, options);
}

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
        server.route(method, "(.*)", echo);
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
    const std::filesystem::path state
        = std::filesystem::temp_directory_path() / "bazarish-facade-test-address";
    std::filesystem::remove_all(state);

    const bazarish::facade::FacadeAddress first = bazarish::facade::loadAddress(state);
    CHECK(first.address().find(".b32.i2p") != std::string::npos);
    CHECK(first.address().find('/') == std::string::npos);
    CHECK(bazarish::facade::loadAddress(state).address() == first.address());

    const bazarish::facade::FacadeAddress minted = bazarish::facade::mintAddress(state);
    CHECK(minted.address() != first.address());
    CHECK(bazarish::facade::loadAddress(state).address() == minted.address());
    std::filesystem::remove_all(state);
}

Headers signedHeaders(const bazarish::Identity& identity, const std::string& method,
    const std::string& path, const std::string& body)
{
    const bazarish::auth::Headers signature = bazarish::auth::signRequest(identity,
        static_cast<std::int64_t>(std::time(nullptr)), method, path,
        bazarish::Bytes(body.begin(), body.end()));
    return Headers(signature.begin(), signature.end());
}

int main()
{
    testLoadSample();
    testAddress();
    const std::filesystem::path backendState
        = std::filesystem::temp_directory_path() / "bazarish-facade-test-backend";
    const bazarish::tls::Credential backendCredential
        = bazarish::tls::selfSigned(backendState);
    http::Server::Options messagingOptions = backendOptions();
    messagingOptions.certificate = backendCredential.certificate.string();
    messagingOptions.key = backendCredential.key.string();
    http::Server messaging(messagingOptions);
    installBackend(messaging, "messaging");
    const int messagingPort = messaging.start();
    CHECK(messagingPort > 0);
    const bazarish::tls::Credential nodeCredential = bazarish::tls::selfSigned(
        std::filesystem::temp_directory_path() / "bazarish-facade-test-node");
    http::Server::Options nodeOptions = backendOptions();
    nodeOptions.certificate = nodeCredential.certificate.string();
    nodeOptions.key = nodeCredential.key.string();
    http::Server serviceNode(nodeOptions);
    installBackend(serviceNode, "service-node");
    const int nodePort = serviceNode.start();
    CHECK(nodePort > 0);

    bazarish::facade::FacadeOptions options;
    options.messaging = {"127.0.0.1", messagingPort, backendCredential.pin};
    options.serviceNode = {"127.0.0.1", nodePort, nodeCredential.pin};
    options.address = "example.b32.i2p";
    const std::filesystem::path configPath
        = std::filesystem::temp_directory_path() / "bazarish-facade-test.json";
    {
        std::ofstream config(configPath);
        config << "{\n  \"logLevel\": \"info\"\n}\n";
    }
    bazarish::facade::FacadeSettings::Values facadeValues;
    facadeValues.logLevel = "info";
    facadeValues.messagingHost = "127.0.0.1";
    facadeValues.messagingPort = messagingPort;
    facadeValues.serviceNodeHost = "127.0.0.1";
    facadeValues.serviceNodePort = nodePort;
    facadeValues.listenHost = "127.0.0.1";
    facadeValues.listenPort = 8419;
    facadeValues.opsHost = "127.0.0.1";
    facadeValues.opsPort = 8429;
    facadeValues.directHost = "127.0.0.1";
    facadeValues.directPort = kDirectPort;
    facadeValues.i2pPrivacy = "max";
    facadeValues.i2pTunnelQuantity = 3;
    const auto facadeSettings
        = std::make_shared<bazarish::facade::FacadeSettings>(configPath, facadeValues);
    options.settings = facadeSettings;
    const bazarish::Identity operatorIdentity = bazarish::Identity::generate();
    options.operatorFingerprints = {operatorIdentity.fingerprint()};
    const std::filesystem::path facadeState
        = std::filesystem::temp_directory_path() / "bazarish-facade-test-own";
    std::filesystem::remove_all(facadeState);
    options.stateDirectory = facadeState.string();
    std::atomic<int> restarts{0};
    options.requestRestart = [&restarts]() { ++restarts; };
    const bazarish::tls::Credential facadeCredential = bazarish::tls::selfSigned(facadeState);
    options.tlsCertificate = facadeCredential.certificate.string();
    options.tlsKey = facadeCredential.key.string();
    bazarish::facade::Facade facade(options);
    const int facadePort = facade.bind("127.0.0.1", 0);
    CHECK(facadePort > 0);
    const int opsPort = facade.bindOps("127.0.0.1", 0);
    CHECK(opsPort > 0);
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

    for (const char* const gone :
        {"/v1/messaging/self", "/v1/messaging/pending", "/v1/account/registration"}) {
        CHECK(call(facadePort, "POST", gone, {}, "{}").status == 404);
        CHECK(call(facadePort, "GET", gone).status == 404);
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
        CHECK(nlohmann::json::parse(tunnel.body).at("backend") == "service-node");
        CHECK(nlohmann::json::parse(tunnel.body).at("body") == "frame");
        const http::ClientResponse card = call(facadePort, "GET", "/v1/node/card");
        CHECK(card.status == 200);
        CHECK(nlohmann::json::parse(card.body).at("backend") == "service-node");
        CHECK(call(facadePort, "GET", "/n").status == 404);
        CHECK(call(facadePort, "POST", "/v1/node/card", {}, "{}").status == 404);
        CHECK(call(facadePort, "GET", "/t").status == 404);
    }

    {
        const http::ClientResponse result = call(facadePort, "POST", "/s/9f3c/t", {}, "frame");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse result = call(facadePort, "GET", "/v1/other/thing");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse result
            = call(facadePort, "PUT", "/v1/storage/blob", {}, "ciphertext-bytes");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse lookup = call(facadePort, "GET",
            "/v1/account/card?user=alice&key=AAAA");
        CHECK(lookup.status == 404);
        const http::ClientResponse publish = call(facadePort, "POST",
            "/v1/account/card", {}, R"({"card":"AAAA"})");
        CHECK(publish.status == 404);
        const http::ClientResponse unknown
            = call(facadePort, "GET", "/v1/other/thing");
        CHECK(lookup.body == unknown.body);
        CHECK(publish.body == unknown.body);
    }

    {
        const http::ClientResponse result
            = call(facadePort, "PUT", "/v1/storage/quota", {}, "{}");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse result = call(facadePort, "GET", "/b/somecapability");
        CHECK(result.status == 404);
    }

    {
        for (const char* const path : {"/v1/messaging/reseed", "/v1/account/portal", "/healthz",
                 "/"}) {
            const http::ClientResponse result = call(facadePort, "GET", path);
            CHECK(result.status == 404);
            CHECK(result.body.empty());
        }
    }

    {
        const http::ClientResponse result
            = call(facadePort, "GET", "/v1/messaging/reseed");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse unauthenticated = callTls(opsPort, facadeCredential.pin, "GET", "/healthz");
        CHECK(unauthenticated.status == 403);
        const http::ClientResponse proxied = callTls(opsPort, facadeCredential.pin, "GET", "/v1/messaging/self");
        CHECK(proxied.status == 404);
    }

    {
        const std::string path = "/settings";
        CHECK(callTls(opsPort, facadeCredential.pin, "GET", path).status == 403);

        const http::ClientResponse shown
            = callTls(opsPort, facadeCredential.pin, "GET", path, signedHeaders(operatorIdentity, "GET", path, {}));
        CHECK(shown.status == 200);
        const nlohmann::json values = nlohmann::json::parse(shown.body);
        CHECK(values.at("address").get<std::string>() == options.address);
        CHECK(!values.contains("url"));
        CHECK(values.at("i2pTunnelQuantity").get<int>() == 3);
        CHECK(values.at("directListen").at("port").get<int>() == kDirectPort);
        CHECK(values.at("serviceNode").at("port").get<int>() == nodePort);

        const nlohmann::json wanted = {{"i2pTunnelQuantity", 8},
            {"directListen", {{"host", "127.0.0.1"}, {"port", kMovedDirectPort}}},
            {"serviceNode", {{"host", "127.0.0.1"}, {"port", kMovedNodePort}}}};
        const std::string body = wanted.dump();
        CHECK(callTls(opsPort, facadeCredential.pin, "PUT", path, signedHeaders(operatorIdentity, "PUT", path, body), body)
                  .status
            == 200);
        CHECK(facadeSettings->get().directPort == kMovedDirectPort);

        std::ifstream written(configPath);
        const nlohmann::json onDisk = nlohmann::json::parse(written);
        CHECK(onDisk.at("i2p").at("tunnelQuantity").get<int>() == 8);
        CHECK(onDisk.at("directListen").at("port").get<int>() == kMovedDirectPort);
        CHECK(onDisk.at("serviceNode").at("port").get<int>() == kMovedNodePort);

        const std::string bad = nlohmann::json{{"i2pTunnelQuantity", 0}}.dump();
        CHECK(callTls(opsPort, facadeCredential.pin, "PUT", path, signedHeaders(operatorIdentity, "PUT", path, bad), bad)
                  .status
            == 400);
        CHECK(facadeSettings->get().i2pTunnelQuantity == 8);

        CHECK(call(facadePort, "GET", "/settings").status == 404);
        CHECK(call(facadePort, "GET", "/settings").status != 200);

        const std::string restart = "/restart";
        CHECK(callTls(opsPort, facadeCredential.pin, "POST", restart).status == 403);
        CHECK(restarts == 0);
        CHECK(callTls(opsPort, facadeCredential.pin, "POST", restart,
                  signedHeaders(operatorIdentity, "POST", restart, {}))
                  .status
            == 200);
        CHECK(restarts == 1);
    }

    {
        const std::string path = "/new-address";
        CHECK(callTls(opsPort, facadeCredential.pin, "POST", path).status == 403);
        const http::ClientResponse renewed = callTls(opsPort, facadeCredential.pin, "POST", path,
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
    serviceNode.stop();
    return 0;
}
