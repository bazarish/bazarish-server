// Bazarish project (c) 2026
#include "Facade.hpp"
#include "Load.hpp"

#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <nlohmann/json.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Auth.hpp>

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
    http::Server messaging(backendOptions());
    installBackend(messaging, "messaging");
    const int messagingPort = messaging.start();
    CHECK(messagingPort > 0);

    bazarish::facade::FacadeOptions options;
    options.messagingHost = "127.0.0.1";
    options.messagingPort = messagingPort;
    options.basePath = "/s/secret123";
    const std::filesystem::path configPath
        = std::filesystem::temp_directory_path() / "bazarish-facade-test.json";
    {
        std::ofstream config(configPath);
        config << "{\n  \"basePath\": \"/s/secret123\"\n}\n";
    }
    bazarish::facade::FacadeSettings::Values facadeValues;
    facadeValues.logLevel = "info";
    facadeValues.basePath = options.basePath;
    facadeValues.messagingHost = "127.0.0.1";
    facadeValues.messagingPort = messagingPort;
    facadeValues.listenHost = "127.0.0.1";
    facadeValues.listenPort = 8419;
    facadeValues.opsHost = "127.0.0.1";
    facadeValues.opsPort = 8429;
    facadeValues.i2pEnabled = true;
    facadeValues.i2pDestinations = 1;
    facadeValues.i2pPrivacy = "max";
    facadeValues.i2pTunnelQuantity = 3;
    const auto facadeSettings
        = std::make_shared<bazarish::facade::FacadeSettings>(configPath, facadeValues);
    options.settings = facadeSettings;
    const bazarish::Identity operatorIdentity = bazarish::Identity::generate();
    options.operatorFingerprints = {operatorIdentity.fingerprint()};
    bazarish::facade::Facade facade(options);
    const int facadePort = facade.bind("127.0.0.1", 0);
    CHECK(facadePort > 0);
    const int opsPort = facade.bindOps("127.0.0.1", 0);
    CHECK(opsPort > 0);

    {
        const std::string sealed = "opaque-frame-bytes";
        const http::ClientResponse result
            = call(facadePort, "POST", "/s/secret123/t", {}, sealed);
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("backend") == "messaging");
        CHECK(reply.at("method") == "POST");
        CHECK(reply.at("path") == "/t");
        CHECK(reply.at("body") == sealed);
        CHECK(reply.at("clientHeader") == "");
    }

    for (const char* const gone : {"/s/secret123/v1/messaging/self",
             "/s/secret123/v1/messaging/pending", "/s/secret123/v1/account/registration",
             "/s/secret123/v1/auth/session"}) {
        CHECK(call(facadePort, "POST", gone, {}, "{}").status == 404);
        CHECK(call(facadePort, "GET", gone).status == 404);
    }

    {
        const http::ClientResponse result = call(facadePort, "GET", "/s/secret123/v1/server/card");
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("backend") == "messaging");
        CHECK(reply.at("path") == "/v1/server/card");
    }

    {
        const http::ClientResponse result = call(facadePort, "GET", "/s/wrong/v1/account/resolve?alias=alice");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse result = call(facadePort, "GET", "/s/secret123/v1/other/thing");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse result
            = call(facadePort, "PUT", "/s/secret123/v1/storage/blob", {}, "ciphertext-bytes");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse lookup = call(facadePort, "GET",
            "/s/secret123/v1/account/card?user=alice&key=AAAA");
        CHECK(lookup.status == 404);
        const http::ClientResponse publish = call(facadePort, "POST",
            "/s/secret123/v1/account/card", {}, R"({"card":"AAAA"})");
        CHECK(publish.status == 404);
        const http::ClientResponse unknown
            = call(facadePort, "GET", "/s/secret123/v1/other/thing");
        CHECK(lookup.body == unknown.body);
        CHECK(publish.body == unknown.body);
    }

    {
        const http::ClientResponse result
            = call(facadePort, "PUT", "/s/secret123/v1/storage/quota", {}, "{}");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse result = call(facadePort, "GET", "/s/secret123/b/somecapability");
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
            = call(facadePort, "GET", "/s/secret123/v1/messaging/reseed");
        CHECK(result.status == 404);
    }

    {
        const http::ClientResponse unauthenticated = call(opsPort, "GET", "/healthz");
        CHECK(unauthenticated.status == 403);
        const http::ClientResponse proxied = call(opsPort, "GET", "/s/secret123/v1/messaging/self");
        CHECK(proxied.status == 404);
    }

    {
        const std::string path = "/settings";
        CHECK(call(opsPort, "GET", path).status == 403);

        const http::ClientResponse shown
            = call(opsPort, "GET", path, signedHeaders(operatorIdentity, "GET", path, {}));
        CHECK(shown.status == 200);
        const nlohmann::json values = nlohmann::json::parse(shown.body);
        CHECK(values.at("basePath").get<std::string>() == "/s/secret123");
        CHECK(values.at("i2pTunnelQuantity").get<int>() == 3);

        const std::string body
            = nlohmann::json{{"basePath", "/s/secret456"}, {"i2pTunnelQuantity", 8}}.dump();
        CHECK(call(opsPort, "PUT", path, signedHeaders(operatorIdentity, "PUT", path, body), body)
                  .status
            == 200);
        CHECK(facadeSettings->get().basePath == "/s/secret456");

        std::ifstream written(configPath);
        const nlohmann::json onDisk = nlohmann::json::parse(written);
        CHECK(onDisk.at("basePath").get<std::string>() == "/s/secret456");
        CHECK(onDisk.at("i2p").at("tunnelQuantity").get<int>() == 8);

        const std::string bad = nlohmann::json{{"basePath", "secret/"}}.dump();
        CHECK(call(opsPort, "PUT", path, signedHeaders(operatorIdentity, "PUT", path, bad), bad)
                  .status
            == 400);
        CHECK(facadeSettings->get().basePath == "/s/secret456");

        CHECK(call(facadePort, "GET", "/settings").status == 404);
        CHECK(call(facadePort, "GET", "/s/secret123/settings").status != 200);

        const std::string restart = "/restart";
        CHECK(call(opsPort, "POST", restart,
                  signedHeaders(operatorIdentity, "POST", restart, {}))
                  .status
            == 503);
    }

    facade.stop();
    messaging.stop();
    return 0;
}
