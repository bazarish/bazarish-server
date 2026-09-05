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
#include <thread>

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

// One request against a server under test. A transport failure comes back as
// status 0, so a check on the status covers "nothing answered" too.
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

// Installs echo handlers that report which backend handled the request and
// what it saw, so the test can assert the facade routed and relayed
// transparently. (The server is non-copyable, so configure in place.)
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
    // A capture group makes the pattern a regex route, so it matches every path.
    for (const char* const method : {"GET", "POST", "PUT", "DELETE"}) {
        server.route(method, "(.*)", echo);
    }
}

http::Server::Options backendOptions()
{
    http::Server::Options options;
    options.port = 0;  // the kernel picks one
    return options;
}

}  // namespace

// What the panel reads off the ops socket: three counts and a gauge, and no
// history behind them.
void testLoadSample()
{
    bazarish::facade::Load load;
    constexpr std::int64_t kNow = 1'700'000'000;
    // In the order time hands them over: a ring keeps the newest and lets the
    // rest fall out from under, which is the whole point of it.
    load.record(kNow - 2 * 24 * 3600);  // two days ago: outside every window
    load.record(kNow - 2 * 3600);       // two hours ago: inside the day only
    load.record(kNow - 90);             // a minute and a half ago: day and hour
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

// One operator-signed request: the ops socket takes nothing else.
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
    http::Server account(backendOptions());
    installBackend(messaging, "messaging");
    installBackend(account, "account");
    const int messagingPort = messaging.start();
    const int accountPort = account.start();
    CHECK(messagingPort > 0 && accountPort > 0);

    bazarish::facade::FacadeOptions options;
    options.messagingHost = "127.0.0.1";
    options.messagingPort = messagingPort;
    options.accountHost = "127.0.0.1";
    options.accountPort = accountPort;
    options.basePath = "/s/secret123";
    // The configuration this facade answers for on its ops socket, backed by a
    // file it can write.
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
    facadeValues.accountHost = "127.0.0.1";
    facadeValues.accountPort = accountPort;
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
    const int facadePort = facade.bindToAnyPort("127.0.0.1");
    CHECK(facadePort > 0);
    std::thread facadeThread([&facade]() { (void)facade.listenAfterBind(); });
    const int opsPort = facade.bindOpsToAnyPort("127.0.0.1");
    CHECK(opsPort > 0);
    std::thread opsThread([&facade]() { (void)facade.listenOpsAfterBind(); });


    // The tunnel: one path, one body, relayed byte for byte. Everything a client
    // says now arrives this way, and this program can read none of it - it does
    // not even learn whether this was mail being fetched or an account being
    // managed.
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
        // Nothing rides beside it: no device, no keys, nothing to read.
        CHECK(reply.at("clientHeader") == "");
    }

    // The routes that used to be the client API are not routes any more. A
    // facade that still carried them would carry them in the clear.
    for (const char* const gone : {"/s/secret123/v1/messaging/self",
             "/s/secret123/v1/messaging/pending", "/s/secret123/v1/account/registration",
             "/s/secret123/v1/auth/session"}) {
        CHECK(call(facadePort, "POST", gone, {}, "{}").status == 404);
        CHECK(call(facadePort, "GET", gone).status == 404);
    }

    // The server card is public, identical for everyone who asks, and what a
    // client needs before it can seal anything - so it is served, and serving it
    // says nothing about anybody.
    {
        const http::ClientResponse result = call(facadePort, "GET", "/s/secret123/v1/server/card");
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("backend") == "messaging");
        CHECK(reply.at("path") == "/v1/server/card");
    }

    // Wrong secret base path: rejected, never forwarded.
    {
        const http::ClientResponse result = call(facadePort, "GET", "/s/wrong/v1/account/resolve?alias=alice");
        CHECK(result.status == 404);
    }

    // Correct base path but an unknown route: rejected.
    {
        const http::ClientResponse result = call(facadePort, "GET", "/s/secret123/v1/other/thing");
        CHECK(result.status == 404);
    }

    // Storage paths are no longer routed anywhere: there is no blob service.
    {
        const http::ClientResponse result
            = call(facadePort, "PUT", "/s/secret123/v1/storage/blob", {}, "ciphertext-bytes");
        CHECK(result.status == 404);
    }

    // Publishing a card and looking one up are both client API now, and the
    // client API has exactly one door. Neither is a route here any more, so the
    // rule that used to live in this file - "forwarding a card lookup would let
    // anyone test a contact against every facade they know" - is enforced by the
    // messaging server, which is the only thing that can still tell the two
    // apart. What is left here is the same bare 404 as any other path.
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

    // The operator quota endpoint is never exposed through the facade.
    {
        const http::ClientResponse result
            = call(facadePort, "PUT", "/s/secret123/v1/storage/quota", {}, "{}");
        CHECK(result.status == 404);
    }

    // The I2P-only download path (/b/*) is never exposed through the facade
    // (a clearnet download would leak the fetcher's IP).
    {
        const http::ClientResponse result = call(facadePort, "GET", "/s/secret123/b/somecapability");
        CHECK(result.status == 404);
    }

    // Nothing outside the secret prefix identifies the host as a facade: the
    // reseed a client fetches before it has any transport, the API root and the
    // operator liveness endpoint all answer the same bare 404.
    {
        for (const char* const path : {"/v1/messaging/reseed", "/v1/account/portal", "/healthz",
                 "/"}) {
            const http::ClientResponse result = call(facadePort, "GET", path);
            CHECK(result.status == 404);
            CHECK(result.body.empty());
        }
    }

    // The reseed is reachable under the secret prefix, unauthenticated - the
    // client has no I2P transport yet when it asks for it.
    {
        const http::ClientResponse result = call(facadePort, "GET", "/s/secret123/v1/messaging/reseed");
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("backend") == "messaging");
        CHECK(reply.at("path") == "/v1/messaging/reseed");
    }

    // The ops socket serves /healthz, and only to an operator-signed caller.
    {
        const http::ClientResponse unauthenticated = call(opsPort, "GET", "/healthz");
        CHECK(unauthenticated.status == 403);
        // The proxy routes are not on this socket.
        const http::ClientResponse proxied = call(opsPort, "GET", "/s/secret123/v1/messaging/self");
        CHECK(proxied.status == 404);
    }

    // The facade's own configuration, on the ops socket and operator-signed: the
    // secret prefix included, because otherwise it is the one setting an
    // operator still has to change over SSH.
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

        // A prefix that is not one is refused, and the facade keeps the one it has.
        const std::string bad = nlohmann::json{{"basePath", "secret/"}}.dump();
        CHECK(call(opsPort, "PUT", path, signedHeaders(operatorIdentity, "PUT", path, bad), bad)
                  .status
            == 400);
        CHECK(facadeSettings->get().basePath == "/s/secret456");

        // The settings routes are not on the public socket.
        CHECK(call(facadePort, "GET", "/settings").status == 404);
        CHECK(call(facadePort, "GET", "/s/secret123/settings").status != 200);

        // A facade nobody can restart says so rather than pretending it did.
        const std::string restart = "/restart";
        CHECK(call(opsPort, "POST", restart,
                  signedHeaders(operatorIdentity, "POST", restart, {}))
                  .status
            == 503);
    }

    facade.stop();
    messaging.stop();
    account.stop();
    facadeThread.join();
    opsThread.join();
    return 0;
}
