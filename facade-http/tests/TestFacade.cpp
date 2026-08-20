// Bazarish project (c) 2026
#include "Facade.hpp"

#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
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

int main()
{
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
    bazarish::facade::Facade facade(options);
    const int facadePort = facade.bindToAnyPort("127.0.0.1");
    CHECK(facadePort > 0);
    std::thread facadeThread([&facade]() { (void)facade.listenAfterBind(); });
    const int opsPort = facade.bindOpsToAnyPort("127.0.0.1");
    CHECK(opsPort > 0);
    std::thread opsThread([&facade]() { (void)facade.listenOpsAfterBind(); });


    // Messaging route: body, method, client header and stripped path relayed.
    {
        const Headers headers = {{"X-Bazarish-Client", "dev1"}};
        const http::ClientResponse result = call(facadePort, "POST", "/s/secret123/v1/messaging/send", headers,
            "envelope-bytes");
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("backend") == "messaging");
        CHECK(reply.at("method") == "POST");
        CHECK(reply.at("path") == "/v1/messaging/send");
        CHECK(reply.at("body") == "envelope-bytes");
        CHECK(reply.at("clientHeader") == "dev1");
    }

    // Account route, with a preserved query string.
    {
        const http::ClientResponse result
            = call(facadePort, "GET", "/s/secret123/v1/account/resolve?alias=alice");
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("backend") == "account");
        CHECK(reply.at("path") == "/v1/account/resolve");
        CHECK(reply.at("alias") == "alice");
    }

    // DELETE is relayed too.
    {
        const http::ClientResponse result
            = call(facadePort, "DELETE", "/s/secret123/v1/account/alias", {}, "{}");
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("method") == "DELETE");
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
        const http::ClientResponse proxied = call(opsPort, "GET", "/s/secret123/v1/messaging/send");
        CHECK(proxied.status == 404);
    }

    facade.stop();
    messaging.stop();
    account.stop();
    facadeThread.join();
    opsThread.join();
    return 0;
}
