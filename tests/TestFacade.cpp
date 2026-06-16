// Bazarish project (c) 2026
#include "Facade.hpp"

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
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

namespace {

// Installs echo handlers that report which backend handled the request and
// what it saw, so the test can assert the facade routed and relayed
// transparently. (httplib::Server is non-copyable, so configure in place.)
void installBackend(httplib::Server& server, const std::string& name)
{
    const auto echo = [name](const httplib::Request& request, httplib::Response& response) {
        nlohmann::json body = {
            {"backend", name},
            {"method", request.method},
            {"path", request.path},
            {"body", request.body},
            {"clientHeader", request.get_header_value("X-Bazarish-Client")},
            {"alias", request.get_param_value("alias")},
        };
        response.set_content(body.dump(), "application/json");
    };
    server.Get(".*", echo);
    server.Post(".*", echo);
    server.Delete(".*", echo);
    server.Put(".*", echo);
}

}  // namespace

int main()
{
    httplib::Server messaging;
    httplib::Server account;
    httplib::Server blob;
    installBackend(messaging, "messaging");
    installBackend(account, "account");
    installBackend(blob, "blob");
    const int messagingPort = messaging.bind_to_any_port("127.0.0.1");
    const int accountPort = account.bind_to_any_port("127.0.0.1");
    const int blobPort = blob.bind_to_any_port("127.0.0.1");
    CHECK(messagingPort > 0 && accountPort > 0 && blobPort > 0);
    std::thread messagingThread([&messaging]() { (void)messaging.listen_after_bind(); });
    std::thread accountThread([&account]() { (void)account.listen_after_bind(); });
    std::thread blobThread([&blob]() { (void)blob.listen_after_bind(); });

    bazarish::facade::FacadeOptions options;
    options.messagingHost = "127.0.0.1";
    options.messagingPort = messagingPort;
    options.accountHost = "127.0.0.1";
    options.accountPort = accountPort;
    options.blobStorageHost = "127.0.0.1";
    options.blobStoragePort = blobPort;
    options.basePath = "/s/secret123";
    bazarish::facade::Facade facade(options);
    const int facadePort = facade.bindToAnyPort("127.0.0.1");
    CHECK(facadePort > 0);
    std::thread facadeThread([&facade]() { (void)facade.listenAfterBind(); });

    httplib::Client client("127.0.0.1", facadePort);
    CHECK(client.is_valid());

    // Messaging route: body, method, client header and stripped path relayed.
    {
        httplib::Headers headers = {{"X-Bazarish-Client", "dev1"}};
        const httplib::Result result = client.Post("/s/secret123/v1/messaging/send", headers,
            "envelope-bytes", "application/json");
        CHECK(result && result->status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result->body);
        CHECK(reply.at("backend") == "messaging");
        CHECK(reply.at("method") == "POST");
        CHECK(reply.at("path") == "/v1/messaging/send");
        CHECK(reply.at("body") == "envelope-bytes");
        CHECK(reply.at("clientHeader") == "dev1");
    }

    // Account route, with a preserved query string.
    {
        const httplib::Result result
            = client.Get("/s/secret123/v1/account/resolve?alias=alice");
        CHECK(result && result->status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result->body);
        CHECK(reply.at("backend") == "account");
        CHECK(reply.at("path") == "/v1/account/resolve");
        CHECK(reply.at("alias") == "alice");
    }

    // DELETE is relayed too.
    {
        const httplib::Result result
            = client.Delete("/s/secret123/v1/account/alias", "{}", "application/json");
        CHECK(result && result->status == 200);
        CHECK(nlohmann::json::parse(result->body).at("method") == "DELETE");
    }

    // Wrong secret base path: rejected, never forwarded.
    {
        const httplib::Result result = client.Get("/s/wrong/v1/account/resolve?alias=alice");
        CHECK(result && result->status == 404);
    }

    // Correct base path but an unknown route: rejected.
    {
        const httplib::Result result = client.Get("/s/secret123/v1/other/thing");
        CHECK(result && result->status == 404);
    }

    // Blob upload (PUT) is forwarded to the blob backend.
    {
        const httplib::Result result = client.Put(
            "/s/secret123/v1/storage/blob", "ciphertext-bytes", "application/octet-stream");
        CHECK(result && result->status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result->body);
        CHECK(reply.at("backend") == "blob");
        CHECK(reply.at("method") == "PUT");
        CHECK(reply.at("path") == "/v1/storage/blob");
        CHECK(reply.at("body") == "ciphertext-bytes");
    }

    // A large blob upload streams through (spooled, then content-provided over
    // several chunks) without the facade buffering it whole — the backend
    // receives the exact bytes.
    {
        const std::string big(200000, 'Z');
        const httplib::Result result
            = client.Put("/s/secret123/v1/storage/blob", big, "application/octet-stream");
        CHECK(result && result->status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result->body);
        CHECK(reply.at("backend") == "blob");
        CHECK(reply.at("method") == "PUT");
        CHECK(reply.at("body").get<std::string>() == big);
    }

    // The operator quota endpoint is never exposed through the facade.
    {
        const httplib::Result result = client.Put(
            "/s/secret123/v1/storage/quota", "{}", "application/json");
        CHECK(result && result->status == 404);
    }

    // The I2P-only download path (/b/*) is never exposed through the facade
    // (a clearnet download would leak the fetcher's IP).
    {
        const httplib::Result result = client.Get("/s/secret123/b/somecapability");
        CHECK(result && result->status == 404);
    }

    facade.stop();
    messaging.stop();
    account.stop();
    blob.stop();
    facadeThread.join();
    messagingThread.join();
    accountThread.join();
    blobThread.join();
    return 0;
}
