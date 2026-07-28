// Bazarish project (c) 2026
#include "QuotaPublisher.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
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
using namespace bazarish::service;

int main()
{
    // The node's signing identity; the stub backend authorises exactly this
    // fingerprint, verifying the request signature (no shared secret).
    const Identity nodeIdentity = Identity::generate();

    const auto authorized = [&nodeIdentity](const httplib::Request& request) -> bool {
        auth::Headers headers;
        for (const char* const name : {auth::kHeaderKeys, auth::kHeaderTimestamp,
                 auth::kHeaderSignatureClassical, auth::kHeaderSignaturePq}) {
            if (request.has_header(name)) {
                headers[name] = request.get_header_value(name);
            }
        }
        try {
            auth::authorizeRequest(headers, static_cast<std::int64_t>(std::time(nullptr)),
                request.method, request.path, Bytes(request.body.begin(), request.body.end()),
                {nodeIdentity.fingerprint()});
            return true;
        } catch (const std::exception&) {
            return false;
        }
    };

    std::string receivedBody;
    std::string storagePath;  // set when the blob-store endpoint is hit
    httplib::Server stub;
    stub.Put("/v1/messaging/quota",
        [&](const httplib::Request& request, httplib::Response& response) {
            if (!authorized(request)) {
                response.status = 403;
                return;
            }
            receivedBody = request.body;
            response.set_content("{\"ok\":true}", "application/json");
        });
    stub.Put("/v1/storage/quota",
        [&](const httplib::Request& request, httplib::Response& response) {
            if (!authorized(request)) {
                response.status = 403;
                return;
            }
            storagePath = request.body;
            response.set_content("{\"ok\":true}", "application/json");
        });

    const int port = stub.bind_to_any_port("127.0.0.1");
    std::thread serverThread([&stub]() { (void)stub.listen_after_bind(); });
    while (!stub.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    const std::string user = Identity::generate().fingerprint();
    const std::string url = "http://127.0.0.1:" + std::to_string(port);

    // A push signed by the authorised identity delivers the user and quota.
    const QuotaPublisher publisher(url, nodeIdentity);
    CHECK(publisher.publish(user, 5368709120ULL));
    const nlohmann::json body = nlohmann::json::parse(receivedBody);
    CHECK(body.at("user").get<std::string>() == user);
    CHECK(body.at("quotaBytes").get<std::uint64_t>() == 5368709120ULL);

    // A push signed by an unauthorised identity is rejected by the server -> false.
    const Identity stranger = Identity::generate();
    const QuotaPublisher wrongSigner(url, stranger);
    CHECK(!wrongSigner.publish(user, 1));

    // A custom endpoint path targets the blob store's quota endpoint.
    const QuotaPublisher blobPublisher(url, nodeIdentity, "/v1/storage/quota");
    CHECK(blobPublisher.publish(user, 42ULL));
    const nlohmann::json storageBody = nlohmann::json::parse(storagePath);
    CHECK(storageBody.at("user").get<std::string>() == user);
    CHECK(storageBody.at("quotaBytes").get<std::uint64_t>() == 42ULL);

    // Not configured (no base URL) -> no-op false, no request made.
    const QuotaPublisher disabled("", nodeIdentity);
    CHECK(!disabled.publish(user, 1));

    stub.stop();
    serverThread.join();
    std::printf("TestQuotaPublisher: all checks passed\n");
    return 0;
}
