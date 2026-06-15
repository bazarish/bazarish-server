// Bazarish project (c) 2026
#include "QuotaPublisher.hpp"

#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
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

using namespace bazarish;
using namespace bazarish::service;

int main()
{
    std::string receivedBody;
    std::string storagePath;  // set when the blob-store endpoint is hit
    httplib::Server stub;
    stub.Put("/v1/messaging/quota", [&](const httplib::Request& request, httplib::Response& response) {
        if (request.get_header_value("X-Operator-Secret") != "op-secret") {
            response.status = 403;
            return;
        }
        receivedBody = request.body;
        response.set_content("{\"ok\":true}", "application/json");
    });
    stub.Put("/v1/storage/quota", [&](const httplib::Request& request, httplib::Response& response) {
        if (request.get_header_value("X-Operator-Secret") != "op-secret") {
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

    // A correctly-authorised push delivers the user and quota.
    const QuotaPublisher publisher(url, "op-secret");
    CHECK(publisher.publish(user, 5368709120ULL));
    const nlohmann::json body = nlohmann::json::parse(receivedBody);
    CHECK(body.at("user").get<std::string>() == user);
    CHECK(body.at("quotaBytes").get<std::uint64_t>() == 5368709120ULL);

    // A wrong operator secret is rejected by the server → false.
    const QuotaPublisher wrongSecret(url, "nope");
    CHECK(!wrongSecret.publish(user, 1));

    // A custom endpoint path targets the blob store's quota endpoint.
    const QuotaPublisher blobPublisher(url, "op-secret", "/v1/storage/quota");
    CHECK(blobPublisher.publish(user, 42ULL));
    const nlohmann::json storageBody = nlohmann::json::parse(storagePath);
    CHECK(storageBody.at("user").get<std::string>() == user);
    CHECK(storageBody.at("quotaBytes").get<std::uint64_t>() == 42ULL);

    // Not configured (no base URL) → no-op false, no request made.
    const QuotaPublisher disabled("", "op-secret");
    CHECK(!disabled.publish(user, 1));

    stub.stop();
    serverThread.join();
    std::printf("TestQuotaPublisher: all checks passed\n");
    return 0;
}
