// Bazarish project (c) 2026
#include "ServiceClient.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Health.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
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
using namespace bazarish::admin;

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

auth::Headers collectAuthHeaders(const httplib::Request& request)
{
    auth::Headers headers;
    for (const char* const name : {auth::kHeaderKeys, auth::kHeaderTimestamp,
             auth::kHeaderSignatureClassical, auth::kHeaderSignaturePq}) {
        if (request.has_header(name)) {
            headers[name] = request.get_header_value(name);
        }
    }
    return headers;
}

}  // namespace

int main()
{
    // The panel's identity; the fake service authorises exactly this fingerprint.
    const Identity panel = Identity::generate();

    std::string quotaUser;
    std::uint64_t quotaBytes = 0;

    httplib::Server service;
    const auto authorize = [&panel](const httplib::Request& request) -> bool {
        try {
            auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                request.path, Bytes(request.body.begin(), request.body.end()),
                {panel.fingerprint()});
            return true;
        } catch (const std::exception&) {
            return false;
        }
    };
    service.Get("/healthz", [&](const httplib::Request& request, httplib::Response& response) {
        if (!authorize(request)) {
            response.status = 403;
            response.set_content("{\"error\":{\"message\":\"denied\"}}", "application/json");
            return;
        }
        response.set_content(
            health::reportJson("server-core", "9.9.9", 1000, 1000 + 42), "application/json");
    });
    service.Put("/v1/messaging/quota",
        [&](const httplib::Request& request, httplib::Response& response) {
            if (!authorize(request)) {
                response.status = 403;
                response.set_content("{\"error\":{\"message\":\"denied\"}}", "application/json");
                return;
            }
            const nlohmann::json body = nlohmann::json::parse(request.body);
            quotaUser = body.at("user").get<std::string>();
            quotaBytes = body.at("quotaBytes").get<std::uint64_t>();
            response.set_content("{\"ok\":true}", "application/json");
        });

    const int port = service.bind_to_any_port("127.0.0.1");
    CHECK(port > 0);
    std::thread serverThread([&service]() { (void)service.listen_after_bind(); });
    while (!service.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    ServiceEntry entry;
    entry.name = "core";
    entry.kind = "server-core";
    entry.url = "http://127.0.0.1:" + std::to_string(port);

    // A probe signed by the authorised panel identity returns parsed health.
    const HealthResult ok = probeHealth(entry, panel);
    CHECK(ok.reachable);
    CHECK(ok.status == 200);
    CHECK(ok.version == "9.9.9");
    CHECK(ok.uptime == 42);
    CHECK(ok.ramBytes > 0);

    // A probe signed by a non-authorised identity is rejected (service is up).
    const Identity stranger = Identity::generate();
    const HealthResult denied = probeHealth(entry, stranger);
    CHECK(!denied.reachable);
    CHECK(denied.status == 403);

    // An operator action is signed and delivers the body.
    const OpResult quota = setQuota(entry, panel, "alicefp", 5000);
    CHECK(quota.ok);
    CHECK(quotaUser == "alicefp");
    CHECK(quotaBytes == 5000);

    // The same action from a non-authorised identity is rejected.
    const OpResult quotaDenied = setQuota(entry, stranger, "alicefp", 5000);
    CHECK(!quotaDenied.ok);
    CHECK(quotaDenied.status == 403);

    service.stop();
    serverThread.join();
    std::printf("TestServiceClient: all checks passed\n");
    return 0;
}
