// Bazarish project (c) 2026
#include "ServiceClient.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <Health.hpp>

#include <bazarish/HttpServer.hpp>
#include <bazarish/Tls.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
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
using namespace bazarish::admin;

namespace {

namespace http = bazarish::http;

using bazarish::nowSeconds;
using bazarish::http::collectAuthHeaders;

}  // namespace

int main()
{
    const Identity panel = Identity::generate();
    const std::filesystem::path keyRoot
        = std::filesystem::temp_directory_path() / "bazarish-panel-client-test";
    std::filesystem::remove_all(keyRoot);
    const bazarish::tls::Credential servicePins = bazarish::tls::selfSigned(keyRoot / "service");
    const bazarish::tls::Credential panelPins = bazarish::tls::selfSigned(keyRoot / "panel");

    std::string quotaUser;
    std::uint64_t quotaBytes = 0;
    std::string searchedQuery;

    http::Server::Options options;
    options.certificate = servicePins.certificate.string();
    options.key = servicePins.key.string();
    options.clientPins = {panelPins.pin};
    options.port = 0;
    http::Server service(options);
    const auto authorize = [&panel](const http::Request& request) -> bool {
        try {
            auth::authorizeRequest(collectAuthHeaders(request), nowSeconds(), request.method,
                request.path, Bytes(request.body.begin(), request.body.end()),
                {panel.fingerprint()});
            return true;
        } catch (const std::exception&) {
            return false;
        }
    };
    const auto refusal = []() {
        http::Response response;
        response.status = 403;
        response.body = "{\"error\":{\"message\":\"denied\"}}";
        return response;
    };
    service.get("/healthz", [&](const http::Request& request) {
        if (!authorize(request)) {
            return refusal();
        }
        http::Response response;
        response.body = health::reportJson("server-core", "9.9.9", 1000, 1000 + 42);
        return response;
    });
    service.put("/v1/account/quota", [&](const http::Request& request) {
        if (!authorize(request)) {
            return refusal();
        }
        const nlohmann::json body = nlohmann::json::parse(request.body);
        quotaUser = body.at("user").get<std::string>();
        quotaBytes = body.at("quotaBytes").get<std::uint64_t>();
        http::Response response;
        response.body = "{\"ok\":true}";
        return response;
    });

    service.get("/v1/account/users", [&](const http::Request& request) {
        if (!authorize(request)) {
            return refusal();
        }
        const auto mark = request.target.find('?');
        searchedQuery = mark == std::string::npos ? std::string() : request.target.substr(mark + 1);
        http::Response response;
        response.body = "{\"users\":[],\"total\":0}";
        return response;
    });

    const int port = service.start();
    CHECK(port > 0);

    ServiceEntry entry;
    entry.name = "core";
    entry.kind = "server-core";
    entry.url = "https://127.0.0.1:" + std::to_string(port);
    entry.pin = servicePins.pin;

    const HealthResult ok = probeHealth(entry, panel, panelPins);
    CHECK(ok.reachable);
    CHECK(ok.status == 200);
    CHECK(ok.version == "9.9.9");
    CHECK(ok.uptime == 42);
    CHECK(ok.ramBytes > 0);

    const Identity stranger = Identity::generate();
    const HealthResult denied = probeHealth(entry, stranger, panelPins);
    CHECK(!denied.reachable);
    CHECK(denied.status == 403);

    const JsonResult quota = callJson(entry, panel, panelPins, "PUT", "/v1/account/quota",
        "{\"user\":\"alicefp\",\"quotaBytes\":5000}");
    CHECK(quota.ok);
    CHECK(quota.status == 200);
    CHECK(quota.body == "{\"ok\":true}");
    CHECK(quotaUser == "alicefp");
    CHECK(quotaBytes == 5000);

    const JsonResult searched
        = callJson(entry, panel, panelPins, "GET", "/v1/account/users?q=abc&state=pending");
    CHECK(searched.ok);
    CHECK(searched.body == "{\"users\":[],\"total\":0}");
    CHECK(searchedQuery == "q=abc&state=pending");

    const JsonResult quotaDenied = callJson(entry, stranger, panelPins, "PUT", "/v1/account/quota",
        "{\"user\":\"alicefp\",\"quotaBytes\":5000}");
    CHECK(!quotaDenied.ok);
    CHECK(quotaDenied.status == 403);

    const bazarish::tls::Credential outsider = bazarish::tls::selfSigned(keyRoot / "outsider");
    CHECK(!probeHealth(entry, panel, outsider).reachable);

    ServiceEntry wrongPin = entry;
    wrongPin.pin = panelPins.pin;
    CHECK(!probeHealth(wrongPin, panel, panelPins).reachable);

    service.stop();
    std::filesystem::remove_all(keyRoot);
    std::printf("TestServiceClient: all checks passed\n");
    return 0;
}
