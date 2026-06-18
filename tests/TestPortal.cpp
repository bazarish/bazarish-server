// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "Portal.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
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

#define CHECK_THROWS(expression)                                                       \
    do {                                                                               \
        bool thrown = false;                                                           \
        try {                                                                          \
            (void)(expression);                                                        \
        } catch (const std::exception&) {                                              \
            thrown = true;                                                             \
        }                                                                              \
        if (!thrown) {                                                                 \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d\n", __FILE__, __LINE__); \
            std::exit(1);                                                              \
        }                                                                              \
    } while (false)

using namespace bazarish;
using namespace bazarish::service;

namespace {

std::int64_t now()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Sign-in-with-key verifies a client-shaped blob and recovers the fingerprint,
// rejecting a wrong challenge, a stale timestamp and tampering.
void testLoginVerification()
{
    const Identity identity = Identity::generate();
    const std::string challenge = "portal-challenge-abc";
    const std::string blob = signLoginBlob(identity, now(), challenge);

    CHECK(verifyLoginBlob(blob, now(), challenge) == identity.fingerprint());
    CHECK_THROWS(verifyLoginBlob(blob, now(), "a-different-challenge"));
    CHECK_THROWS(verifyLoginBlob(blob, now() + 100000, challenge));
    CHECK_THROWS(verifyLoginBlob(blob + "x", now(), challenge));
}

// GET /v1/account/portal reflects the configured onboarding offer.
void testPortalDiscovery()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-portal-" + toHex(randomBytes(8)));
    SubscriptionStore store(root);
    GrantStore grants(root);

    AccountApiOptions options;
    options.serverFingerprint = "server-fp";
    options.portalMessage = "Register at the portal";
    options.portalLinks = {"https://portal.example/a", "http://abc.onion/b"};
    options.settlementCurrency = "XMR";
    options.freeRegistrationCaptcha = true;
    options.i2pDestService = {true, "500000000", 30};        // monthly
    options.defaultQuotaBytes = 10 * 1024 * 1024;            // free minimum
    options.storagePlan = {true, 5ULL * 1024 * 1024 * 1024, "300000000", 30};  // 5 GiB / month

    AccountApi api(store, grants, options);
    const int port = api.bindToAnyPort("127.0.0.1");
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });

    httplib::Client client("127.0.0.1", port);
    httplib::Result response;
    for (int attempt = 0; attempt < 200; ++attempt) {
        response = client.Get("/v1/account/portal");
        if (response) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(response);
    CHECK(response->status == 200);

    const nlohmann::json body = nlohmann::json::parse(response->body);
    CHECK(body.at("message").get<std::string>() == "Register at the portal");
    CHECK(body.at("links").size() == 2);
    const nlohmann::json& services = body.at("services");
    CHECK(services.at("freeRegistration").at("enabled").get<bool>());
    CHECK(services.at("freeRegistration").at("captcha").get<bool>());
    CHECK(services.at("i2pDest").at("periodDays").get<std::int64_t>() == 30);    // monthly
    CHECK(services.at("i2pDest").at("currency").get<std::string>() == "XMR");
    const nlohmann::json& storage = services.at("storage");
    CHECK(storage.at("freeQuotaBytes").get<std::uint64_t>() == 10 * 1024 * 1024);
    CHECK(storage.at("paid").at("enabled").get<bool>());
    CHECK(storage.at("paid").at("quotaBytes").get<std::uint64_t>() == 5ULL * 1024 * 1024 * 1024);
    CHECK(storage.at("paid").at("priceAtomic").get<std::string>() == "300000000");
    CHECK(storage.at("paid").at("periodDays").get<std::int64_t>() == 30);

    api.stop();
    serverThread.join();
    fs::remove_all(root);
}

}  // namespace

int main()
{
    testLoginVerification();
    testPortalDiscovery();
    std::printf("TestPortal: all checks passed\n");
    return 0;
}
