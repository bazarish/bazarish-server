// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include <bazarish/Portal.hpp>
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
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

namespace http = bazarish::http;

using Headers = std::map<std::string, std::string>;

// One request against the API under test. A transport failure comes back as
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
    options.freeRegistrationCaptcha = true;
    options.defaultQuotaBytes = 50 * 1024 * 1024;
    options.registration = AccountApiOptions::Registration::eApproval;
    options.registrationMessage = "write to the operator";

    AccountApi api(store, grants, options);
    const int port = api.bindToAnyPort("127.0.0.1");
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });

    http::ClientResponse response;
    for (int attempt = 0; attempt < 200; ++attempt) {
        response = call(port, "GET", "/v1/account/portal");
        if (response.status != 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(response.status == 200);

    const nlohmann::json body = nlohmann::json::parse(response.body);
    CHECK(body.at("message").get<std::string>() == "Register at the portal");
    CHECK(body.at("links").size() == 2);
    // Nothing is for sale, so there is no service catalogue - only the terms of
    // registration and the one quota everybody gets.
    CHECK(!body.contains("services"));
    const nlohmann::json& registration = body.at("registration");
    CHECK(registration.at("captcha").get<bool>());
    CHECK(registration.at("requiresApproval").get<bool>());
    CHECK(registration.at("message").get<std::string>() == "write to the operator");
    CHECK(body.at("quotaBytes").get<std::uint64_t>() == 50 * 1024 * 1024);

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
