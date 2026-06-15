// Bazarish project (c) 2026
#include "Portal.hpp"
#include "PortalApi.hpp"
#include "PortalSession.hpp"

#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
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

std::string cookieToken(const std::string& setCookie)
{
    const std::string key = "session=";
    const auto pos = setCookie.find(key);
    if (pos == std::string::npos) {
        return {};
    }
    const auto start = pos + key.size();
    const auto end = setCookie.find(';', start);
    return setCookie.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

void testSessionToken()
{
    const PortalSession session("session-secret", 3600);
    const std::string token = session.issue("user-fingerprint", 1000);
    CHECK(session.verify(token, 1000) == "user-fingerprint");
    CHECK_THROWS(session.verify(token, 1000 + 3601));  // expired
    CHECK_THROWS(session.verify(token + "x", 1000));   // tampered tag
    CHECK_THROWS(session.verify("garbage", 1000));     // malformed
}

void testLoginFlow()
{
    const Identity identity = Identity::generate();

    PortalApiOptions options;
    options.audience = "test-server-fp";
    options.challengeSecret = "challenge-secret";
    options.sessionSecret = "session-secret";
    PortalApi api(options);

    const int port = api.bindToAnyPort("127.0.0.1");
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });

    httplib::Client client("127.0.0.1", port);
    httplib::Result challengeResponse;
    for (int attempt = 0; attempt < 200; ++attempt) {
        challengeResponse = client.Get("/portal/login");
        if (challengeResponse) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(challengeResponse);
    CHECK(challengeResponse->status == 200);
    const std::string challenge
        = nlohmann::json::parse(challengeResponse->body).at("challenge").get<std::string>();

    // Sign the challenge with the Client identity and log in.
    const std::string blob = signLoginBlob(identity, now(), challenge);
    const nlohmann::json loginBody = {{"challenge", challenge}, {"blob", blob}};
    const httplib::Result login
        = client.Post("/portal/login", loginBody.dump(), "application/json");
    CHECK(login);
    CHECK(login->status == 200);
    CHECK(nlohmann::json::parse(login->body).at("userId").get<std::string>()
        == identity.fingerprint());
    const std::string token = cookieToken(login->get_header_value("Set-Cookie"));
    CHECK(!token.empty());

    // The session cookie identifies the user on /portal/me.
    httplib::Headers cookie = {{"Cookie", "session=" + token}};
    const httplib::Result me = client.Get("/portal/me", cookie);
    CHECK(me);
    CHECK(me->status == 200);
    CHECK(nlohmann::json::parse(me->body).at("userId").get<std::string>()
        == identity.fingerprint());

    // No cookie → unauthenticated.
    const httplib::Result anon = client.Get("/portal/me");
    CHECK(anon);
    CHECK(anon->status == 401);

    // A bad signature → login rejected.
    const nlohmann::json badBody = {{"challenge", challenge}, {"blob", "not-a-valid-blob"}};
    const httplib::Result badLogin
        = client.Post("/portal/login", badBody.dump(), "application/json");
    CHECK(badLogin);
    CHECK(badLogin->status == 401);

    api.stop();
    serverThread.join();
}

}  // namespace

int main()
{
    testSessionToken();
    testLoginFlow();
    std::printf("TestPortalApi: all checks passed\n");
    return 0;
}
