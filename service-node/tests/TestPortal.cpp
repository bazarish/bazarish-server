// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "PortalApi.hpp"
#include <bazarish/Portal.hpp>
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <optional>
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
    options.defaultQuotaBytes = 20 * 1024 * 1024;
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
    CHECK(body.at("quotaBytes").get<std::uint64_t>() == 20 * 1024 * 1024);

    api.stop();
    serverThread.join();
    fs::remove_all(root);
}


// A captcha the test can answer: what is under test here is the portal's flow,
// not the drawing.
class StubCaptcha : public Captcha {
public:
    static constexpr const char* kId = "stub-captcha-id";
    static constexpr const char* kAnswer = "42";
    static constexpr const char* kBody = "<svg id=\"stub-captcha\"></svg>";

    std::string name() const override { return "stub"; }

    CaptchaChallenge issue(std::int64_t) override
    {
        return CaptchaChallenge{kId, "image/svg+xml", kBody};
    }

    bool verify(const std::string& id, const std::string& answer, std::int64_t) override
    {
        return id == kId && answer == kAnswer;
    }
};

std::string urlEncoded(const std::string& text)
{
    static const char* const kHexDigits = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : text) {
        if (std::isalnum(c) != 0 || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHexDigits[c >> 4]);
            out.push_back(kHexDigits[c & 0x0F]);
        }
    }
    return out;
}

// One form post, as a browser sends it.
http::ClientResponse postForm(const int port, const std::string& path, const std::string& body,
    const std::string& cookie = {})
{
    http::ClientRequest request;
    request.method = "POST";
    request.target = path;
    request.body = body;
    request.contentType = "application/x-www-form-urlencoded";
    if (!cookie.empty()) {
        request.headers["Cookie"] = cookie;
    }
    return http::request("127.0.0.1", port, request, {});
}

std::string between(const std::string& text, const std::string& open, const std::string& close)
{
    const auto start = text.find(open);
    CHECK(start != std::string::npos);
    const auto from = start + open.size();
    const auto end = text.find(close, from);
    CHECK(end != std::string::npos);
    return text.substr(from, end - from);
}

// The whole portal: prove a key, read a captcha, and that is the account. There
// is no third step and no account area behind it.
void testWebFlow()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-portal-web-" + toHex(randomBytes(8)));
    GrantStore grants(root);
    StubCaptcha captcha;

    const Identity identity = Identity::generate();
    PortalApiOptions options;
    options.serverFingerprint = "service-node-fingerprint";
    options.consumer = LoginConsumer{"Bazarish service node", "http://node.example", "Account owner"};
    options.serverDescriptor = "bazarish-descriptor-for-the-test";
    options.challengeSecret = toHex(randomBytes(16));
    options.sessionSecret = toHex(randomBytes(16));
    options.assetsDirectory = BAZARISH_PORTAL_ASSETS_DIR;
    options.requireCaptcha = true;

    std::string deleted;
    options.deleteAccount = [&](const std::string& user) {
        deleted = user;
        grants.erase(user);
    };
    // The mailbox figures come from the messaging server; the portal only shows
    // what it is handed.
    options.accountUsage = [](const std::string&) {
        return PortalApiOptions::Usage{1024, 20 * 1024 * 1024, 2};
    };

    PortalApi portal(options, captcha, grants);
    const int port = portal.bindToAnyPort("127.0.0.1");
    CHECK(port > 0);
    std::thread portalThread([&portal]() { (void)portal.listenAfterBind(); });

    http::ClientResponse page;
    for (int attempt = 0; attempt < 200; ++attempt) {
        page = call(port, "GET", "/");
        if (page.status != 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(page.status == 200);
    // Signed out: the key step is the live one, and no captcha is given away.
    CHECK(page.body.find("sign in with your key") != std::string::npos);
    CHECK(page.body.find(StubCaptcha::kBody) == std::string::npos);

    // The portal's own files are served beside the page.
    const http::ClientResponse style = call(port, "GET", "/style.css");
    CHECK(style.status == 200);
    CHECK(style.contentType.find("text/css") != std::string::npos);
    CHECK(call(port, "GET", "/../CMakeLists.txt").status == 404);

    // The script is an extra, not a dependency: the page above already carries
    // the whole flow, and the script only adds a copy button on top of it.
    const http::ClientResponse script = call(port, "GET", "/portal.js");
    CHECK(script.status == 200);
    CHECK(script.contentType.find("javascript") != std::string::npos);

    // Every Bazarish face draws from one kit and is lit by a phosphor of its
    // own, so that two of them open side by side are not read as one. This one
    // is the cyan of a messaging server.
    CHECK(style.body.find("--bz-key: #14e2ff") != std::string::npos);

    const std::string challenge = between(page.body, "<pre class=\"copy\">", "</pre>");
    const std::string blob = signLoginBlob(identity, now(), challenge);
    const http::ClientResponse signedIn = postForm(port, "/login",
        "challenge=" + urlEncoded(challenge) + "&blob=" + urlEncoded(blob));
    CHECK(signedIn.status == 303);
    const std::string cookie = between(signedIn.headers.at("set-cookie") + ";", "session=", ";");
    CHECK(!cookie.empty());

    // Signed in and unregistered: the captcha is the page.
    const http::ClientResponse asked = call(port, "GET", "/", {{"Cookie", "session=" + cookie}});
    CHECK(asked.status == 200);
    CHECK(asked.body.find(StubCaptcha::kBody) != std::string::npos);
    CHECK(asked.body.find(identity.fingerprint()) != std::string::npos);

    // A wrong code registers nobody.
    const http::ClientResponse refused = postForm(port, "/register",
        std::string("captchaId=") + StubCaptcha::kId + "&captchaAnswer=nope",
        "session=" + cookie);
    CHECK(refused.status == 403);
    CHECK(!grants.peekSubscription(identity.fingerprint()).has_value());

    // The right code is the registration itself.
    const http::ClientResponse registered = postForm(port, "/register",
        std::string("captchaId=") + StubCaptcha::kId + "&captchaAnswer=" + StubCaptcha::kAnswer,
        "session=" + cookie);
    CHECK(registered.status == 303);
    const std::optional<GrantStore::SubscriptionGrant> grant
        = grants.peekSubscription(identity.fingerprint());
    CHECK(grant.has_value());
    CHECK(grant->quotaBytes == options.defaultQuotaBytes);

    // Afterwards the page states the account and hands over the descriptor, with
    // what the messaging server holds for it.
    const http::ClientResponse done = call(port, "GET", "/", {{"Cookie", "session=" + cookie}});
    CHECK(done.status == 200);
    CHECK(done.body.find("registered") != std::string::npos);
    CHECK(done.body.find(options.serverDescriptor) != std::string::npos);
    CHECK(done.body.find(StubCaptcha::kBody) == std::string::npos);
    CHECK(done.body.find("1.0 KiB of 20 MiB") != std::string::npos);
    CHECK(done.body.find("<span>Devices</span>2") != std::string::npos);

    // Nothing a visitor receives carries a note to whoever wrote it.
    CHECK(page.body.find("<!--") == std::string::npos);
    CHECK(asked.body.find("<!--") == std::string::npos);
    CHECK(done.body.find("<!--") == std::string::npos);
    CHECK(script.body.find("console.") == std::string::npos);

    // An account's owner can end it from the browser: one page to confirm, one
    // post to do it.
    {
        const http::ClientResponse asked
            = postForm(port, "/delete", "", "session=" + cookie);
        CHECK(asked.status == 200);
        CHECK(asked.body.find("This cannot be undone") != std::string::npos);
        CHECK(grants.peekSubscription(identity.fingerprint()).has_value());

        const http::ClientResponse done
            = postForm(port, "/delete", "confirm=yes", "session=" + cookie);
        CHECK(done.status == 303);
        CHECK(deleted == identity.fingerprint());
        CHECK(!grants.peekSubscription(identity.fingerprint()).has_value());
    }

    // A banned key is told so and gets nothing else: no captcha, no terms.
    {
        const Identity refused = Identity::generate();
        grants.ban(refused.fingerprint(), "Spam", now());
        const http::ClientResponse page = call(port, "GET", "/");
        const std::string challenge = between(page.body, "<pre class=\"copy\">", "</pre>");
        const http::ClientResponse signedIn = postForm(port, "/login",
            "challenge=" + urlEncoded(challenge) + "&blob="
                + urlEncoded(signLoginBlob(refused, now(), challenge)));
        CHECK(signedIn.status == 303);
        const std::string banned
            = between(signedIn.headers.at("set-cookie") + ";", "session=", ";");

        const http::ClientResponse shown
            = call(port, "GET", "/", {{"Cookie", "session=" + banned}});
        CHECK(shown.status == 200);
        CHECK(shown.body.find("Spam") != std::string::npos);
        CHECK(shown.body.find(StubCaptcha::kBody) == std::string::npos);

        const http::ClientResponse tried = postForm(port, "/register",
            std::string("captchaId=") + StubCaptcha::kId + "&captchaAnswer="
                + StubCaptcha::kAnswer,
            "session=" + banned);
        CHECK(tried.status == 403);
        CHECK(!grants.peekSubscription(refused.fingerprint()).has_value());
    }

    portal.stop();
    portalThread.join();
    fs::remove_all(root);
}

}  // namespace

int main()
{
    testLoginVerification();
    testPortalDiscovery();
    testWebFlow();
    std::printf("TestPortal: all checks passed\n");
    return 0;
}
