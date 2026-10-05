// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "PortalApi.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Portal.hpp>
#include <bazarish/ServerDescriptor.hpp>
#include <bazarish/WebAssets.hpp>

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

// The portal's per-run HMAC secrets, as the node mints them.
constexpr std::size_t kSecretBytes = 16;

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

    NodeSettings::Values values;
    values.portalMessage = "Register at the portal";
    values.portalLinks = {"https://portal.example/a", "http://abc.onion/b"};
    values.defaultQuotaBytes = 20 * 1024 * 1024;
    values.requireApproval = true;
    values.registrationMessage = "write to the operator";
    AccountApiOptions options;
    options.serverFingerprint = "server-fp";
    options.settings = std::make_shared<NodeSettings>(fs::path(), values);

    AccountApi api(store, grants, options);
    const int port = api.bind("127.0.0.1", 0);
    std::thread serverThread([&api]() { api.wait(); });

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
    // Two modes and no third: either an operator approves the account or the
    // server takes it as it comes. There is nothing here for a client to solve.
    CHECK(!registration.contains("captcha"));
    CHECK(registration.at("requiresApproval").get<bool>());
    CHECK(registration.at("message").get<std::string>() == "write to the operator");
    CHECK(body.at("quotaBytes").get<std::uint64_t>() == 20 * 1024 * 1024);

    api.stop();
    serverThread.join();
    fs::remove_all(root);
}


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

// The whole portal: prove a key, and that is the account. There is no second
// step and no account area behind it.
void testWebFlow()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-portal-web-" + toHex(randomBytes(8)));
    GrantStore grants(root);

    const Identity identity = Identity::generate();
    constexpr std::uint64_t kQuota = 20 * 1024 * 1024;
    NodeSettings::Values values;
    values.loginConsumer
        = LoginConsumer{"Bazarish service node", "http://node.example", "Account owner"};
    values.defaultQuotaBytes = kQuota;
    // The descriptor the cabinet hands over is built from these, so the page and
    // the panel can never show different ways in.
    values.facades = {"http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr.b32.i2p/s"};
    PortalApiOptions options;
    options.serverFingerprint = "service-node-fingerprint";
    options.challengeSecret = toHex(randomBytes(kSecretBytes));
    options.sessionSecret = toHex(randomBytes(kSecretBytes));
    options.assetsDirectory = BAZARISH_PORTAL_ASSETS_DIR;
    options.settings = std::make_shared<NodeSettings>(fs::path(), values);
    const std::string descriptor
        = encodeServerDescriptor({options.serverFingerprint, values.facades, values.reseeds});

    std::string deleted;
    options.deleteAccount = [&](const std::string& user) {
        deleted = user;
        grants.erase(user);
    };
    // The mailbox figures come from the messaging server; the portal only shows
    // what it is handed.
    options.accountUsage = [](const std::string&) -> std::optional<MailboxUsage> {
        return MailboxUsage{1024, kQuota, 2};
    };

    PortalApi portal(options, grants);
    const int port = portal.bind("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread portalThread([&portal]() { portal.wait(); });

    http::ClientResponse page;
    for (int attempt = 0; attempt < 200; ++attempt) {
        page = call(port, "GET", "/");
        if (page.status != 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(page.status == 200);
    // Signed out: the key step is the only one, and nothing is granted yet.
    CHECK(page.body.find("sign in with your key") != std::string::npos);

    // --- the same page, in every language this face offers ---
    //
    // Nothing is asserted about the words themselves; what is asserted is that
    // the page is drawn whole in each language, which a key nobody wrote a text
    // for would break.
    for (const char* const code : {"en", "ru", "es", "zh", "ar"}) {
        const http::ClientResponse drawn
            = call(port, "GET", "/", {{"Cookie", "lang=" + std::string(code)}});
        CHECK(drawn.status == 200);
        CHECK(drawn.body.find("{{t.") == std::string::npos);
        CHECK(drawn.body.find("{{") == std::string::npos);
        CHECK(drawn.body.find("lang=\"" + std::string(code) + "\"") != std::string::npos);
        // Arabic is the one that reads the other way.
        const std::string direction = std::string(code) == "ar" ? "rtl" : "ltr";
        CHECK(drawn.body.find("dir=\"" + direction + "\"") != std::string::npos);
        CHECK(drawn.body.find("class=\"lang-one is-on\"") != std::string::npos);
    }
    // A cookie naming a language this face does not serve is answered in the
    // first one rather than refused.
    const http::ClientResponse stranger = call(port, "GET", "/", {{"Cookie", "lang=de"}});
    CHECK(stranger.status == 200);
    CHECK(stranger.body.find("lang=\"en\"") != std::string::npos);

    // Clicking a language leaves the cookie and comes back to the page it was
    // clicked on, and is not a way to send somebody somewhere else.
    const http::ClientResponse switched = call(port, "GET", "/lang/ru?back=%2Fportal%2Fme");
    CHECK(switched.status == 303);
    CHECK(switched.headers.at("location") == "/portal/me");
    CHECK(switched.headers.at("set-cookie").find("lang=ru;") == 0);
    const http::ClientResponse away
        = call(port, "GET", "/lang/ru?back=https%3A%2F%2Fevil.example");
    CHECK(away.status == 303);
    CHECK(away.headers.at("location") == "/");
    const http::ClientResponse unknown = call(port, "GET", "/lang/de?back=%2F");
    CHECK(unknown.status == 303);
    CHECK(unknown.headers.count("set-cookie") == 0);

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

    // Signing in was the registration: the page that follows it states the
    // account, and there is no step in between to post.
    const http::ClientResponse asked = call(port, "GET", "/", {{"Cookie", "session=" + cookie}});
    CHECK(asked.status == 200);
    CHECK(asked.body.find(identity.fingerprint()) != std::string::npos);
    CHECK(postForm(port, "/register", "", "session=" + cookie).status == 404);
    const std::optional<GrantStore::SubscriptionGrant> grant
        = grants.peekSubscription(identity.fingerprint());
    CHECK(grant.has_value());
    CHECK(grant->quotaBytes == kQuota);

    // Afterwards the page states the account and hands over the descriptor, with
    // what the messaging server holds for it.
    const http::ClientResponse done = call(port, "GET", "/", {{"Cookie", "session=" + cookie}});
    CHECK(done.status == 200);
    CHECK(done.body.find("registered") != std::string::npos);
    CHECK(done.body.find(htmlEscape(descriptor)) != std::string::npos);
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

    // A banned key is told so and gets nothing else: no account, no terms.
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
        // Signing in registers everyone else; a ban is what stops it.
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
