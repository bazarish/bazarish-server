// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "PortalApi.hpp"
#include "SubscriptionStore.hpp"
#include "HttpTestUtil.hpp"
#include "TestUtil.hpp"

#include <LoginRelay.hpp>

#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Percent.hpp>
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
#include <fstream>
#include <optional>
#include <string>
#include <map>

using namespace bazarish;
using namespace bazarish::service;

namespace {

using testutil::Headers;
using testutil::call;

constexpr std::size_t kSecretBytes = 16;

namespace http = bazarish::http;

std::int64_t now()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void testLoginVerification()
{
    const Identity identity = Identity::generate();
    const std::string challenge = encodeLoginChallenge("portal-challenge-abc");
    const std::string blob = signLoginBlob(identity, now(), challenge);

    CHECK(verifyLoginBlob(blob, now(), challenge) == identity.fingerprint());
    CHECK_THROWS(verifyLoginBlob(blob, now(), "a-different-challenge"));
    CHECK_THROWS(verifyLoginBlob(blob, now() + 100000, challenge));
    CHECK_THROWS(verifyLoginBlob(blob + "x", now(), challenge));
}

void testLoginCallback()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-portal-" + toHex(randomBytes(8)));
    SubscriptionStore store(root);
    GrantStore grants(root);

    const NodeSettings::Values values;
    AccountApiOptions options;
    options.serverFingerprint = "server-fp";
    const fs::path configPath = root / "node.json";
    {
        std::ofstream config(configPath);
        config << "{\n  \"state\": \"" << root.string() << "\"\n}\n";
    }
    options.settings = std::make_shared<NodeSettings>(configPath, values);
    options.forgetMailbox = [](const std::string&) { return true; };
    options.publishQuota = [](const std::string&, std::uint64_t) {};
    options.publishCardChanged = [](const std::string&) {};
    options.logins = std::make_shared<LoginMailbox>();

    AccountApi api(store, grants, options);
    const int port = api.bind("127.0.0.1", 0);
    CHECK(port > 0);
    {
        LoginChallenge panel("panel-secret",
            LoginConsumer{"Bazarish admin panel", {"https://panel.example"}, "Administrator"});
        const std::string facade = std::string(52, 'f') + ".b32.i2p";
        const std::string challenge = panel.issue(now(), loginrelay::callbackUrl(facade));
        const std::string nonce = loginrelay::nonceOf(challenge);
        const Identity signer = Identity::generate();
        const Bytes key = newLinkKey();
        const auto deliverUnder = [&](const Bytes& sealing, const std::string& sent,
                                      const std::string& blob) {
            return call(port, "POST", loginrelay::kCallbackPath, {},
                sealLoginAnswer(sealing, {sent, blob}))
                .status;
        };
        const auto deliver = [&](const std::string& sent, const std::string& blob) {
            return deliverUnder(key, sent, blob);
        };
        const std::string path = std::string(loginrelay::kChallengePrefix) + nonce;
        CHECK(call(port, "GET", path).status == 404);
        CHECK(deliver(challenge, signLoginBlob(signer, now(), challenge)) == 404);

        CHECK(options.logins->expect(challenge, "token", key, now()));
        const http::ClientResponse fetched = call(port, "GET", path);
        CHECK(fetched.status == 200);
        CHECK(fetched.body.find(nonce) == std::string::npos);
        CHECK(openLoginChallenge(key, Bytes(fetched.body.begin(), fetched.body.end())) == challenge);
        CHECK(deliverUnder(newLinkKey(), challenge, signLoginBlob(signer, now(), challenge)) == 403);
        CHECK(call(port, "POST", loginrelay::kCallbackPath, {}, "{\"challenge\": 1}").status == 400);
        CHECK(call(port, "POST", loginrelay::kCallbackPath, {}, "not json").status == 400);
        CHECK(deliver(challenge, "not a blob") == 403);
        CHECK(deliver(challenge, signLoginBlob(signer, now(), panel.issue(now()))) == 403);
        CHECK(options.logins->claim(nonce, "token", now()).state == LoginMailbox::State::eWaiting);
        CHECK(deliver(challenge, signLoginBlob(signer, now(), challenge)) == 200);
        CHECK(deliver(challenge, signLoginBlob(signer, now(), challenge)) == 404);
        const LoginMailbox::Claim claim = options.logins->claim(nonce, "token", now());
        CHECK(claim.state == LoginMailbox::State::eSigned);
        CHECK(panel.verify(claim.challenge, claim.blob, now()) == signer.fingerprint());
    }

    api.stop();
    fs::remove_all(root);
}

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

void testWebFlow()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-portal-web-" + toHex(randomBytes(8)));
    GrantStore grants(root);

    const Identity identity = Identity::generate();
    constexpr std::uint64_t kQuota = 20 * 1024 * 1024;
    NodeSettings::Values values;
    values.loginConsumer
        = LoginConsumer{"Bazarish service node", {"http://node.example"}, "Account owner"};
    values.defaultQuotaBytes = kQuota;
    values.facades = {"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr.b32.i2p"};
    PortalApiOptions options;
    options.serverFingerprint = "service-node-fingerprint";
    options.challengeSecret = toHex(randomBytes(kSecretBytes));
    options.sessionSecret = toHex(randomBytes(kSecretBytes));
    options.assetsDirectory = BAZARISH_PORTAL_ASSETS_DIR;
    const fs::path nodeConfig = root / "service-node.json";
    fs::create_directories(root);
    std::ofstream(nodeConfig) << "{}";
    options.settings = std::make_shared<NodeSettings>(nodeConfig, values);
    options.logins = std::make_shared<LoginMailbox>();
    const std::string descriptor
        = encodeServerDescriptor({options.serverFingerprint, values.facades, values.reseeds});

    std::string deleted;
    options.deleteAccount = [&](const std::string& user) {
        deleted = user;
        grants.erase(user);
    };
    options.accountUsage = [](const std::string&) -> std::optional<MailboxUsage> {
        return MailboxUsage{1024, kQuota, 2};
    };

    PortalApi portal(options, grants);
    const int port = portal.bind("127.0.0.1", 0);
    CHECK(port > 0);
    const http::ClientResponse page = call(port, "GET", "/");
    CHECK(page.status == 200);
    CHECK(page.body.find("<h2 class=\"view-title\">Sign in<") != std::string::npos);
    CHECK(page.body.find("server serv ice- node -fin gerp rint<") != std::string::npos);

    for (const char* const code : {"en", "ru", "es", "zh", "ar"}) {
        const http::ClientResponse drawn
            = call(port, "GET", "/", {{"Cookie", "lang=" + std::string(code)}});
        CHECK(drawn.status == 200);
        CHECK(drawn.body.find("{{t.") == std::string::npos);
        CHECK(drawn.body.find("{{") == std::string::npos);
        CHECK(drawn.body.find("lang=\"" + std::string(code) + "\"") != std::string::npos);
        const std::string direction = std::string(code) == "ar" ? "rtl" : "ltr";
        CHECK(drawn.body.find("dir=\"" + direction + "\"") != std::string::npos);
        CHECK(drawn.body.find("class=\"lang-one is-on\"") != std::string::npos);
    }
    const http::ClientResponse stranger = call(port, "GET", "/", {{"Cookie", "lang=de"}});
    CHECK(stranger.status == 200);
    CHECK(stranger.body.find("lang=\"en\"") != std::string::npos);

    const http::ClientResponse switched = call(port, "GET", "/lang/ru?back=%2Fstyle.css");
    CHECK(switched.status == 303);
    CHECK(switched.headers.at("location") == "/style.css");
    CHECK(switched.headers.at("set-cookie").find("lang=ru;") == 0);
    const http::ClientResponse away
        = call(port, "GET", "/lang/ru?back=https%3A%2F%2Fevil.example");
    CHECK(away.status == 303);
    CHECK(away.headers.at("location") == "/");
    const http::ClientResponse unknown = call(port, "GET", "/lang/de?back=%2F");
    CHECK(unknown.status == 303);
    CHECK(unknown.headers.count("set-cookie") == 0);

    const http::ClientResponse style = call(port, "GET", "/style.css");
    CHECK(style.status == 200);
    CHECK(style.contentType.find("text/css") != std::string::npos);
    CHECK(call(port, "GET", "/../CMakeLists.txt").status == 404);

    const http::ClientResponse script = call(port, "GET", "/portal.js");
    CHECK(script.status == 200);
    CHECK(script.contentType.find("javascript") != std::string::npos);

    CHECK(style.body.find("--bz-key: #14e2ff") != std::string::npos);

    CHECK(page.body.find("data-sign-wait") == std::string::npos);
    CHECK(page.headers.count("set-cookie") == 0);
    {
        const std::string facade = std::string(52, 'f') + ".b32.i2p";
        NodeSettings::Values withFacade = values;
        withFacade.facades = {facade};
        options.settings->set(withFacade);

        const http::ClientResponse shown = call(port, "GET", "/");
        CHECK(shown.status == 200);
        CHECK(shown.body.find("class=\"qr-code\"><svg") != std::string::npos);
        const std::string pasted = between(shown.body, "<pre class=\"copy\">", "</pre>");
        CHECK(!readLoginCallback(pasted).has_value());
        CHECK(shown.body.find("<div data-signin-tabs hidden>") != std::string::npos);
        CHECK(shown.body.find("class=\"tab is-on\" type=\"button\" data-signin-show=\"copy\"")
            < shown.body.find("data-signin-show=\"scan\""));
        CHECK(shown.body.find("<div data-signin-pane=\"scan\" hidden>")
            < shown.body.find("<div data-signin-pane=\"copy\">"));
        const std::string nonce = between(shown.body, "data-sign-wait=\"/login/wait?nonce=", "\"");
        const std::string scanned = options.logins->held(nonce, now())->challenge;
        const std::optional<LoginCallback> callback = readLoginCallback(scanned);
        CHECK(callback.has_value() && callback->host == facade && callback->path == "/login/callback");
        const std::string token = between(shown.headers.at("set-cookie") + ";", "signin=", ";");
        CHECK(shown.headers.at("set-cookie").find("Path=/login") != std::string::npos);
        const auto wait = [&](const std::string& cookie) {
            return nlohmann::json::parse(call(port, "GET", "/login/wait?nonce=" + nonce,
                {{"Cookie", "signin=" + cookie}}).body).at("state").get<std::string>();
        };
        CHECK(wait(token) == "waiting");
        CHECK(options.logins->held(nonce, now())->challenge == scanned);
        CHECK(options.logins->deliver(nonce, scanned, signLoginBlob(identity, now(), scanned), now()));
        CHECK(wait(toHex(randomBytes(kSecretBytes))) == "gone");
        const http::ClientResponse claimed = call(port, "GET", "/login/wait?nonce=" + nonce,
            {{"Cookie", "signin=" + token}});
        CHECK(nlohmann::json::parse(claimed.body).at("state") == "signedIn");
        const std::string scannedSession
            = between(claimed.headers.at("set-cookie") + ";", "session=", ";");
        CHECK(call(port, "GET", "/", {{"Cookie", "session=" + scannedSession}}).body.find(
                  identity.fingerprint())
            != std::string::npos);
        CHECK(wait(token) == "gone");

        const http::ClientResponse forged = call(port, "GET", "/");
        const std::string other = options.logins
            ->held(between(forged.body, "data-sign-wait=\"/login/wait?nonce=", "\""), now())
            ->challenge;
        const std::string otherToken = between(forged.headers.at("set-cookie") + ";", "signin=", ";");
        const std::string otherNonce = loginrelay::nonceOf(other);
        nlohmann::json edited = nlohmann::json::parse(decodeLoginChallenge(other));
        edited["callback"] = "http://" + std::string(52, 'e') + ".b32.i2p/login/callback";
        const std::string moved = encodeLoginChallenge(edited.dump());
        CHECK(!options.logins->deliver(otherNonce, moved, signLoginBlob(identity, now(), moved), now()));
        CHECK(options.logins->deliver(otherNonce, other, "not a blob", now()));
        CHECK(nlohmann::json::parse(call(port, "GET", "/login/wait?nonce=" + otherNonce,
                  {{"Cookie", "signin=" + otherToken}}).body).at("state") == "gone");

        options.settings->set(values);
    }

    const std::string challenge = between(page.body, "<pre class=\"copy\">", "</pre>");
    const std::string blob = signLoginBlob(identity, now(), challenge);
    const http::ClientResponse signedIn = postForm(port, "/login",
        "challenge=" + bazarish::percentEncode(challenge) + "&blob=" + bazarish::percentEncode(blob));
    CHECK(signedIn.status == 303);
    const std::string cookie = between(signedIn.headers.at("set-cookie") + ";", "session=", ";");
    CHECK(!cookie.empty());
    CHECK(signedIn.headers.at("set-cookie").find("; Secure;") != std::string::npos);

    const http::ClientResponse asked = call(port, "GET", "/", {{"Cookie", "session=" + cookie}});
    CHECK(asked.status == 200);
    CHECK(asked.body.find(identity.fingerprint()) != std::string::npos);
    const std::optional<GrantStore::SubscriptionGrant> grant
        = grants.peekSubscription(identity.fingerprint());
    CHECK(grant.has_value());
    CHECK(grant->quotaBytes == kQuota);

    const http::ClientResponse done = call(port, "GET", "/", {{"Cookie", "session=" + cookie}});
    CHECK(done.status == 200);
    CHECK(done.body.find("<h2 class=\"panel-title\">account</h2>") != std::string::npos);
    CHECK(done.body.find(htmlEscape(descriptor)) != std::string::npos);
    CHECK(done.body.find("href=\"#descriptor-qr\"") != std::string::npos);
    CHECK(done.body.find("id=\"descriptor-qr\"") != std::string::npos);
    CHECK(done.body.find("<path fill=\"#000\" d=\"M") != std::string::npos);
    CHECK(done.body.find("1.0 KiB of 20 MiB") != std::string::npos);
    CHECK(done.body.find("<span>Devices</span>2") != std::string::npos);

    CHECK(page.body.find("<!--") == std::string::npos);
    CHECK(asked.body.find("<!--") == std::string::npos);
    CHECK(done.body.find("<!--") == std::string::npos);
    CHECK(script.body.find("console.") == std::string::npos);

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
        CHECK(call(port, "GET", "/", {{"Cookie", "session=" + cookie}})
                  .body.find(identity.fingerprint())
            == std::string::npos);
    }

    {
        const Identity refused = Identity::generate();
        grants.ban(refused.fingerprint(), "Spam");
        const http::ClientResponse page = call(port, "GET", "/");
        const std::string challenge = between(page.body, "<pre class=\"copy\">", "</pre>");
        const http::ClientResponse signedIn = postForm(port, "/login",
            "challenge=" + bazarish::percentEncode(challenge) + "&blob="
                + bazarish::percentEncode(signLoginBlob(refused, now(), challenge)));
        CHECK(signedIn.status == 303);
        const std::string banned
            = between(signedIn.headers.at("set-cookie") + ";", "session=", ";");

        const http::ClientResponse shown
            = call(port, "GET", "/", {{"Cookie", "session=" + banned}});
        CHECK(shown.status == 200);
        CHECK(shown.body.find("Spam") != std::string::npos);
        CHECK(!grants.peekSubscription(refused.fingerprint()).has_value());
    }

    portal.stop();
    fs::remove_all(root);
}

}  // namespace

int main()
{
    testLoginVerification();
    testLoginCallback();
    testWebFlow();
    std::printf("TestPortal: all checks passed\n");
    return 0;
}
