// Bazarish project (c) 2026
#include "GrantStore.hpp"
#include "InvoiceStore.hpp"
#include "LedgerStore.hpp"
#include "MockPaymentGateway.hpp"
#include "Portal.hpp"
#include "PortalApi.hpp"
#include "PortalSession.hpp"
#include "SelfHostedCaptcha.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <optional>
#include <regex>
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

std::string extractCaptchaCode(const std::string& svg)
{
    std::string code;
    const std::regex re(">([A-Z2-9])</text>");
    for (auto it = std::sregex_iterator(svg.begin(), svg.end(), re); it != std::sregex_iterator();
         ++it) {
        code += (*it)[1].str();
    }
    return code;
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
    namespace fs = std::filesystem;
    const Identity identity = Identity::generate();
    const fs::path grantRoot = fs::temp_directory_path() / ("bazarish-grants-" + toHex(randomBytes(8)));

    SelfHostedCaptcha captcha("captcha-secret", 5, 300);
    GrantStore grants(grantRoot);
    LedgerStore ledger(grantRoot, "XMR");
    InvoiceStore invoices(grantRoot / "invoices.json");
    MockPaymentGateway gateway(false);

    PortalApiOptions options;
    options.audience = "test-server-fp";
    options.challengeSecret = "challenge-secret";
    options.sessionSecret = "session-secret";
    options.defaultQuotaBytes = 10 * 1024 * 1024;
    options.settlementCurrency = "XMR";
    options.paidServices["username"] = {600, 365 * 24 * 3600};
    PortalApi api(options, captcha, grants, ledger, invoices, gateway);

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

    // Registration requires a session.
    const httplib::Result anonRegister = client.Post(
        "/portal/register", nlohmann::json({{"captchaId", "x"}, {"captchaAnswer", "y"}}).dump(),
        "application/json");
    CHECK(anonRegister && anonRegister->status == 401);

    // Free registration: solve a captcha while logged in -> a pending grant.
    const httplib::Result captchaResponse = client.Get("/portal/captcha");
    CHECK(captchaResponse && captchaResponse->status == 200);
    const nlohmann::json captchaJson = nlohmann::json::parse(captchaResponse->body);
    const std::string captchaId = captchaJson.at("captchaId").get<std::string>();
    const std::string code = extractCaptchaCode(captchaJson.at("body").get<std::string>());

    const nlohmann::json registerBody = {{"captchaId", captchaId}, {"captchaAnswer", code}};
    const httplib::Result registered
        = client.Post("/portal/register", cookie, registerBody.dump(), "application/json");
    CHECK(registered && registered->status == 200);

    const std::optional<GrantStore::SubscriptionGrant> grant
        = grants.peekSubscription(identity.fingerprint());
    CHECK(grant.has_value());
    CHECK(grant->quotaBytes == 10 * 1024 * 1024);

    // A wrong captcha answer is rejected.
    const httplib::Result captcha2 = client.Get("/portal/captcha");
    const nlohmann::json captcha2Json = nlohmann::json::parse(captcha2->body);
    const nlohmann::json badCaptcha
        = {{"captchaId", captcha2Json.at("captchaId").get<std::string>()},
            {"captchaAnswer", "ZZZZZ"}};
    const httplib::Result rejected
        = client.Post("/portal/register", cookie, badCaptcha.dump(), "application/json");
    CHECK(rejected && rejected->status == 403);

    // Balance starts at zero.
    const httplib::Result balance0 = client.Get("/portal/balance", cookie);
    CHECK(balance0 && balance0->status == 200);
    CHECK(nlohmann::json::parse(balance0->body).at("balanceAtomic").get<std::string>() == "0");

    // Top up: create an invoice (mock gateway → pending until marked paid).
    const httplib::Result topup = client.Post(
        "/portal/topup", cookie, nlohmann::json({{"amount", "1000"}}).dump(), "application/json");
    CHECK(topup && topup->status == 200);
    const std::string invoiceId = nlohmann::json::parse(topup->body).at("invoiceId").get<std::string>();

    // Pending: polling does not credit yet.
    const httplib::Result pending = client.Get("/portal/pay/" + invoiceId, cookie);
    CHECK(pending && nlohmann::json::parse(pending->body).at("state").get<std::string>() == "pending");
    CHECK(nlohmann::json::parse(pending->body).at("balanceAtomic").get<std::string>() == "0");

    // Confirm the payment out of band, then poll: the balance is credited once.
    gateway.markPaid(invoiceId, "1000", 1);
    const httplib::Result confirmed = client.Get("/portal/pay/" + invoiceId, cookie);
    CHECK(confirmed && nlohmann::json::parse(confirmed->body).at("state").get<std::string>() == "confirmed");
    CHECK(nlohmann::json::parse(confirmed->body).at("balanceAtomic").get<std::string>() == "1000");
    // Idempotent: a second poll does not double-credit.
    const httplib::Result again = client.Get("/portal/pay/" + invoiceId, cookie);
    CHECK(nlohmann::json::parse(again->body).at("balanceAtomic").get<std::string>() == "1000");

    // Buy the username (600): balance drops to 400, entitlement is recorded.
    const httplib::Result bought = client.Post(
        "/portal/buy", cookie, nlohmann::json({{"service", "username"}}).dump(), "application/json");
    CHECK(bought && bought->status == 200);
    CHECK(nlohmann::json::parse(bought->body).at("balanceAtomic").get<std::string>() == "400");
    CHECK(grants.peekService(identity.fingerprint(), "username").has_value());

    // A second purchase (600) exceeds the remaining balance (400) → refused,
    // balance unchanged.
    const httplib::Result broke = client.Post(
        "/portal/buy", cookie, nlohmann::json({{"service", "username"}}).dump(), "application/json");
    CHECK(broke && broke->status == 402);
    const httplib::Result balanceAfter = client.Get("/portal/balance", cookie);
    CHECK(nlohmann::json::parse(balanceAfter->body).at("balanceAtomic").get<std::string>() == "400");

    api.stop();
    serverThread.join();
    fs::remove_all(grantRoot);
}

// With requireCaptcha=false the portal grants free registration to any
// signed-in user without a captcha, but still requires the sign-in-with-key
// session.
void testOpenRegistration()
{
    namespace fs = std::filesystem;
    const Identity identity = Identity::generate();
    const fs::path grantRoot
        = fs::temp_directory_path() / ("bazarish-grants-" + toHex(randomBytes(8)));

    SelfHostedCaptcha captcha("captcha-secret", 5, 300);
    GrantStore grants(grantRoot);
    LedgerStore ledger(grantRoot, "XMR");
    InvoiceStore invoices(grantRoot / "invoices.json");
    MockPaymentGateway gateway(false);

    PortalApiOptions options;
    options.audience = "test-server-fp";
    options.challengeSecret = "challenge-secret";
    options.sessionSecret = "session-secret";
    options.defaultQuotaBytes = 10 * 1024 * 1024;
    options.settlementCurrency = "XMR";
    options.requireCaptcha = false;
    PortalApi api(options, captcha, grants, ledger, invoices, gateway);

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
    CHECK(challengeResponse && challengeResponse->status == 200);
    const std::string challenge
        = nlohmann::json::parse(challengeResponse->body).at("challenge").get<std::string>();
    const std::string blob = signLoginBlob(identity, now(), challenge);
    const httplib::Result login = client.Post("/portal/login",
        nlohmann::json({{"challenge", challenge}, {"blob", blob}}).dump(), "application/json");
    CHECK(login && login->status == 200);
    const httplib::Headers cookie
        = {{"Cookie", "session=" + cookieToken(login->get_header_value("Set-Cookie"))}};

    // Captcha disabled: a logged-in user registers with no captcha (empty body).
    const httplib::Result registered = client.Post("/portal/register", cookie, "{}", "application/json");
    CHECK(registered && registered->status == 200);
    CHECK(grants.peekSubscription(identity.fingerprint()).has_value());

    // The session is still required even with the captcha off.
    const httplib::Result anon = client.Post("/portal/register", "{}", "application/json");
    CHECK(anon && anon->status == 401);

    api.stop();
    serverThread.join();
    fs::remove_all(grantRoot);
}

// The browser-facing, JS-free HTML site: login form -> cabinet -> register ->
// buy, plus the logged-out redirect guard. Shares the server with the JSON API.
void testWebUi()
{
    namespace fs = std::filesystem;
    const Identity identity = Identity::generate();
    const fs::path grantRoot
        = fs::temp_directory_path() / ("bazarish-grants-" + toHex(randomBytes(8)));

    SelfHostedCaptcha captcha("captcha-secret", 5, 300);
    GrantStore grants(grantRoot);
    LedgerStore ledger(grantRoot, "XMR");
    InvoiceStore invoices(grantRoot / "invoices.json");
    MockPaymentGateway gateway(false);

    PortalApiOptions options;
    options.audience = "test-server-fp";
    options.challengeSecret = "challenge-secret";
    options.sessionSecret = "session-secret";
    options.defaultQuotaBytes = 10 * 1024 * 1024;
    options.settlementCurrency = "XMR";
    options.requireCaptcha = false;
    options.paidServices["username"] = {600, 365 * 24 * 3600};
    PortalApi api(options, captcha, grants, ledger, invoices, gateway);

    const int port = api.bindToAnyPort("127.0.0.1");
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });
    httplib::Client client("127.0.0.1", port);

    httplib::Result home;
    for (int attempt = 0; attempt < 200; ++attempt) {
        home = client.Get("/");
        if (home) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    // Logged out, the home page is the sign-in-with-key login form.
    CHECK(home && home->status == 200);
    CHECK(home->get_header_value("Content-Type").find("text/html") != std::string::npos);
    CHECK(home->body.find("sign-login") != std::string::npos);

    // Sign in through the HTML form (challenge from the API, signed by the key).
    const std::string challenge = nlohmann::json::parse(client.Get("/portal/login")->body)
                                      .at("challenge")
                                      .get<std::string>();
    const std::string blob = signLoginBlob(identity, now(), challenge);
    const httplib::Result login
        = client.Post("/login", httplib::Params{{"challenge", challenge}, {"blob", blob}});
    CHECK(login && login->status == 303);
    CHECK(login->get_header_value("Location") == "/");
    const std::string token = cookieToken(login->get_header_value("Set-Cookie"));
    CHECK(!token.empty());
    const httplib::Headers cookie = {{"Cookie", "session=" + token}};

    // The cabinet shows the signed-in user, balance and the offered service.
    const httplib::Result cabinet = client.Get("/", cookie);
    CHECK(cabinet && cabinet->status == 200);
    CHECK(cabinet->body.find(identity.fingerprint()) != std::string::npos);
    CHECK(cabinet->body.find("Balance") != std::string::npos);
    CHECK(cabinet->body.find("username") != std::string::npos);

    // Free registration through the form (captcha off) records a grant.
    const httplib::Result registered = client.Post("/register", cookie, httplib::Params{});
    CHECK(registered && registered->status == 303);
    CHECK(registered->get_header_value("Location") == "/?msg=registered");
    CHECK(grants.peekSubscription(identity.fingerprint()).has_value());

    // Buying with a zero balance redirects back with the insufficient flash.
    const httplib::Result buy
        = client.Post("/buy", cookie, httplib::Params{{"service", "username"}});
    CHECK(buy && buy->status == 303);
    CHECK(buy->get_header_value("Location") == "/?msg=insufficient");

    // A logged-out action redirects to the login page rather than 401-ing.
    const httplib::Result guard = client.Get("/topup");
    CHECK(guard && guard->status == 303);
    CHECK(guard->get_header_value("Location") == "/login");

    api.stop();
    serverThread.join();
    fs::remove_all(grantRoot);
}

}  // namespace

int main()
{
    testSessionToken();
    testLoginFlow();
    testOpenRegistration();
    testWebUi();
    std::printf("TestPortalApi: all checks passed\n");
    return 0;
}
