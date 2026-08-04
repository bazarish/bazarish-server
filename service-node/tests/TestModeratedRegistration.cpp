// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
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

namespace {

httplib::Headers makeHeaders(const Identity& identity, const std::string& method,
    const std::string& path, const std::string& body)
{
    const auth::Headers signed_ = auth::signRequest(identity,
        static_cast<std::int64_t>(std::time(nullptr)), method, path,
        Bytes(body.begin(), body.end()));
    return httplib::Headers(signed_.begin(), signed_.end());
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-moderation-test";
    std::filesystem::remove_all(root);
    SubscriptionStore store(root);
    GrantStore grants(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const std::string serverFp = serverIdentity.fingerprint();
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    const Bytes cardDer = ServerCard::issue(
        serverIdentity, {"i2p:exampledest"}, Key::fromPublicDer(serverSealing.publicDer()), now);

    const Identity panel = Identity::generate();
    const Identity alice = Identity::generate();

    AccountApiOptions options;
    options.serverFingerprint = serverFp;
    options.serverCardDer = cardDer;
    options.defaultQuotaBytes = 50 * 1024 * 1024;
    options.maxTermSeconds = 14 * 24 * 3600;
    options.operatorFingerprints = {panel.fingerprint()};
    options.registration = AccountApiOptions::Registration::eApproval;
    options.registrationMessage = "write to admin@example.i2p to finish registration";
    int pubCalls = 0;
    options.publishI2pTransient = [&pubCalls](const std::string&, const std::string&,
                                      std::int64_t) { ++pubCalls; };
    AccountApi api(store, grants, options);

    const int port = api.bindToAnyPort("127.0.0.1");
    CHECK(port > 0);
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });
    httplib::Client client("127.0.0.1", port);
    CHECK(client.is_valid());

    const std::string transientBody
        = nlohmann::json{{"transient", "t-b64"}, {"expiresUnix", now + 7 * 24 * 3600}}.dump();

    // The account is created exactly as on an open node - only frozen.
    {
        grants.grantSubscription(
            alice.fingerprint(), options.defaultQuotaBytes, options.maxTermSeconds, now);
        const Bytes cert
            = SubscriptionCertificate::issue(alice, serverFp, now, now + 3 * 24 * 3600);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const httplib::Result result = client.Post("/v1/account/subscribe",
            makeHeaders(alice, "POST", "/v1/account/subscribe", body), body, "application/json");
        CHECK(result && result->status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result->body);
        CHECK(reply.at("approval") == "pending");
        CHECK(reply.at("registrationMessage") == options.registrationMessage);
    }

    // Frozen means the destination is never brought up: the transient is refused
    // with a typed error carrying the operator's instructions.
    {
        const httplib::Result result = client.Post("/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", transientBody), transientBody,
            "application/json");
        CHECK(result && result->status == 403);
        const nlohmann::json error = nlohmann::json::parse(result->body).at("error");
        CHECK(error.at("code") == "ACCOUNT_PENDING_APPROVAL");
        CHECK(error.at("message") == options.registrationMessage);
        CHECK(pubCalls == 0);
    }

    // The operator sees the account waiting.
    {
        const httplib::Result result = client.Get(
            "/v1/account/pending", makeHeaders(panel, "GET", "/v1/account/pending", ""));
        CHECK(result && result->status == 200);
        const nlohmann::json pending = nlohmann::json::parse(result->body).at("pending");
        CHECK(pending.size() == 1);
        CHECK(pending.at(0).at("user") == alice.fingerprint());
    }

    // Approval is operator-only.
    {
        const std::string body = nlohmann::json{{"user", alice.fingerprint()}}.dump();
        const httplib::Result forged = client.Post("/v1/account/approve",
            makeHeaders(alice, "POST", "/v1/account/approve", body), body, "application/json");
        CHECK(forged && forged->status == 403);
        CHECK(grants.peekApproval(alice.fingerprint())->pending());

        const httplib::Result result = client.Post("/v1/account/approve",
            makeHeaders(panel, "POST", "/v1/account/approve", body), body, "application/json");
        CHECK(result && result->status == 200);
    }

    // Once approved the account is served like any other.
    {
        const httplib::Result result = client.Post("/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", transientBody), transientBody,
            "application/json");
        CHECK(result && result->status == 200);
        CHECK(pubCalls == 1);

        const httplib::Result pending = client.Get(
            "/v1/account/pending", makeHeaders(panel, "GET", "/v1/account/pending", ""));
        CHECK(nlohmann::json::parse(pending->body).at("pending").empty());
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    std::printf("TestModeratedRegistration: all checks passed\n");
    return 0;
}
