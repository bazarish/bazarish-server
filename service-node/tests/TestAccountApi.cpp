// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Cms.hpp>
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
        = std::filesystem::temp_directory_path() / "bazarish-account-test";
    std::filesystem::remove_all(root);
    SubscriptionStore store(root);
    GrantStore grants(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const std::string serverFp = serverIdentity.fingerprint();
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    const Bytes cardDer = ServerCard::issue(
        serverIdentity, {"i2p:exampledest"}, Key::fromPublicDer(serverSealing.publicDer()), now);

    AccountApiOptions options;
    options.serverFingerprint = serverFp;
    options.serverCardDer = cardDer;
    options.defaultQuotaBytes = 10 * 1024 * 1024;
    options.maxTermSeconds = 14 * 24 * 3600;
    // Capture per-user-dest publishes so the i2p-dest endpoint can be asserted.
    std::string pubUser;
    std::string pubTransient;
    std::int64_t pubExpires = -1;
    int pubCalls = 0;
    options.publishI2pTransient = [&](const std::string& user, const std::string& transientB64,
                                      const std::int64_t expiresUnix) {
        pubUser = user;
        pubTransient = transientB64;
        pubExpires = expiresUnix;
        ++pubCalls;
    };
    AccountApi api(store, grants, options);

    const int port = api.bindToAnyPort("127.0.0.1");
    CHECK(port > 0);
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });
    httplib::Client client("127.0.0.1", port);
    CHECK(client.is_valid());

    const Identity alice = Identity::generate();
    const Identity mallory = Identity::generate();

    // Subscribe with a valid certificate. Registration is portal-authorised:
    // a pending grant must exist before the Client submits its signed cert.
    {
        grants.grantSubscription(alice.fingerprint(), options.defaultQuotaBytes,
            options.maxTermSeconds, now);
        const Bytes cert
            = SubscriptionCertificate::issue(alice, serverFp, now, now + 3 * 24 * 3600);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const httplib::Result result = client.Post("/v1/account/subscribe",
            makeHeaders(alice, "POST", "/v1/account/subscribe", body), body,
            "application/json");
        CHECK(result && result->status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result->body);
        CHECK(reply.at("quotaBytes") == options.defaultQuotaBytes);
        CHECK(reply.at("notAfter") == now + 3 * 24 * 3600);
        CHECK(fromBase64(reply.at("serverCard").get<std::string>()) == cardDer);
    }

    // A certificate signed by someone else but naming alice fails the
    // signer check inside verify (hybrid signer must equal body.user).
    {
        const nlohmann::json forgedBody = {
            {"v", kCertificateFormatVersion}, {"user", alice.fingerprint()},
            {"server", serverFp}, {"issuedAt", now}, {"notAfter", now + 3600}};
        const Bytes forged = cms::signJsonHybrid(forgedBody, mallory);
        const std::string body = nlohmann::json{{"cert", toBase64(forged)}}.dump();
        const httplib::Result result = client.Post("/v1/account/subscribe",
            makeHeaders(mallory, "POST", "/v1/account/subscribe", body), body,
            "application/json");
        CHECK(result && result->status == 400);
    }

    // A certificate for a different server is rejected.
    {
        const Bytes cert = SubscriptionCertificate::issue(
            alice, Identity::generate().fingerprint(), now, now + 3600);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const httplib::Result result = client.Post("/v1/account/subscribe",
            makeHeaders(alice, "POST", "/v1/account/subscribe", body), body,
            "application/json");
        CHECK(result && result->status == 400);
    }

    // A term longer than the maximum is rejected.
    {
        const Bytes cert = SubscriptionCertificate::issue(
            alice, serverFp, now, now + 30 * 24 * 3600);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const httplib::Result result = client.Post("/v1/account/subscribe",
            makeHeaders(alice, "POST", "/v1/account/subscribe", body), body,
            "application/json");
        CHECK(result && result->status == 400);
        CHECK(nlohmann::json::parse(result->body).at("error").at("code")
            == "SUBSCRIPTION_TERM_TOO_LONG");
    }

    // Subscription status reflects the active subscription.
    {
        const httplib::Result result = client.Get("/v1/account/subscription",
            makeHeaders(alice, "GET", "/v1/account/subscription", ""));
        CHECK(result && result->status == 200);
        CHECK(nlohmann::json::parse(result->body).at("notAfter") == now + 3 * 24 * 3600);
    }

    // Contact lookup by fingerprint returns the subscription certificate
    // with the user's sealing prekey; unknown users are an explicit 404.
    {
        // Renewal is portal-authorised too (a fresh grant), so it re-runs the
        // captcha / payment rather than letting a free term self-renew forever.
        grants.grantSubscription(alice.fingerprint(), options.defaultQuotaBytes,
            options.maxTermSeconds, now);
        const Key aliceSealing = Key::generateSealing();
        const Bytes cert = SubscriptionCertificate::issue(
            alice, serverFp, now, now + 3 * 24 * 3600, aliceSealing.publicDer());
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const httplib::Result renewed = client.Post("/v1/account/renew",
            makeHeaders(alice, "POST", "/v1/account/renew", body), body, "application/json");
        CHECK(renewed && renewed->status == 200);

        const httplib::Result result
            = client.Get("/v1/account/contact?user=" + alice.fingerprint());
        CHECK(result && result->status == 200);
        const SubscriptionCertificate looked = SubscriptionCertificate::verify(fromBase64(
            nlohmann::json::parse(result->body).at("subscriptionCert").get<std::string>()));
        CHECK(looked.user == alice.fingerprint());
        CHECK(looked.sealingPublicKeyDer == aliceSealing.publicDer());

        const httplib::Result missing
            = client.Get("/v1/account/contact?user=" + mallory.fingerprint());
        CHECK(missing && missing->status == 404);
    }

    // Unsubscribe drops the subscription.
    {
        const httplib::Result result = client.Delete("/v1/account/subscription",
            makeHeaders(alice, "DELETE", "/v1/account/subscription", ""));
        CHECK(result && result->status == 200);
        const httplib::Result status = client.Get("/v1/account/subscription",
            makeHeaders(alice, "GET", "/v1/account/subscription", ""));
        CHECK(status && status->status == 404);
    }

    // Per-user I2P destination delegation: every account owns one, so the only
    // gate is that this node knows the account and has approved it.
    {
        const std::string body
            = nlohmann::json{{"transient", "user-transient-b64"},
                  {"expiresUnix", now + 7 * 24 * 3600}}
                  .dump();
        // A stranger with no account here -> 403, nothing published.
        const httplib::Result stranger = client.Post("/v1/account/i2p-dest",
            makeHeaders(mallory, "POST", "/v1/account/i2p-dest", body), body, "application/json");
        CHECK(stranger && stranger->status == 403);
        CHECK(pubCalls == 0);

        // An account registered on an open node is approved on creation -> 200.
        CHECK(!grants.peekApproval(alice.fingerprint())->pending());
        const httplib::Result ok = client.Post("/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", body), body, "application/json");
        CHECK(ok && ok->status == 200);
        CHECK(pubCalls == 1);
        CHECK(pubUser == alice.fingerprint());
        CHECK(pubTransient == "user-transient-b64");
        CHECK(pubExpires == now + 7 * 24 * 3600);

        // An empty transient revokes (published with empty transient, expiry 0).
        const std::string revokeBody = nlohmann::json::object().dump();
        const httplib::Result revoked = client.Post("/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", revokeBody), revokeBody,
            "application/json");
        CHECK(revoked && revoked->status == 200);
        CHECK(pubCalls == 2);
        CHECK(pubTransient.empty());
        CHECK(pubExpires == 0);
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
