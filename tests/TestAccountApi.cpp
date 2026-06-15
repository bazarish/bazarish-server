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

    // Registering a username requires an active username entitlement bought on
    // the portal; without one the request is refused.
    {
        const Bytes cert = AliasCertificate::issue(alice, "alice", now, std::nullopt);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const httplib::Result ungranted = client.Post("/v1/account/alias",
            makeHeaders(alice, "POST", "/v1/account/alias", body), body, "application/json");
        CHECK(ungranted && ungranted->status == 403);
    }

    // Register an alias (with an entitlement) and resolve it to the full chain.
    {
        grants.grantService(alice.fingerprint(), "username", now + 365 * 24 * 3600, now);
        const Bytes cert = AliasCertificate::issue(alice, "alice", now, std::nullopt);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const httplib::Result result = client.Post("/v1/account/alias",
            makeHeaders(alice, "POST", "/v1/account/alias", body), body, "application/json");
        CHECK(result && result->status == 200);

        const httplib::Result resolved = client.Get("/v1/account/resolve?alias=alice");
        CHECK(resolved && resolved->status == 200);
        const nlohmann::json chain = nlohmann::json::parse(resolved->body);
        CHECK(chain.at("user") == alice.fingerprint());
        // The returned chain verifies independently.
        const AliasCertificate aliasCert
            = AliasCertificate::verify(fromBase64(chain.at("aliasCert").get<std::string>()));
        CHECK(aliasCert.alias == "alice");
        const SubscriptionCertificate subCert = SubscriptionCertificate::verify(
            fromBase64(chain.at("subscriptionCert").get<std::string>()));
        CHECK(subCert.user == alice.fingerprint());
        CHECK(subCert.server == serverFp);
    }

    // Mallory cannot take alice's alias (even with her own username entitlement).
    {
        grants.grantService(mallory.fingerprint(), "username", now + 365 * 24 * 3600, now);
        const Bytes cert = AliasCertificate::issue(mallory, "alice", now, std::nullopt);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const httplib::Result result = client.Post("/v1/account/alias",
            makeHeaders(mallory, "POST", "/v1/account/alias", body), body,
            "application/json");
        CHECK(result && result->status == 409);
        CHECK(nlohmann::json::parse(result->body).at("error").at("code") == "ALIAS_TAKEN");
    }

    // Unknown alias resolution is an explicit error (no anti-enumeration).
    {
        const httplib::Result result = client.Get("/v1/account/resolve?alias=ghost");
        CHECK(result && result->status == 404);
        CHECK(nlohmann::json::parse(result->body).at("error").at("code") == "ALIAS_UNKNOWN");
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

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
