// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Crypto.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
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

Headers makeHeaders(const Identity& identity, const std::string& method,
    const std::string& path, const std::string& body)
{
    const auth::Headers signed_ = auth::signRequest(identity,
        static_cast<std::int64_t>(std::time(nullptr)), method, path,
        Bytes(body.begin(), body.end()));
    return Headers(signed_.begin(), signed_.end());
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
    // The messaging server's answer, so the refusal path can be exercised too.
    bool pubAccepts = true;
    options.publishI2pTransient = [&](const std::string& user, const std::string& transientB64,
                                      const std::int64_t expiresUnix) {
        pubUser = user;
        pubTransient = transientB64;
        pubExpires = expiresUnix;
        ++pubCalls;
        return pubAccepts;
    };
    // Capture quota pushes: the granted quota must reach the messaging server,
    // else it would answer the user with its own unrelated default.
    std::string quotaUser;
    std::uint64_t quotaPushed = 0;
    int quotaCalls = 0;
    options.publishQuota = [&](const std::string& user, const std::uint64_t quotaBytes) {
        quotaUser = user;
        quotaPushed = quotaBytes;
        ++quotaCalls;
    };
    AccountApi api(store, grants, options);

    const int port = api.bindToAnyPort("127.0.0.1");
    CHECK(port > 0);
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });

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
        const http::ClientResponse result = call(port, "POST", "/v1/account/subscribe",
            makeHeaders(alice, "POST", "/v1/account/subscribe", body), body);
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("quotaBytes") == options.defaultQuotaBytes);
        CHECK(reply.at("notAfter") == now + 3 * 24 * 3600);
        CHECK(fromBase64(reply.at("serverCard").get<std::string>()) == cardDer);
        // The grant's quota was pushed to the messaging server for this user.
        CHECK(quotaCalls == 1);
        CHECK(quotaUser == alice.fingerprint());
        CHECK(quotaPushed == options.defaultQuotaBytes);
    }

    // A certificate signed by someone else but naming alice fails the
    // signer check inside verify (hybrid signer must equal body.user).
    {
        const nlohmann::json forgedBody = {
            {"v", kCertificateFormatVersion}, {"user", alice.fingerprint()},
            {"server", serverFp}, {"issuedAt", now}, {"notAfter", now + 3600}};
        const Bytes forged = cms::signJsonHybrid(forgedBody, mallory);
        const std::string body = nlohmann::json{{"cert", toBase64(forged)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/subscribe",
            makeHeaders(mallory, "POST", "/v1/account/subscribe", body), body);
        CHECK(result.status == 400);
    }

    // A certificate for a different server is rejected.
    {
        const Bytes cert = SubscriptionCertificate::issue(
            alice, Identity::generate().fingerprint(), now, now + 3600);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/subscribe",
            makeHeaders(alice, "POST", "/v1/account/subscribe", body), body);
        CHECK(result.status == 400);
    }

    // A term longer than the maximum is rejected.
    {
        const Bytes cert = SubscriptionCertificate::issue(
            alice, serverFp, now, now + 30 * 24 * 3600);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/subscribe",
            makeHeaders(alice, "POST", "/v1/account/subscribe", body), body);
        CHECK(result.status == 400);
        CHECK(nlohmann::json::parse(result.body).at("error").at("code")
            == "SUBSCRIPTION_TERM_TOO_LONG");
    }

    // Subscription status reflects the active subscription.
    {
        const http::ClientResponse result = call(port, "GET", "/v1/account/subscription",
            makeHeaders(alice, "GET", "/v1/account/subscription", ""));
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("notAfter") == now + 3 * 24 * 3600);
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
        const http::ClientResponse renewed = call(port, "POST", "/v1/account/renew",
            makeHeaders(alice, "POST", "/v1/account/renew", body), body);
        CHECK(renewed.status == 200);

        const http::ClientResponse result
            = call(port, "GET", "/v1/account/contact?user=" + alice.fingerprint());
        CHECK(result.status == 200);
        const SubscriptionCertificate looked = SubscriptionCertificate::verify(fromBase64(
            nlohmann::json::parse(result.body).at("subscriptionCert").get<std::string>()));
        CHECK(looked.user == alice.fingerprint());
        CHECK(looked.sealingPublicKeyDer == aliceSealing.publicDer());

        const http::ClientResponse missing
            = call(port, "GET", "/v1/account/contact?user=" + mallory.fingerprint());
        CHECK(missing.status == 404);
    }

    // Re-publishing the card inside the term already held needs no grant: the
    // destination can only be delegated once the account exists, so the first
    // certificate never carries routing and the client republishes right after.
    {
        const Key sealing = Key::generateSealing();
        const std::string dest
            = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
        const Bytes servingKey = Key::generateSealing().publicDer();
        CHECK(!grants.peekSubscription(alice.fingerprint()).has_value());
        const Bytes cert = SubscriptionCertificate::issue(alice, serverFp, now,
            now + 3 * 24 * 3600, sealing.publicDer(), dest, servingKey);
        const std::string body = nlohmann::json{{"cert", toBase64(cert)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/renew",
            makeHeaders(alice, "POST", "/v1/account/renew", body), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("quotaBytes") == options.defaultQuotaBytes);

        // The published card is the one a contact now gets, routing included.
        const http::ClientResponse looked
            = call(port, "GET", "/v1/account/contact?user=" + alice.fingerprint());
        CHECK(looked.status == 200);
        const SubscriptionCertificate card = SubscriptionCertificate::verify(fromBase64(
            nlohmann::json::parse(looked.body).at("subscriptionCert").get<std::string>()));
        CHECK(card.dest == dest);
        CHECK(card.servingSealingKeyDer == servingKey);

        // Extending the term is a new subscription, so that still needs a grant.
        const Bytes longer
            = SubscriptionCertificate::issue(alice, serverFp, now, now + 4 * 24 * 3600);
        const std::string longerBody = nlohmann::json{{"cert", toBase64(longer)}}.dump();
        const http::ClientResponse refused = call(port, "POST", "/v1/account/renew",
            makeHeaders(alice, "POST", "/v1/account/renew", longerBody), longerBody);
        CHECK(refused.status == 403);
    }

    // Per-user I2P destination delegation: every account owns one, so the only
    // gate is that this node knows the account and has approved it.
    {
        const std::string body
            = nlohmann::json{{"transient", "user-transient-b64"},
                  {"expiresUnix", now + 7 * 24 * 3600}}
                  .dump();
        // A stranger with no account here -> 403, nothing published.
        const http::ClientResponse stranger = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(mallory, "POST", "/v1/account/i2p-dest", body), body);
        CHECK(stranger.status == 403);
        CHECK(pubCalls == 0);

        // An account registered on an open node is approved on creation -> 200.
        CHECK(!grants.peekApproval(alice.fingerprint())->pending());
        const http::ClientResponse ok = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", body), body);
        CHECK(ok.status == 200);
        CHECK(pubCalls == 1);
        CHECK(pubUser == alice.fingerprint());
        CHECK(pubTransient == "user-transient-b64");
        CHECK(pubExpires == now + 7 * 24 * 3600);

        // A messaging server that does not take the delegation must not leave the
        // node claiming one is held: the client is told, and the status stays put.
        {
            pubAccepts = false;
            const http::ClientResponse refused = call(port, "POST", "/v1/account/i2p-dest",
                makeHeaders(alice, "POST", "/v1/account/i2p-dest", body), body);
            CHECK(refused.status == 503);
            const http::ClientResponse status = call(port, "GET", "/v1/account/i2p-status",
                makeHeaders(alice, "GET", "/v1/account/i2p-status", {}));
            CHECK(status.status == 200);
            const nlohmann::json reply = nlohmann::json::parse(status.body);
            CHECK(reply.at("transientExpires") == now + 7 * 24 * 3600);  // the one that did land
            pubAccepts = true;
        }

        // An empty transient revokes (published with empty transient, expiry 0).
        const std::string revokeBody = nlohmann::json::object().dump();
        const http::ClientResponse revoked = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", revokeBody), revokeBody);
        CHECK(revoked.status == 200);
        CHECK(pubCalls == 3);  // delegate, the refused attempt above, revoke
        CHECK(pubTransient.empty());
        CHECK(pubExpires == 0);
    }

    // Unsubscribe tears the account down: subscription gone, destination revoked,
    // grants dropped - so the account can no longer delegate a transient.
    {
        const http::ClientResponse result = call(port, "DELETE", "/v1/account/subscription",
            makeHeaders(alice, "DELETE", "/v1/account/subscription", ""));
        CHECK(result.status == 200);
        CHECK(pubCalls == 4);  // + the revoke unsubscribe performs
        CHECK(pubTransient.empty());
        CHECK(!grants.peekApproval(alice.fingerprint()).has_value());

        const http::ClientResponse status = call(port, "GET", "/v1/account/subscription",
            makeHeaders(alice, "GET", "/v1/account/subscription", ""));
        CHECK(status.status == 404);

        const std::string body
            = nlohmann::json{{"transient", "after-unsubscribe"}, {"expiresUnix", now + 3600}}
                  .dump();
        const http::ClientResponse orphan = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", body), body);
        CHECK(orphan.status == 403);
        CHECK(pubCalls == 4);  // refused before reaching the publisher
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
