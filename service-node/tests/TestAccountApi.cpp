// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Descriptor.hpp>
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
    const Bytes cardDer
        = ServerCard::issue(serverIdentity, Key::fromPublicDer(serverSealing.publicDer()), now);

    AccountApiOptions options;
    options.serverFingerprint = serverFp;
    options.serverCardDer = cardDer;
    options.defaultQuotaBytes = 10 * 1024 * 1024;
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
    // Deleting an account has to reach the messaging server too, or its mail
    // outlives the account that could have collected it.
    std::string forgottenMailbox;
    options.forgetMailbox = [&forgottenMailbox](const std::string& user) {
        forgottenMailbox = user;
        return true;
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

    // Publishing a card. Registration is portal-authorised: a pending grant must
    // exist before the client's first call, and that call is what turns the
    // registration into an account.
    {
        grants.grantSubscription(alice.fingerprint(), options.defaultQuotaBytes, now);
        const Bytes card = ContactCard::issue(alice, now);
        const std::string body = nlohmann::json{{"card", toBase64(card)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            makeHeaders(alice, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("quotaBytes") == options.defaultQuotaBytes);
        CHECK(fromBase64(reply.at("serverCard").get<std::string>()) == cardDer);
        // The grant's quota was pushed to the messaging server for this user.
        CHECK(quotaCalls == 1);
        CHECK(quotaUser == alice.fingerprint());
        CHECK(quotaPushed == options.defaultQuotaBytes);
    }

    // A card signed by someone else but naming alice fails the signer check
    // inside verify (the hybrid signer must equal body.user).
    {
        const nlohmann::json forgedBody
            = {{"v", kCertificateFormatVersion}, {"user", alice.fingerprint()}};
        const Bytes forged = cms::signJsonHybrid(forgedBody, mallory);
        const std::string body = nlohmann::json{{"card", toBase64(forged)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            makeHeaders(mallory, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 400);
    }

    // A client with no registration behind it is refused.
    {
        const Bytes card = ContactCard::issue(mallory, now);
        const std::string body = nlohmann::json{{"card", toBase64(card)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            makeHeaders(mallory, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 403);
    }

    // Re-publishing routing needs no second grant: a destination can only be
    // delegated once the account exists, so the first card carries none and the
    // client publishes again as soon as it has one.
    {
        const Key sealing = Key::generateSealing();
        const std::string dest
            = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
        const Bytes servingKey = Key::generateSealing().publicDer();
        CHECK(!grants.peekSubscription(alice.fingerprint()).has_value());
        const Bytes card
            = ContactCard::issue(alice, now + 1, dest, sealing.publicDer(), servingKey);
        const std::string body = nlohmann::json{{"card", toBase64(card)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            makeHeaders(alice, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("quotaBytes") == options.defaultQuotaBytes);

        // The card is answered only to someone holding the descriptor: the view
        // capability from it comes back with the query. The node issued it when
        // the account was created and reported it with the publish.
        const std::string view
            = nlohmann::json::parse(result.body).at("view").get<std::string>();
        CHECK(view.size() == bazarish::kViewCapabilityChars);
        const http::ClientResponse looked = call(port, "GET",
            "/v1/account/card?user=" + alice.fingerprint() + "&view=" + view);
        CHECK(looked.status == 200);
        const ContactCard fetched = ContactCard::verify(
            fromBase64(nlohmann::json::parse(looked.body).at("card").get<std::string>()));
        CHECK(fetched.dest == dest);
        CHECK(fetched.servingSealingKeyDer == servingKey);

        // A card is published forwards only. An older one - a copy a second
        // device kept - would otherwise put this account's routing back to what
        // it used to be, with a valid signature and nobody the wiser.
        {
            const std::string oldDest
                = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            const Bytes stale = ContactCard::issue(
                alice, now, oldDest, sealing.publicDer(), servingKey);
            const std::string staleBody = nlohmann::json{{"card", toBase64(stale)}}.dump();
            CHECK(call(port, "POST", "/v1/account/card",
                      makeHeaders(alice, "POST", "/v1/account/card", staleBody), staleBody)
                      .status
                == 409);
            // Nor one of the same age: "newer" means newer, not "no older".
            const Bytes sameAge = ContactCard::issue(
                alice, now + 1, oldDest, sealing.publicDer(), servingKey);
            const std::string sameBody = nlohmann::json{{"card", toBase64(sameAge)}}.dump();
            CHECK(call(port, "POST", "/v1/account/card",
                      makeHeaders(alice, "POST", "/v1/account/card", sameBody), sameBody)
                      .status
                == 409);
            // And what is served is still the card that was published.
            const http::ClientResponse again = call(port, "GET",
                "/v1/account/card?user=" + alice.fingerprint() + "&view=" + view);
            CHECK(ContactCard::verify(fromBase64(
                      nlohmann::json::parse(again.body).at("card").get<std::string>()))
                      .dest
                == dest);

            // A clock running ahead cannot publish a card no later one could beat.
            const Bytes future = ContactCard::issue(alice, now + 4000, oldDest,
                sealing.publicDer(), servingKey);
            const std::string futureBody = nlohmann::json{{"card", toBase64(future)}}.dump();
            CHECK(call(port, "POST", "/v1/account/card",
                      makeHeaders(alice, "POST", "/v1/account/card", futureBody), futureBody)
                      .status
                == 400);
        }
        CHECK(fetched.sealingPublicKeyDer == sealing.publicDer());

        // A wrong key and an unknown user are refused identically, so asking
        // teaches nothing about who is served here.
        const http::ClientResponse wrongKey = call(port, "GET",
            "/v1/account/card?user=" + alice.fingerprint()
                + "&view=ffffffffffffffffffffffffffffffff");
        const http::ClientResponse unknown = call(port, "GET",
            "/v1/account/card?user=" + mallory.fingerprint() + "&view=" + view);
        CHECK(wrongKey.status == 404);
        CHECK(unknown.status == 404);
        CHECK(wrongKey.body == unknown.body);
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

    // Closing the account tears it down: record gone, destination revoked,
    // grants dropped - so the account can no longer delegate a transient.
    {
        const http::ClientResponse result = call(port, "DELETE", "/v1/account/registration",
            makeHeaders(alice, "DELETE", "/v1/account/registration", ""));
        CHECK(result.status == 200);
        CHECK(pubCalls == 4);  // + the revoke the teardown performs
        CHECK(pubTransient.empty());
        CHECK(!grants.peekApproval(alice.fingerprint()).has_value());
        CHECK(forgottenMailbox == alice.fingerprint());

        // Asking again is answered the same way. It is what a client sees when an
        // operator deleted the account first: nothing to end, and no reason to
        // refuse - a refusal would leave a profile nobody can ever clean up.
        const http::ClientResponse again = call(port, "DELETE", "/v1/account/registration",
            makeHeaders(alice, "DELETE", "/v1/account/registration", ""));
        CHECK(again.status == 200);

        const std::string body
            = nlohmann::json{{"transient", "after-closing"}, {"expiresUnix", now + 3600}}.dump();
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
