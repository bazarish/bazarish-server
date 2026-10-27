// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Descriptor.hpp>
#include <bazarish/Hybrid.hpp>
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

constexpr const char* kServedDest = "servedaddressb33";
constexpr const char* kServedServingKey = "c2VydmluZy1rZXk=";

namespace http = bazarish::http;

using Headers = std::map<std::string, std::string>;

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

Bytes botCard(const Identity& owner, const std::int64_t issuedAt, const std::string& dest = {},
    const Bytes& sealingDer = {}, const Bytes& servingDer = {})
{
    ContactCard card;
    card.kind = AccountKind::eBot;
    card.issuedAt = issuedAt;
    card.dest = dest;
    card.sealingPublicKeyDer = sealingDer;
    card.servingSealingKeyDer = servingDer;
    return card.issue(owner);
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

    constexpr std::uint64_t kQuota = 10 * 1024 * 1024;
    NodeSettings::Values values;
    values.defaultQuotaBytes = kQuota;
    AccountApiOptions options;
    options.serverFingerprint = serverFp;
    options.serverCardDer = cardDer;
    options.settings = std::make_shared<NodeSettings>(std::filesystem::path(), values);
    std::string pubUser;
    std::string pubTransient;
    std::int64_t pubExpires = -1;
    int pubCalls = 0;
    bool pubAccepts = true;
    options.publishI2pTransient = [&](const std::string& user, const std::string& transientB64,
                                      const std::int64_t expiresUnix)
        -> std::optional<ServedDestination> {
        pubUser = user;
        pubTransient = transientB64;
        pubExpires = expiresUnix;
        ++pubCalls;
        if (!pubAccepts) {
            return std::nullopt;
        }
        return ServedDestination{kServedDest, kServedServingKey};
    };
    std::string forgottenMailbox;
    options.forgetMailbox = [&forgottenMailbox](const std::string& user) {
        forgottenMailbox = user;
        return true;
    };
    std::string quotaUser;
    std::uint64_t quotaPushed = 0;
    int quotaCalls = 0;
    options.publishQuota = [&](const std::string& user, const std::uint64_t quotaBytes) {
        quotaUser = user;
        quotaPushed = quotaBytes;
        ++quotaCalls;
    };
    AccountApi api(store, grants, options);

    const int port = api.bind("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serverThread([&api]() { api.wait(); });

    const Identity alice = Identity::generate();
    const Identity mallory = Identity::generate();

    {
        grants.grantSubscription(alice.fingerprint(), kQuota, now);
        const Bytes card = botCard(alice, now);
        const std::string body = nlohmann::json{{"card", toBase64(card)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            makeHeaders(alice, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("quotaBytes") == kQuota);
        CHECK(fromBase64(reply.at("serverCard").get<std::string>()) == cardDer);
        CHECK(quotaCalls == 1);
        CHECK(quotaUser == alice.fingerprint());
        CHECK(quotaPushed == kQuota);
    }

    {
        const nlohmann::json forgedBody
            = {{"v", kCertificateFormatVersion}, {"user", alice.fingerprint()}};
        const Bytes forged = hybrid::signJson(forgedBody, mallory);
        const std::string body = nlohmann::json{{"card", toBase64(forged)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            makeHeaders(mallory, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 400);
    }

    {
        const Bytes card = botCard(mallory, now);
        const std::string body = nlohmann::json{{"card", toBase64(card)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            makeHeaders(mallory, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 403);
    }

    {
        const Key sealing = Key::generateSealing();
        const std::string dest
            = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
        const Bytes servingKey = Key::generateSealing().publicDer();
        CHECK(!grants.peekSubscription(alice.fingerprint()).has_value());
        const Bytes card
            = botCard(alice, now + 1, dest, sealing.publicDer(), servingKey);
        const std::string body = nlohmann::json{{"card", toBase64(card)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            makeHeaders(alice, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("quotaBytes") == kQuota);

        const http::ClientResponse looked
            = call(port, "GET", "/v1/account/card?user=" + alice.fingerprint(),
                makeHeaders(serverIdentity, "GET", "/v1/account/card", ""));
        CHECK(looked.status == 200);
        const ContactCard fetched = ContactCard::verify(
            fromBase64(nlohmann::json::parse(looked.body).at("card").get<std::string>()));
        CHECK(fetched.dest == dest);
        CHECK(fetched.servingSealingKeyDer == servingKey);

        {
            const std::string oldDest
                = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            const Bytes stale = botCard(
                alice, now, oldDest, sealing.publicDer(), servingKey);
            const std::string staleBody = nlohmann::json{{"card", toBase64(stale)}}.dump();
            CHECK(call(port, "POST", "/v1/account/card",
                      makeHeaders(alice, "POST", "/v1/account/card", staleBody), staleBody)
                      .status
                == 409);
            const Bytes sameAge = botCard(
                alice, now + 1, oldDest, sealing.publicDer(), servingKey);
            const std::string sameBody = nlohmann::json{{"card", toBase64(sameAge)}}.dump();
            CHECK(call(port, "POST", "/v1/account/card",
                      makeHeaders(alice, "POST", "/v1/account/card", sameBody), sameBody)
                      .status
                == 409);
            const http::ClientResponse again
                = call(port, "GET", "/v1/account/card?user=" + alice.fingerprint(),
                    makeHeaders(serverIdentity, "GET", "/v1/account/card", ""));
            CHECK(ContactCard::verify(fromBase64(
                      nlohmann::json::parse(again.body).at("card").get<std::string>()))
                      .dest
                == dest);

            const Bytes future = botCard(alice, now + 4000, oldDest,
                sealing.publicDer(), servingKey);
            const std::string futureBody = nlohmann::json{{"card", toBase64(future)}}.dump();
            CHECK(call(port, "POST", "/v1/account/card",
                      makeHeaders(alice, "POST", "/v1/account/card", futureBody), futureBody)
                      .status
                == 400);
        }
        CHECK(fetched.sealingPublicKeyDer == sealing.publicDer());

        const http::ClientResponse unknown
            = call(port, "GET", "/v1/account/card?user=" + mallory.fingerprint(),
                    makeHeaders(serverIdentity, "GET", "/v1/account/card", ""));
        CHECK(unknown.status == 404);
    }

    {
        const std::string body
            = nlohmann::json{{"transient", "user-transient-b64"},
                  {"expiresUnix", now + 7 * 24 * 3600}}
                  .dump();
        const http::ClientResponse stranger = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(mallory, "POST", "/v1/account/i2p-dest", body), body);
        CHECK(stranger.status == 403);
        CHECK(pubCalls == 0);

        CHECK(!grants.peekApproval(alice.fingerprint())->pending());
        const http::ClientResponse ok = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", body), body);
        CHECK(ok.status == 200);
        CHECK(pubCalls == 1);
        CHECK(pubUser == alice.fingerprint());
        CHECK(pubTransient == "user-transient-b64");
        CHECK(pubExpires == now + 7 * 24 * 3600);
        const std::int64_t delegatedAt = store.getAccount(alice.fingerprint())->delegatedAt;
        CHECK(delegatedAt >= now);
        {
            const nlohmann::json served = nlohmann::json::parse(ok.body);
            CHECK(served.at("dest").get<std::string>() == kServedDest);
            CHECK(served.at("servingKey").get<std::string>() == kServedServingKey);
        }

        {
            pubAccepts = false;
            const http::ClientResponse refused = call(port, "POST", "/v1/account/i2p-dest",
                makeHeaders(alice, "POST", "/v1/account/i2p-dest", body), body);
            CHECK(refused.status == 503);
            const http::ClientResponse status = call(port, "GET", "/v1/account/i2p-status",
                makeHeaders(alice, "GET", "/v1/account/i2p-status", {}));
            CHECK(status.status == 200);
            const nlohmann::json reply = nlohmann::json::parse(status.body);
            CHECK(reply.at("transientExpires") == now + 7 * 24 * 3600);
            pubAccepts = true;
        }

        const std::string revokeBody = nlohmann::json::object().dump();
        const http::ClientResponse revoked = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", revokeBody), revokeBody);
        CHECK(revoked.status == 200);
        CHECK(pubCalls == 3);
        CHECK(pubTransient.empty());
        CHECK(pubExpires == 0);
        CHECK(store.getAccount(alice.fingerprint())->delegatedAt == delegatedAt);
    }

    {
        const http::ClientResponse result = call(port, "DELETE", "/v1/account/registration",
            makeHeaders(alice, "DELETE", "/v1/account/registration", ""));
        CHECK(result.status == 200);
        CHECK(pubCalls == 4);
        CHECK(pubTransient.empty());
        CHECK(!grants.peekApproval(alice.fingerprint()).has_value());
        CHECK(forgottenMailbox == alice.fingerprint());

        const http::ClientResponse again = call(port, "DELETE", "/v1/account/registration",
            makeHeaders(alice, "DELETE", "/v1/account/registration", ""));
        CHECK(again.status == 200);

        const std::string body
            = nlohmann::json{{"transient", "after-closing"}, {"expiresUnix", now + 3600}}.dump();
        const http::ClientResponse orphan = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", body), body);
        CHECK(orphan.status == 403);
        CHECK(pubCalls == 4);
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
