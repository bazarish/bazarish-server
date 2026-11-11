// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "HttpTestUtil.hpp"
#include "TestUtil.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/KeyedSeal.hpp>

#include <bazarish/HttpClient.hpp>
#include <bazarish/I2p.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <map>
#include <thread>

using namespace bazarish;
using namespace bazarish::service;

namespace {

const std::string kCardKeyText = bazarish::linkKeyText(bazarish::newLinkKey());

using testutil::Headers;
using testutil::call;
using testutil::signedHeaders;

namespace http = bazarish::http;

constexpr int kDelegationDays = 7;

const std::string kCardDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";

Bytes botCard(const Identity& owner, const std::int64_t issuedAt,
    const std::string& dest = kCardDest,
    const Bytes& sealingDer = Key::generateSealing().publicDer(),
    const Bytes& servingDer = Key::generateSealing().publicDer())
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
        = testutil::freshDir("moderation-test");
    SubscriptionStore store(root);
    GrantStore grants(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const std::string serverFp = serverIdentity.fingerprint();
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    const Bytes cardDer
        = ServerCard::issue(serverIdentity, ServerCard::Service::eMessaging,
            Key::fromPublicDer(serverSealing.publicDer()), now);

    const Identity panel = Identity::generate();
    const Identity alice = Identity::generate();

    constexpr std::uint64_t kQuota = 20 * 1024 * 1024;
    const std::string kHoldMessage = "write to admin@example.i2p to finish registration";
    NodeSettings::Values values;
    values.defaultQuotaBytes = kQuota;
    values.requireApproval = true;
    values.registrationMessage = kHoldMessage;
    AccountApiOptions options;
    options.serverFingerprint = serverFp;
    options.serverCardDer = cardDer;
    options.operatorFingerprints = {panel.fingerprint()};
    options.settings = std::make_shared<NodeSettings>(std::filesystem::path(), values);
    options.forgetMailbox = [](const std::string&) { return true; };
    options.publishQuota = [](const std::string&, std::uint64_t) {};
    options.publishCardChanged = [](const std::string&) {};
    int pubCalls = 0;
    options.publishI2pTransient = [&pubCalls](const std::string&, const std::string&,
                                      std::int64_t, const AddressKeys&)
        -> std::optional<ServedDestination> {
        ++pubCalls;
        return ServedDestination{};
    };
    AccountApi api(store, grants, options);

    const int port = api.bind("127.0.0.1", 0);
    const int opsPort = api.bindOps("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serverThread([&api]() { api.wait(); });

    const bazarish::i2p::Keys delegation
        = bazarish::i2p::Keys::generate().issueTransient(kDelegationDays);
    const std::string transientBody = nlohmann::json{{"transient", toBase64(delegation.blob())},
        {"expiresUnix", delegation.transientExpires()}, {"sealingKey", "sealing-pem"},
        {"signingKey", "signing-pem"}}
                                          .dump();

    {
        grants.grantSubscription(
            alice.fingerprint(), kQuota, now);
        const Bytes card = botCard(alice, now);
        const std::string body = nlohmann::json{{"card", toBase64(card)}, {"cardKey", kCardKeyText}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            signedHeaders(alice, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("approval") == "pending");
        CHECK(reply.at("registrationMessage") == kHoldMessage);
    }

    const auto cardServed = [&]() {
        return call(port, "GET", "/v1/account/card?user=" + alice.fingerprint(),
            signedHeaders(
                serverIdentity, "GET", "/v1/account/card?user=" + alice.fingerprint(), ""))
            .status;
    };
    CHECK(cardServed() == 404);

    {
        const http::ClientResponse result = call(port, "POST", "/v1/account/i2p-dest",
            signedHeaders(alice, "POST", "/v1/account/i2p-dest", transientBody), transientBody);
        CHECK(result.status == 403);
        const nlohmann::json error = nlohmann::json::parse(result.body).at("error");
        CHECK(error.at("code") == "ACCOUNT_PENDING_APPROVAL");
        CHECK(error.at("message") == kHoldMessage);
        CHECK(pubCalls == 0);
    }

    {
        const http::ClientResponse result = call(opsPort, "GET", "/v1/account/users?state=pending",
            signedHeaders(panel, "GET", "/v1/account/users?state=pending", ""));
        CHECK(result.status == 200);
        const nlohmann::json users = nlohmann::json::parse(result.body).at("users");
        CHECK(users.size() == 1);
        CHECK(users.at(0).at("user") == alice.fingerprint());
        CHECK(users.at(0).at("approval") == "pending");
    }

    {
        const std::string body = nlohmann::json{{"user", alice.fingerprint()}}.dump();
        const http::ClientResponse forged = call(opsPort, "POST", "/v1/account/approve",
            signedHeaders(alice, "POST", "/v1/account/approve", body), body);
        CHECK(forged.status == 403);
        CHECK(grants.peekApproval(alice.fingerprint())->pending());

        const http::ClientResponse result = call(opsPort, "POST", "/v1/account/approve",
            signedHeaders(panel, "POST", "/v1/account/approve", body), body);
        CHECK(result.status == 200);
        CHECK(cardServed() == 200);
    }

    {
        const http::ClientResponse result = call(port, "POST", "/v1/account/i2p-dest",
            signedHeaders(alice, "POST", "/v1/account/i2p-dest", transientBody), transientBody);
        CHECK(result.status == 200);
        CHECK(pubCalls == 1);

        const http::ClientResponse pending = call(opsPort, "GET", "/v1/account/users?state=pending",
            signedHeaders(panel, "GET", "/v1/account/users?state=pending", ""));
        CHECK(nlohmann::json::parse(pending.body).at("users").empty());
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    std::printf("TestModeratedRegistration: all checks passed\n");
    return 0;
}
