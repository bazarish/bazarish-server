// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "DeviceTestKit.hpp"
#include "HttpTestUtil.hpp"
#include "TestUtil.hpp"

#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/KeyedSeal.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::service;

namespace {

namespace http = bazarish::http;

using testutil::call;
using testutil::deviceHeaders;
using testutil::signedHeaders;

constexpr std::uint64_t kQuota = 10 * 1024 * 1024;
constexpr std::uint64_t kRaised = 40 * 1024 * 1024;
constexpr std::uint64_t kLowered = 30 * 1024 * 1024;
constexpr int kDelegationDays = 7;
const std::string kCardDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";

class MessagingServer {
public:
    void setUp(const bool up)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        up_ = up;
    }

    PushOutcome quota(const std::string& user, const std::uint64_t quotaBytes)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!up_) {
            return PushOutcome::eUnreachable;
        }
        quotas_[user] = quotaBytes;
        return PushOutcome::eDelivered;
    }

    PushOutcome card(const std::string& user)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!up_) {
            return PushOutcome::eUnreachable;
        }
        cards_.push_back(user);
        return PushOutcome::eDelivered;
    }

    PushOutcome takeDown(const std::string& user)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!up_) {
            return PushOutcome::eUnreachable;
        }
        takenDown_.push_back(user);
        return PushOutcome::eDelivered;
    }

    std::size_t takeDownsOf(const std::string& user)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<std::size_t>(std::count(takenDown_.begin(), takenDown_.end(), user));
    }

    std::uint64_t quotaOf(const std::string& user)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = quotas_.find(user);
        return found == quotas_.end() ? 0 : found->second;
    }

    std::size_t cardsOf(const std::string& user)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<std::size_t>(std::count(cards_.begin(), cards_.end(), user));
    }

private:
    std::mutex mutex_;
    bool up_ = false;
    std::map<std::string, std::uint64_t> quotas_;
    std::vector<std::string> cards_;
    std::vector<std::string> takenDown_;
};

Bytes cardOf(const devicetest::Account& owner, const std::int64_t issuedAt)
{
    ContactCard card;
    card.kind = AccountKind::eBot;
    card.issuedAt = issuedAt;
    card.dest = kCardDest;
    const EpochNumber current = epochAt(issuedAt);
    card.epochs = {{current, kFirstEpochGeneration, owner.keys.id(), Key::generateSealing().publicDer()},
        {current + 1, kFirstEpochGeneration, owner.keys.id(), Key::generateSealing().publicDer()}};
    card.servingSealingKeyDer = Key::generateSealing().publicDer();
    card.devices = owner.book();
    return card.issue(owner.device.signing());
}

bool serverPending(const int opsPort, const Identity& panel, const std::string& user)
{
    const std::string target = "/v1/account/user?user=" + user;
    const http::ClientResponse answer
        = call(opsPort, "GET", target, signedHeaders(panel, "GET", target, {}));
    CHECK(answer.status == 200);
    return nlohmann::json::parse(answer.body).at("serverPending").get<bool>();
}

http::ClientResponse operatorCall(const int port, const Identity& panel,
    const std::string& method, const std::string& target, const std::string& body = {})
{
    return call(port, method, target, signedHeaders(panel, method, target, body), body);
}

}  // namespace

int main()
{
    const std::filesystem::path root = testutil::freshDir("push-queue-test");
    SubscriptionStore store(root);
    GrantStore grants(root);

    const Identity serverIdentity = Identity::generate();
    const Identity panel = Identity::generate();
    const std::int64_t now = nowSeconds();
    const Key nodeSealing = Key::generateSealing();

    MessagingServer messaging;
    NodeSettings::Values values;
    values.defaultQuotaBytes = kQuota;
    AccountApiOptions options;
    options.opsClientPins = {"a pin a plain test socket never checks"};
    options.serverFingerprint = serverIdentity.fingerprint();
    options.serverCardDer = ServerCard::issue(serverIdentity, ServerCard::Service::eMessaging,
        Key::fromPublicDer(Key::generateSealing().publicDer()), now);
    options.sealingKey = std::make_shared<Key>(Key::fromPrivatePem(nodeSealing.privatePem()));
    options.nodeCardDer = ServerCard::issue(serverIdentity, ServerCard::Service::eServiceNode,
        Key::fromPublicDer(nodeSealing.publicDer()), now);
    options.settings = std::make_shared<NodeSettings>(std::filesystem::path(), values);
    options.operatorFingerprints = {panel.fingerprint()};
    options.publishI2pTransient = [](const std::string&, const std::string&, std::int64_t,
                                      const AddressKeys&) -> std::optional<ServedDestination> {
        return ServedDestination{};
    };
    options.forgetMailbox = [](const std::string&) { return true; };
    const auto queue = [&]() {
        return std::make_shared<PushQueue>(root, store, *options.userLocks,
            PushQueue::Delivery{
                .quota =
                    [&messaging](const std::string& user, const std::uint64_t quotaBytes) {
                        return messaging.quota(user, quotaBytes);
                    },
                .card = [&messaging](const std::string& user) { return messaging.card(user); },
                .takeDownAddress =
                    [&messaging](const std::string& user) { return messaging.takeDown(user); }});
    };

    const devicetest::Account alice;
    const std::string user = alice.fingerprint();
    const std::string quotaBody = nlohmann::json{{"user", user}, {"quotaBytes", kRaised}}.dump();

    {
        options.pushes = queue();
        AccountApi api(store, grants, options);
        const int port = api.bind("127.0.0.1", 0);
        const int opsPort = api.bindOps("127.0.0.1", 0);
        CHECK(port > 0);
        CHECK(opsPort > 0);
        std::thread serving([&api]() { api.wait(); });

        grants.grantSubscription(user, kQuota, now);
        const std::string cardBody
            = nlohmann::json{{"card", toBase64(cardOf(alice, now))},
                  {"cardKey", linkKeyText(newLinkKey())}}
                  .dump();
        CHECK(call(port, "POST", "/v1/account/card",
                  deviceHeaders(alice.device, "POST", "/v1/account/card", cardBody), cardBody)
                  .status
            == 200);

        CHECK(serverPending(opsPort, panel, user));
        const http::ClientResponse set
            = operatorCall(opsPort, panel, "PUT", "/v1/account/quota", quotaBody);
        CHECK(set.status == 200);
        const nlohmann::json record = nlohmann::json::parse(set.body);
        CHECK(record.at("quotaBytes").get<std::uint64_t>() == kRaised);
        CHECK(record.at("serverPending").get<bool>());
        CHECK(messaging.quotaOf(user) == 0);
        CHECK(messaging.cardsOf(user) == 0);

        messaging.setUp(true);
        const std::string lookup = "/v1/account/card?user=" + user;
        CHECK(call(port, "GET", lookup, signedHeaders(serverIdentity, "GET", lookup, {})).status
            == 200);
        CHECK(testutil::waitFor([&]() {
            return messaging.quotaOf(user) == kRaised && messaging.cardsOf(user) == 1;
        }));
        CHECK(testutil::waitFor([&]() { return !serverPending(opsPort, panel, user); }));

        messaging.setUp(false);
        const std::string lowered
            = nlohmann::json{{"user", user}, {"quotaBytes", kLowered}}.dump();
        CHECK(operatorCall(opsPort, panel, "PUT", "/v1/account/quota", lowered).status == 200);
        CHECK(serverPending(opsPort, panel, user));

        api.stop();
        serving.join();
    }

    {
        options.pushes = queue();
        AccountApi api(store, grants, options);
        const int opsPort = api.bindOps("127.0.0.1", 0);
        CHECK(opsPort > 0);
        CHECK(serverPending(opsPort, panel, user));
        CHECK(messaging.quotaOf(user) == kRaised);

        messaging.setUp(true);
        options.pushes->serverReached();
        CHECK(testutil::waitFor([&]() { return messaging.quotaOf(user) == kLowered; }));
        CHECK(testutil::waitFor([&]() { return !serverPending(opsPort, panel, user); }));
        CHECK(messaging.cardsOf(user) == 1);

        const int port = api.bind("127.0.0.1", 0);
        CHECK(port > 0);
        messaging.setUp(false);
        const std::string hold
            = nlohmann::json{{"user", user}, {"message", "write to the operator"}}.dump();
        const http::ClientResponse held
            = operatorCall(opsPort, panel, "POST", "/v1/account/undelegate", hold);
        CHECK(held.status == 200);
        CHECK(nlohmann::json::parse(held.body).at("serverPending").get<bool>());
        CHECK(messaging.takeDownsOf(user) == 0);

        const std::string approve = nlohmann::json{{"user", user}}.dump();
        CHECK(operatorCall(opsPort, panel, "POST", "/v1/account/approve", approve).status == 200);
        const i2p::Keys delegation = i2p::Keys::generate().issueTransient(kDelegationDays);
        const std::string delegate = nlohmann::json{{"transient", toBase64(delegation.blob())},
            {"expiresUnix", delegation.transientExpires()}, {"sealingKey", "sealing-pem"},
            {"signingKey", "signing-pem"}}
                                         .dump();
        CHECK(call(port, "POST", "/v1/account/i2p-dest",
                  deviceHeaders(alice.device, "POST", "/v1/account/i2p-dest", delegate), delegate)
                  .status
            == 200);
        CHECK(!serverPending(opsPort, panel, user));

        CHECK(operatorCall(opsPort, panel, "POST", "/v1/account/undelegate", hold).status == 200);
        CHECK(serverPending(opsPort, panel, user));

        messaging.setUp(true);
        const std::string lookup = "/v1/account/card?user=" + user;
        CHECK(call(port, "GET", lookup, signedHeaders(serverIdentity, "GET", lookup, {})).status
            == 404);
        CHECK(testutil::waitFor([&]() { return messaging.takeDownsOf(user) == 1; }));
        CHECK(testutil::waitFor([&]() { return !serverPending(opsPort, panel, user); }));
        api.stop();
    }
    options.pushes.reset();

    std::filesystem::remove_all(root);
    std::printf("TestPushQueue OK\n");
    return 0;
}
