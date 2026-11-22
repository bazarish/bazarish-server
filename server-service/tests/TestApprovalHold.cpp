// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "AccountRemoval.hpp"
#include "DeviceTestKit.hpp"
#include "HttpTestUtil.hpp"
#include "TestUtil.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Descriptor.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <future>
#include <memory>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::service;

namespace {

namespace http = bazarish::http;

constexpr const char* kStatus = "/v1/account/i2p-status";
constexpr const char* kHeldWhilePending = "/v1/account/i2p-status?hold=1&since=pending";
constexpr std::chrono::seconds kSoon{5};
constexpr std::uint64_t kQuota = 10 * 1024 * 1024;
constexpr char kBanReason[] = "spam from this key";

const std::string kCardDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gqaaaa.b32.i2p";

Bytes cardOf(const devicetest::Account& owner, const std::int64_t issuedAt)
{
    ContactCard card;
    card.kind = AccountKind::eBot;
    card.issuedAt = issuedAt;
    card.dest = kCardDest;
    const EpochNumber current = epochAt(issuedAt);
    card.epochs = {
        {current, kFirstEpochGeneration, owner.keys.id(), Key::generateSealing().publicDer()},
        {current + 1, kFirstEpochGeneration, owner.keys.id(), Key::generateSealing().publicDer()}};
    card.servingSealingKeyDer = Key::generateSealing().publicDer();
    card.devices = owner.book();
    return card.issue(owner.device.signing());
}

std::future<http::ClientResponse> holdFor(const int port, const devicetest::Account& account)
{
    return std::async(std::launch::async, [port, &account]() {
        http::ClientOptions unbounded;
        unbounded.readTimeout = std::chrono::seconds(0);
        return testutil::call(port, "GET", kHeldWhilePending,
            testutil::deviceHeaders(account.device, "GET", kHeldWhilePending, ""), {}, unbounded);
    });
}

void registerPending(const int port, GrantStore& grants, const devicetest::Account& account,
    const std::int64_t now)
{
    grants.grantSubscription(account.fingerprint(), kQuota, now);
    const std::string body = nlohmann::json{{"card", toBase64(cardOf(account, now))},
        {"cardKey", linkKeyText(newLinkKey())}}.dump();
    const http::ClientResponse result = testutil::call(port, "POST", "/v1/account/card",
        testutil::deviceHeaders(account.device, "POST", "/v1/account/card", body), body);
    CHECK(result.status == 200);
    CHECK(nlohmann::json::parse(result.body).at("approval") == "pending");
}

}  // namespace

int main()
try {
    const testutil::ScratchDir scratch("approval-hold-test");
    const std::filesystem::path& root = scratch.path();
    SubscriptionStore store(root);
    GrantStore grants(root);

    const Identity serverIdentity = Identity::generate();
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    const Key nodeSealing = Key::generateSealing();

    NodeSettings::Values values;
    values.defaultQuotaBytes = kQuota;
    values.requireApproval = true;
    AccountApiOptions options;
    options.opsClientPins = {"a pin a plain test socket never checks"};
    options.serverFingerprint = serverIdentity.fingerprint();
    options.sealingKey = std::make_shared<Key>(Key::fromPrivatePem(nodeSealing.privatePem()));
    options.nodeCardDer = ServerCard::issue(serverIdentity, ServerCard::Service::eServerService,
        Key::fromPublicDer(nodeSealing.publicDer()));
    options.settings = std::make_shared<NodeSettings>(std::filesystem::path(), values);
    options.pushes = std::make_shared<PushQueue>(root, store, *options.userLocks,
        PushQueue::Delivery{
            .quota = [](const std::string&, std::uint64_t) { return PushOutcome::eDelivered; },
            .card = [](const std::string&) { return PushOutcome::eDelivered; },
            .takeDownAddress = [](const std::string&) { return PushOutcome::eDelivered; },
            .forget = [](const std::string&) { return PushOutcome::eDelivered; }});
    AccountApi api(store, grants, options);
    const int port = api.bind("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serving([&api]() { api.wait(); });

    const devicetest::Account approved;
    const devicetest::Account declined;
    const devicetest::Account banned;
    for (const devicetest::Account* const account : {&approved, &declined, &banned}) {
        registerPending(port, grants, *account, now);
    }

    {
        std::future<http::ClientResponse> held = holdFor(port, approved);
        CHECK(held.wait_for(kSoon) == std::future_status::timeout);
        grants.approve(declined.fingerprint(), now);
        grants.hold(banned.fingerprint(), "still looking", now, 0);
        CHECK(held.wait_for(kSoon) == std::future_status::timeout);
        grants.approve(approved.fingerprint(), now);
        CHECK(held.wait_for(kSoon) == std::future_status::ready);
        const http::ClientResponse answer = held.get();
        CHECK(answer.status == 200);
        CHECK(nlohmann::json::parse(answer.body).at("approval") == "approved");

        const http::ClientResponse atOnce = testutil::call(port, "GET", kHeldWhilePending,
            testutil::deviceHeaders(approved.device, "GET", kHeldWhilePending, ""));
        CHECK(nlohmann::json::parse(atOnce.body).at("approval") == "approved");
    }

    {
        grants.hold(declined.fingerprint(), "waiting again", now, 0);
        std::future<http::ClientResponse> held = holdFor(port, declined);
        CHECK(held.wait_for(kSoon) == std::future_status::timeout);
        removeAccount(declined.fingerprint(), store, grants, *options.pushes);
        CHECK(held.wait_for(kSoon) == std::future_status::ready);
        const http::ClientResponse answer = held.get();
        CHECK(answer.status == 200);
        CHECK(nlohmann::json::parse(answer.body).at("approval") == "none");
    }

    {
        std::future<http::ClientResponse> held = holdFor(port, banned);
        CHECK(held.wait_for(kSoon) == std::future_status::timeout);
        grants.ban(banned.fingerprint(), kBanReason);
        CHECK(held.wait_for(kSoon) == std::future_status::ready);
        const http::ClientResponse answer = held.get();
        CHECK(answer.status == 403);
        CHECK(nlohmann::json::parse(answer.body).at("error").at("message") == kBanReason);
    }

    {
        const devicetest::Account waiting;
        registerPending(port, grants, waiting, now);
        std::future<http::ClientResponse> held = holdFor(port, waiting);
        CHECK(held.wait_for(kSoon) == std::future_status::timeout);
        const http::ClientResponse plain = testutil::call(
            port, "GET", kStatus, testutil::deviceHeaders(waiting.device, "GET", kStatus, ""));
        CHECK(nlohmann::json::parse(plain.body).at("approval") == "pending");
        CHECK(held.wait_for(kSoon) == std::future_status::ready);
        CHECK(nlohmann::json::parse(held.get().body).at("approval") == "pending");
    }

    api.stop();
    serving.join();
    std::printf("TestApprovalHold ok\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
