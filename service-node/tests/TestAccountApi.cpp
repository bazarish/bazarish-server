// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "DeviceTestKit.hpp"
#include "HttpTestUtil.hpp"
#include "TestUtil.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Descriptor.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Tunnel.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <atomic>
#include <vector>
#include <filesystem>
#include <functional>
#include <future>
#include <map>
#include <thread>

using namespace bazarish;
using namespace bazarish::service;

namespace {

const std::string kCardKeyText = bazarish::linkKeyText(bazarish::newLinkKey());

using testutil::Headers;
using testutil::call;
using testutil::signedHeaders;

constexpr const char* kServedDest = "servedaddressb33";
constexpr const char* kSealingPem = "sealing-pem";
constexpr const char* kSigningPem = "signing-pem";
constexpr int kDelegationDays = 7;
constexpr int kPollMs = 1;
constexpr std::size_t kSessionSecretBytes = 32;
constexpr std::size_t kSessionIdChars = 32;

namespace http = bazarish::http;

constexpr char kCardTypeName[] = "contact-card";

const std::string kCardDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";

Bytes cardWith(const devicetest::Account& owner, const DeviceBook& devices,
    const std::int64_t issuedAt, const std::string& dest = kCardDest)
{
    ContactCard card;
    card.kind = AccountKind::eBot;
    card.issuedAt = issuedAt;
    card.dest = dest;
    const EpochNumber current = epochAt(issuedAt);
    card.epochs = {{current, kFirstEpochGeneration, owner.keys.id(), Key::generateSealing().publicDer()},
        {current + 1, kFirstEpochGeneration, owner.keys.id(), Key::generateSealing().publicDer()}};
    card.servingSealingKeyDer = Key::generateSealing().publicDer();
    card.devices = devices;
    return card.issue(owner.device.signing());
}

Bytes botCard(const devicetest::Account& owner, const std::int64_t issuedAt,
    const std::string& dest = kCardDest,
    const Bytes& sealingDer = Key::generateSealing().publicDer(),
    const Bytes& servingDer = Key::generateSealing().publicDer())
{
    ContactCard card;
    card.kind = AccountKind::eBot;
    card.issuedAt = issuedAt;
    card.dest = dest;
    const EpochNumber current = epochAt(issuedAt);
    card.epochs = {{current, kFirstEpochGeneration, owner.keys.id(), sealingDer},
        {current + 1, kFirstEpochGeneration, owner.keys.id(), Key::generateSealing().publicDer()}};
    card.servingSealingKeyDer = servingDer;
    card.devices = owner.book();
    return card.issue(owner.device.signing());
}

testutil::Headers deviceSigned(const DeviceCredential& device, const std::string& method,
    const std::string& target, const std::string& body)
{
    return testutil::deviceHeaders(device, method, target, body);
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = testutil::freshDir("account-test");
    SubscriptionStore store(root);
    GrantStore grants(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const std::string serverFp = serverIdentity.fingerprint();
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    const Bytes cardDer = ServerCard::issue(serverIdentity, ServerCard::Service::eMessaging,
        Key::fromPublicDer(serverSealing.publicDer()), now);
    const Key nodeSealing = Key::generateSealing();
    const Bytes nodeCardDer = ServerCard::issue(serverIdentity,
        ServerCard::Service::eServiceNode, Key::fromPublicDer(nodeSealing.publicDer()), now);

    constexpr std::uint64_t kQuota = 10 * 1024 * 1024;
    NodeSettings::Values values;
    values.defaultQuotaBytes = kQuota;
    AccountApiOptions options;
    options.serverFingerprint = serverFp;
    options.serverCardDer = cardDer;
    options.sealingKey = std::make_shared<Key>(Key::fromPrivatePem(nodeSealing.privatePem()));
    options.nodeCardDer = nodeCardDer;
    options.settings = std::make_shared<NodeSettings>(std::filesystem::path(), values);
    std::string pubUser;
    std::string pubTransient;
    std::int64_t pubExpires = -1;
    AddressKeys pubKeys;
    int pubCalls = 0;
    bool pubAccepts = true;
    std::function<void(const std::string& user, const std::string& transient)> pubGate;
    const Identity operatorIdentity = Identity::generate();
    options.operatorFingerprints = {operatorIdentity.fingerprint()};
    options.publishI2pTransient = [&](const std::string& user, const std::string& transientB64,
                                      const std::int64_t expiresUnix, const AddressKeys& keys)
        -> std::optional<ServedDestination> {
        if (pubGate) {
            pubGate(user, transientB64);
        }
        pubUser = user;
        pubTransient = transientB64;
        pubExpires = expiresUnix;
        pubKeys = keys;
        ++pubCalls;
        if (!pubAccepts) {
            return std::nullopt;
        }
        return ServedDestination{kServedDest};
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
    std::vector<std::string> cardsChanged;
    options.publishCardChanged
        = [&cardsChanged](const std::string& user) { cardsChanged.push_back(user); };
    AccountApi api(store, grants, options);

    const int port = api.bind("127.0.0.1", 0);
    CHECK(port > 0);
    const int opsPort = api.bindOps("127.0.0.1", 0);
    CHECK(opsPort > 0);
    std::thread serverThread([&api]() { api.wait(); });

    const devicetest::Account alice;
    const devicetest::Account mallory;

    {
        grants.grantSubscription(alice.fingerprint(), kQuota, now);
        const Bytes card = botCard(alice, now);
        const std::string body = nlohmann::json{{"card", toBase64(card)}, {"cardKey", kCardKeyText}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            deviceSigned(alice.device, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("quotaBytes") == kQuota);
        CHECK(fromBase64(reply.at("serverCard").get<std::string>()) == cardDer);
        CHECK(quotaCalls == 1);
        CHECK(quotaUser == alice.fingerprint());
        CHECK(quotaPushed == kQuota);
        CHECK(cardsChanged == std::vector<std::string>{alice.fingerprint()});
    }

    {
        const nlohmann::json destless = {{"v", kCertificateFormatVersion}, {"t", kCardTypeName},
            {"issuedAt", now + 1}, {"kind", "bot"}, {"dest", ""},
            {"sealingKey", toBase64(Key::generateSealing().publicDer())},
            {"servingKey", toBase64(Key::generateSealing().publicDer())}};
        const Bytes card = hybrid::signJson(destless, alice.device.signing());
        const std::string body = nlohmann::json{{"card", toBase64(card)}, {"cardKey", kCardKeyText}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            deviceSigned(alice.device, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 400);
        CHECK(cardsChanged.size() == 1);
    }

    {
        const nlohmann::json forgedBody
            = {{"v", kCertificateFormatVersion}, {"user", alice.fingerprint()}};
        const Bytes forged = hybrid::signJson(forgedBody, mallory.device.signing());
        const std::string body = nlohmann::json{{"card", toBase64(forged)}, {"cardKey", kCardKeyText}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            deviceSigned(mallory.device, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 400);
    }

    {
        const Bytes card = botCard(mallory, now);
        const std::string body = nlohmann::json{{"card", toBase64(card)}, {"cardKey", kCardKeyText}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            deviceSigned(mallory.device, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 404);
        CHECK(nlohmann::json::parse(result.body).at("error").at("code") == "ACCOUNT_UNKNOWN");
    }

    {
        const Key sealing = Key::generateSealing();
        const std::string dest
            = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
        const Bytes servingKey = Key::generateSealing().publicDer();
        CHECK(!grants.peekSubscription(alice.fingerprint()).has_value());
        const Bytes card
            = botCard(alice, now + 1, dest, sealing.publicDer(), servingKey);
        const std::string body = nlohmann::json{{"card", toBase64(card)}, {"cardKey", kCardKeyText}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            deviceSigned(alice.device, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("quotaBytes") == kQuota);

        const http::ClientResponse looked
            = call(port, "GET", "/v1/account/card?user=" + alice.fingerprint(),
                signedHeaders(serverIdentity, "GET", "/v1/account/card?user=" + alice.fingerprint(), ""));
        CHECK(looked.status == 200);
        CHECK(nlohmann::json::parse(looked.body).at("cardKey") == kCardKeyText);
        const ContactCard fetched = ContactCard::verify(
            fromBase64(nlohmann::json::parse(looked.body).at("card").get<std::string>()));
        CHECK(fetched.dest == dest);
        CHECK(fetched.servingSealingKeyDer == servingKey);

        {
            const std::string oldDest
                = "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
            const Bytes stale = botCard(
                alice, now, oldDest, sealing.publicDer(), servingKey);
            const std::string staleBody = nlohmann::json{{"card", toBase64(stale)}, {"cardKey", kCardKeyText}}.dump();
            CHECK(call(port, "POST", "/v1/account/card",
                      deviceSigned(alice.device, "POST", "/v1/account/card", staleBody), staleBody)
                      .status
                == 409);
            const Bytes sameAge = botCard(
                alice, now + 1, oldDest, sealing.publicDer(), servingKey);
            const std::string sameBody = nlohmann::json{{"card", toBase64(sameAge)}, {"cardKey", kCardKeyText}}.dump();
            CHECK(call(port, "POST", "/v1/account/card",
                      deviceSigned(alice.device, "POST", "/v1/account/card", sameBody), sameBody)
                      .status
                == 409);
            const http::ClientResponse again
                = call(port, "GET", "/v1/account/card?user=" + alice.fingerprint(),
                    signedHeaders(serverIdentity, "GET", "/v1/account/card?user=" + alice.fingerprint(), ""));
            CHECK(ContactCard::verify(fromBase64(
                      nlohmann::json::parse(again.body).at("card").get<std::string>()))
                      .dest
                == dest);

            const Bytes future = botCard(alice, now + 4000, oldDest,
                sealing.publicDer(), servingKey);
            const std::string futureBody = nlohmann::json{{"card", toBase64(future)}, {"cardKey", kCardKeyText}}.dump();
            CHECK(call(port, "POST", "/v1/account/card",
                      deviceSigned(alice.device, "POST", "/v1/account/card", futureBody), futureBody)
                      .status
                == 400);
        }
        CHECK(fetched.epochs.front().keyDer == sealing.publicDer());

        const http::ClientResponse unknown
            = call(port, "GET", "/v1/account/card?user=" + mallory.fingerprint(),
                    signedHeaders(serverIdentity, "GET", "/v1/account/card?user=" + mallory.fingerprint(), ""));
        CHECK(unknown.status == 404);
    }

    {
        const bazarish::i2p::Keys master = bazarish::i2p::Keys::generate();
        const bazarish::i2p::Keys delegation = master.issueTransient(kDelegationDays);
        const std::string transient = toBase64(delegation.blob());
        const std::int64_t expires = delegation.transientExpires();
        const std::string keyless
            = nlohmann::json{{"transient", transient}, {"expiresUnix", expires}}.dump();
        const std::string body = nlohmann::json{{"transient", transient}, {"expiresUnix", expires},
            {"sealingKey", kSealingPem}, {"signingKey", kSigningPem}}
                                     .dump();
        const http::ClientResponse stranger = call(port, "POST", "/v1/account/i2p-dest",
            deviceSigned(mallory.device, "POST", "/v1/account/i2p-dest", body), body);
        CHECK(stranger.status == 404);
        CHECK(nlohmann::json::parse(stranger.body).at("error").at("code") == "ACCOUNT_UNKNOWN");
        CHECK(pubCalls == 0);
        const http::ClientResponse withoutKeys = call(port, "POST", "/v1/account/i2p-dest",
            deviceSigned(alice.device, "POST", "/v1/account/i2p-dest", keyless), keyless);
        CHECK(withoutKeys.status == 400);
        CHECK(pubCalls == 0);
        {
            const Bytes full = delegation.blob();
            const Bytes oneDay = master.issueTransient(1).blob();
            const std::size_t perDay = (full.size() - oneDay.size()) / (kDelegationDays - 1);
            const Bytes todayOnly(full.begin(),
                full.end() - static_cast<std::ptrdiff_t>(perDay * (kDelegationDays - 1)));
            const std::string forged = nlohmann::json{{"transient", toBase64(todayOnly)},
                {"expiresUnix", expires}, {"sealingKey", kSealingPem}, {"signingKey", kSigningPem}}
                                           .dump();
            CHECK(call(port, "POST", "/v1/account/i2p-dest",
                      deviceSigned(alice.device, "POST", "/v1/account/i2p-dest", forged), forged)
                      .status
                == 400);
            const std::string misdated
                = nlohmann::json{{"transient", transient}, {"expiresUnix", expires + 1},
                    {"sealingKey", kSealingPem}, {"signingKey", kSigningPem}}
                      .dump();
            CHECK(call(port, "POST", "/v1/account/i2p-dest",
                      deviceSigned(alice.device, "POST", "/v1/account/i2p-dest", misdated), misdated)
                      .status
                == 400);
            CHECK(pubCalls == 0);
        }

        CHECK(!grants.peekApproval(alice.fingerprint())->pending());
        const http::ClientResponse ok = call(port, "POST", "/v1/account/i2p-dest",
            deviceSigned(alice.device, "POST", "/v1/account/i2p-dest", body), body);
        CHECK(ok.status == 200);
        CHECK(pubCalls == 1);
        CHECK(pubUser == alice.fingerprint());
        CHECK(pubTransient == transient);
        CHECK(pubExpires == expires);
        CHECK(pubKeys.sealingPem == kSealingPem);
        CHECK(pubKeys.signingPem == kSigningPem);
        const std::int64_t delegatedAt = store.getAccount(alice.fingerprint())->delegatedAt;
        CHECK(delegatedAt >= now);
        CHECK(nlohmann::json::parse(ok.body).at("dest").get<std::string>() == kServedDest);

        {
            pubAccepts = false;
            const http::ClientResponse refused = call(port, "POST", "/v1/account/i2p-dest",
                deviceSigned(alice.device, "POST", "/v1/account/i2p-dest", body), body);
            CHECK(refused.status == 503);
            const http::ClientResponse status = call(port, "GET", "/v1/account/i2p-status",
                deviceSigned(alice.device, "GET", "/v1/account/i2p-status", {}));
            CHECK(status.status == 200);
            const nlohmann::json reply = nlohmann::json::parse(status.body);
            CHECK(reply.at("transientExpires") == expires);
            pubAccepts = true;
        }

        const std::string revokeBody = nlohmann::json::object().dump();
        const http::ClientResponse revoked = call(port, "POST", "/v1/account/i2p-dest",
            deviceSigned(alice.device, "POST", "/v1/account/i2p-dest", revokeBody), revokeBody);
        CHECK(revoked.status == 200);
        CHECK(pubCalls == 3);
        CHECK(pubTransient.empty());
        CHECK(pubExpires == 0);
        CHECK(store.getAccount(alice.fingerprint())->delegatedAt == delegatedAt);
    }

    {
        const devicetest::Device tablet(alice.root, DeviceRole::eSecondary);
        const http::ClientResponse notPrimary = call(port, "DELETE", "/v1/account/registration",
            deviceSigned(tablet.credential, "DELETE", "/v1/account/registration", ""));
        CHECK(notPrimary.status == 403);
        CHECK(nlohmann::json::parse(notPrimary.body).at("error").at("code") == "DEVICE_NOT_PRIMARY");
        CHECK(grants.peekApproval(alice.fingerprint()).has_value());

        const bazarish::i2p::Keys elsewhere
            = bazarish::i2p::Keys::generate().issueTransient(kDelegationDays);
        const std::string moving = nlohmann::json{{"transient", toBase64(elsewhere.blob())},
            {"expiresUnix", elsewhere.transientExpires()}, {"sealingKey", kSealingPem},
            {"signingKey", kSigningPem}}
                                       .dump();
        const int callsBefore = pubCalls;
        const http::ClientResponse newAddress = call(port, "POST", "/v1/account/i2p-dest",
            deviceSigned(tablet.credential, "POST", "/v1/account/i2p-dest", moving), moving);
        CHECK(newAddress.status == 403);
        CHECK(nlohmann::json::parse(newAddress.body).at("error").at("code") == "DEVICE_NOT_PRIMARY");
        CHECK(pubCalls == callsBefore);

        const auto publish = [&](const Bytes& card) {
            const std::string body
                = nlohmann::json{{"card", toBase64(card)}, {"cardKey", kCardKeyText}}.dump();
            return call(port, "POST", "/v1/account/card",
                deviceSigned(alice.device, "POST", "/v1/account/card", body), body);
        };
        CHECK(publish(cardWith(alice, devicetest::bookOf(alice.root, {&alice.primary, &tablet}),
                  now + 2))
                  .status
            == 200);
        CHECK(call(port, "GET", "/v1/account/i2p-status",
                  deviceSigned(tablet.credential, "GET", "/v1/account/i2p-status", {}))
                  .status
            == 200);
        CHECK(publish(cardWith(alice,
                          devicetest::bookOf(alice.root, {&alice.primary},
                              kFirstRevocationNumber + 1, {tablet.id()}),
                          now + 3))
                  .status
            == 200);
        const http::ClientResponse revoked = call(port, "GET", "/v1/account/i2p-status",
            deviceSigned(tablet.credential, "GET", "/v1/account/i2p-status", {}));
        CHECK(revoked.status == 403);
        CHECK(nlohmann::json::parse(revoked.body).at("error").at("code") == "DEVICE_REVOKED");
        CHECK(publish(cardWith(alice, devicetest::bookOf(alice.root, {&alice.primary, &tablet}),
                  now + 4))
                  .status
            == 409);
    }

    {
        const http::ClientResponse result = call(port, "DELETE", "/v1/account/registration",
            deviceSigned(alice.device, "DELETE", "/v1/account/registration", ""));
        CHECK(result.status == 200);
        CHECK(pubCalls == 4);
        CHECK(pubTransient.empty());
        CHECK(!grants.peekApproval(alice.fingerprint()).has_value());
        CHECK(forgottenMailbox == alice.fingerprint());

        const http::ClientResponse again = call(port, "DELETE", "/v1/account/registration",
            deviceSigned(alice.device, "DELETE", "/v1/account/registration", ""));
        CHECK(again.status == 200);

        const std::string body
            = nlohmann::json{{"transient", "after-closing"}, {"expiresUnix", now + 3600}}.dump();
        const http::ClientResponse orphan = call(port, "POST", "/v1/account/i2p-dest",
            deviceSigned(alice.device, "POST", "/v1/account/i2p-dest", body), body);
        CHECK(orphan.status == 404);
        CHECK(pubCalls == 4);
    }

    {
        const http::ClientResponse served = call(port, "GET", tunnel::kNodeCardPath);
        CHECK(served.status == 200);
        CHECK(Bytes(served.body.begin(), served.body.end()) == nodeCardDer);

        const auto post = [port](const Bytes& frame) {
            http::ClientRequest request;
            request.method = "POST";
            request.target = tunnel::kNodeTunnelPath;
            request.contentType = "application/octet-stream";
            request.body = std::string(frame.begin(), frame.end());
            return http::request("127.0.0.1", port, request, {});
        };
        const devicetest::Account carol;
        grants.recordRegistration(carol.fingerprint(), now, true);
        const Bytes secret = randomBytes(kSessionSecretBytes);
        const Key replyKey = Key::generateSealing();
        tunnel::Hello hello;
        hello.secret = secret;
        hello.replyKeyDer = replyKey.publicDer();
        hello.signature = auth::signDeviceRequest(
            carol.device, now, tunnel::kHelloMethod, tunnel::kHelloPath, secret);

        const http::ClientResponse misaddressed
            = post(tunnel::sealHello(hello, Key::fromPublicDer(serverSealing.publicDer())));
        CHECK(misaddressed.status == 200);
        bool opened = true;
        try {
            (void)tunnel::openWelcome(
                Bytes(misaddressed.body.begin(), misaddressed.body.end()), replyKey);
        } catch (const std::exception&) {
            opened = false;
        }
        CHECK(!opened);

        const http::ClientResponse welcomed
            = post(tunnel::sealHello(hello, Key::fromPublicDer(nodeSealing.publicDer())));
        CHECK(welcomed.status == 200);
        CHECK(tunnel::openWelcome(Bytes(welcomed.body.begin(), welcomed.body.end()), replyKey)
                  .expiresUnix
            > now);

        const std::string id = toHex(sha256(secret)).substr(0, kSessionIdChars);
        const Bytes tunnelKey = tunnel::deriveTunnelKey(secret, id);
        const std::uint64_t seq = 1;
        const std::string handle = auth::sessionHandle(secret, seq);
        tunnel::Request inner;
        inner.method = "GET";
        inner.path = "/v1/account/i2p-status";
        const auth::Headers mac = auth::macRequest(handle, auth::deriveSessionKey(secret, id),
            seq, now, inner.method, inner.path, {});
        inner.headers = std::map<std::string, std::string>(mac.begin(), mac.end());
        const http::ClientResponse carried
            = post(tunnel::carry(handle, tunnelKey, tunnel::encodeRequest(inner)));
        CHECK(carried.status == 200);
        const tunnel::Response answer = tunnel::decodeResponse(
            tunnel::open(Bytes(carried.body.begin(), carried.body.end()), tunnelKey));
        CHECK(answer.status == 200);
        CHECK(nlohmann::json::parse(answer.body).at("approval") == "approved");
    }

    {
        const devicetest::Account ben;
        grants.recordRegistration(ben.fingerprint(), now, true);
        const bazarish::i2p::Keys delegation
            = bazarish::i2p::Keys::generate().issueTransient(kDelegationDays);
        const std::string delegated = nlohmann::json{{"transient", toBase64(delegation.blob())},
            {"expiresUnix", delegation.transientExpires()}, {"sealingKey", kSealingPem},
            {"signingKey", kSigningPem}}
                                          .dump();
        std::promise<void> revoking;
        std::promise<void> goOn;
        std::promise<void> banned;
        const std::shared_future<void> mayGoOn = goOn.get_future().share();
        const std::shared_future<void> wasBanned = banned.get_future().share();
        std::atomic<bool> revokeSeen{false};
        std::atomic<bool> publishing{false};
        pubGate = [&](const std::string& user, const std::string& transient) {
            if (user != ben.fingerprint()) {
                return;
            }
            if (transient.empty() && !revokeSeen.exchange(true)) {
                revoking.set_value();
                mayGoOn.wait();
            } else if (!transient.empty()) {
                publishing = true;
                wasBanned.wait();
            }
        };
        const std::string banBody = nlohmann::json{{"user", ben.fingerprint()}}.dump();
        std::thread banning([&]() {
            CHECK(call(opsPort, "POST", "/v1/account/ban",
                      signedHeaders(operatorIdentity, "POST", "/v1/account/ban", banBody), banBody)
                      .status
                == 200);
        });
        revoking.get_future().wait();
        std::atomic<int> delegatedStatus{0};
        std::thread delegating([&]() {
            delegatedStatus = call(port, "POST", "/v1/account/i2p-dest",
                deviceSigned(ben.device, "POST", "/v1/account/i2p-dest", delegated), delegated)
                                  .status;
        });
        while (!publishing.load() && options.userLocks->holders(ben.fingerprint()) < 2) {
            std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
        }
        goOn.set_value();
        banning.join();
        banned.set_value();
        delegating.join();
        pubGate = nullptr;
        CHECK(delegatedStatus.load() != 200);
        CHECK(!grants.peekTransient(ben.fingerprint()).has_value());
        CHECK(grants.peekBan(ben.fingerprint()).has_value());
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
