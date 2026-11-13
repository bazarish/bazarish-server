// Bazarish project (c) 2026
#include "HttpApi.hpp"
#include "bazarish/JsonRead.hpp"
#include "EventGate.hpp"
#include "DeviceTestKit.hpp"
#include "HttpTestUtil.hpp"
#include "TestUtil.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/DeliveryEnvelope.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Pass.hpp>

#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Tunnel.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::server;

namespace {

using testutil::Headers;
using testutil::call;

namespace http = bazarish::http;

Headers makeHeaders(const devicetest::Device& device, const std::string& method,
    const std::string& path, const std::string& body)
{
    return testutil::deviceHeaders(device.credential, method, path, body);
}

Headers operatorHeaders(const Identity& identity, const std::string& method,
    const std::string& path, const std::string& body)
{
    return testutil::signedHeaders(identity, method, path, body);
}

Bytes sealEnvelope(const Key& serverSealingPublic, const std::string& mailbox,
    const std::string& deliveryId, const Bytes& pass)
{
    return sealDeliveryEnvelope(
        DeliveryEnvelope{"content", mailbox, deliveryId, pass}, serverSealingPublic);
}

}  // namespace

constexpr std::int64_t kNow = 1780000000;
constexpr std::size_t kHeavyPayloadBytes = 64 * 1024;

int main()
{
    const std::filesystem::path root
        = testutil::freshDir("httpapi-test");
    DiskStorage storage(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const std::string serverFp = serverIdentity.fingerprint();
    const std::string serverDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
    const Key sealingPublic = Key::fromPublicDer(serverSealing.publicDer());

    DeliveryEngineOptions engineOptions;
    engineOptions.defaultQuotaBytes = 1024;
    DeliveryEngine engine(storage, engineOptions);
    HttpApiOptions httpOptions;
    const auto serverServingKey
        = std::make_shared<Key>(Key::fromPrivatePem(serverSealing.privatePem()));
    httpOptions.sealingKey = serverServingKey;
    httpOptions.assignDestination = [serverDest](const std::string&) {
        return DestinationAssignment{serverDest, "home"};
    };
    const Identity operatorIdentity = Identity::generate();
    httpOptions.operatorFingerprints = {operatorIdentity.fingerprint()};
    const std::filesystem::path configPath = root / "server-core.json";
    {
        std::ofstream config(configPath);
        config << "{\n  \"state\": \"/var/lib/bazarish/server-core\"\n}\n";
    }
    bazarish::server::ServerSettings::Values initialSettings;
    initialSettings.logLevel = "info";
    initialSettings.i2pPrivacy = "max";
    initialSettings.i2pLogLevel = "none";
    initialSettings.listenHost = "127.0.0.1";
    initialSettings.listenPort = 8420;
    initialSettings.serviceNodeUrl = "http://127.0.0.1:8421";
    const auto serverSettings = std::make_shared<bazarish::server::ServerSettings>(
        configPath, initialSettings);
    httpOptions.settings = serverSettings;
    httpOptions.stateDirectory = "/var/lib/bazarish/server-core";
    httpOptions.fingerprint = "server-fingerprint";
    std::string provisionedUser;
    std::string provisionedTransient;
    std::int64_t provisionedExpires = 0;
    std::string provisionedSealing;
    std::string provisionedSigning;
    std::string forgottenUser;
    httpOptions.provisionI2pDest = [&](const std::string& user, const std::string& transientB64,
                                       const std::int64_t expiresUnix,
                                       const std::string& sealingKeyPem,
                                       const std::string& signingKeyPem)
        -> bazarish::server::DestinationAssignment {
        provisionedUser = user;
        provisionedTransient = transientB64;
        provisionedExpires = expiresUnix;
        provisionedSealing = sealingKeyPem;
        provisionedSigning = signingKeyPem;
        return {serverDest, "building"};
    };
    httpOptions.forgetI2pDest = [&](const std::string& user) { forgottenUser = user; };
    const Identity stranger = Identity::generate();
    const devicetest::Device strangerDev(stranger);
    const Identity alice = Identity::generate();
    const Identity bob = Identity::generate();
    const devicetest::Device aliceDev(alice);
    const devicetest::Device alicePhone(alice, DeviceRole::eSecondary);
    const devicetest::Device aliceStray(alice, DeviceRole::eSecondary);
    const devicetest::Device bobDev(bob);
    std::mutex booksMutex;
    std::map<std::string, DeviceBook> books{
        {alice.fingerprint(), devicetest::bookOf(alice, {&aliceDev, &alicePhone, &aliceStray})},
        {bob.fingerprint(), devicetest::bookOf(bob, {&bobDev})}};
    httpOptions.accountDevices = [&](const std::string& user) -> std::optional<DeviceBook> {
        const std::lock_guard<std::mutex> lock(booksMutex);
        const auto found = books.find(user);
        if (found == books.end()) {
            return std::nullopt;
        }
        return found->second;
    };
    httpOptions.reseedSample = [](std::size_t) { return std::vector<Bytes>{}; };
    int restarts = 0;
    httpOptions.requestRestart = [&restarts]() { ++restarts; };

    httpOptions.identity
        = std::make_shared<const Identity>(Identity::fromPrivatePem(serverIdentity.privatePem()));

    EventGate eventGate;
    HttpApi api(storage, eventGate, httpOptions);

    const int port = api.bind("127.0.0.1", 0);
    const int opsPort = api.bindOps("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serverThread([&api]() { api.wait(); });

    {
        const http::ClientResponse result
            = call(port, "POST", "/v1/messaging/clients", {}, "{}");
        CHECK(result.status == 401);
    }

    {
        const std::string body = nlohmann::json{{"install", "install1"}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/clients",
            makeHeaders(strangerDev, "POST", "/v1/messaging/clients", body), body);
        CHECK(result.status == 404);
        CHECK(nlohmann::json::parse(result.body).at("error").at("code") == "ACCOUNT_UNKNOWN");
        CHECK(storage.listClients(stranger.fingerprint()).empty());
        CHECK(call(port, "GET", "/v1/messaging/events",
                  makeHeaders(strangerDev, "GET", "/v1/messaging/events", ""))
                  .status
            == 404);
    }

    for (const devicetest::Device* const device : {&aliceDev, &bobDev}) {
        const std::string body = nlohmann::json{{"install", "install1"}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/clients",
            makeHeaders(*device, "POST", "/v1/messaging/clients", body), body);
        CHECK(result.status == 200);
        CHECK(call(port, "POST", "/v1/messaging/clients",
                  makeHeaders(*device, "POST", "/v1/messaging/clients", body), body)
                  .status
            == 200);
    }
    {
        const std::string twin = nlohmann::json{{"install", "install2"}}.dump();
        const http::ClientResponse taken = call(port, "POST", "/v1/messaging/clients",
            makeHeaders(bobDev, "POST", "/v1/messaging/clients", twin), twin);
        CHECK(taken.status == 409);
        CHECK(nlohmann::json::parse(taken.body).at("error").at("code") == "DEVICE_TAKEN");
    }

    {
        const Key nodeSealing = Key::generateSealing();
        const std::string body
            = nlohmann::json{{"sealingKey", toBase64(nodeSealing.publicDer())}}.dump();
        CHECK(call(opsPort, "POST", "/v1/messaging/node-card",
                  operatorHeaders(alice, "POST", "/v1/messaging/node-card", body), body)
                  .status
            == 403);
        const http::ClientResponse issued = call(opsPort, "POST", "/v1/messaging/node-card",
            operatorHeaders(operatorIdentity, "POST", "/v1/messaging/node-card", body), body);
        CHECK(issued.status == 200);
        const Bytes der
            = fromBase64(nlohmann::json::parse(issued.body).at("card").get<std::string>());
        const ServerCard card = ServerCard::verify(der, ServerCard::Service::eServiceNode);
        CHECK(card.server == serverFp);
        CHECK(card.sealingKey().fingerprint() == nodeSealing.fingerprint());
    }

    const Bytes aliceSecret = randomBytes(kDeliverySecretSize);
    const Bytes passForBob = deliveryPass(aliceSecret, std::string(52, 'b'));
    const Bytes handleForBob = deliveryPassHandle(passForBob);
    {
        const std::string body
            = nlohmann::json{{"passes", {toBase64(handleForBob)}}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes",
            makeHeaders(aliceDev, "POST", "/v1/messaging/passes", body), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("held") == 1);
    }
    {
        const std::string body
            = nlohmann::json{{"passes", {toBase64(handleForBob)}}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes",
            makeHeaders(aliceDev, "POST", "/v1/messaging/passes", body), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("held") == 1);
    }
    CHECK(storage.passCount(alice.fingerprint()) == 1);
    CHECK(storage.hasPass(alice.fingerprint(), handleForBob));

    {
        const std::string body = nlohmann::json{{"passes", nlohmann::json::array()}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes",
            makeHeaders(aliceStray, "POST", "/v1/messaging/passes", body), body);
        CHECK(result.status == 403);
    }
    {
        nlohmann::json many = nlohmann::json::array();
        for (std::size_t i = 0; i <= kMaxPassesPerRequest; ++i) {
            many.push_back(toBase64(randomBytes(kDeliveryPassSize)));
        }
        const std::string body = nlohmann::json{{"passes", many}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes",
            makeHeaders(aliceDev, "POST", "/v1/messaging/passes", body), body);
        CHECK(result.status == 400);
        CHECK(storage.passCount(alice.fingerprint()) == 1);
    }
    {
        std::vector<Bytes> filler;
        for (std::size_t i = storage.passCount(alice.fingerprint()); i < kMaxPassesPerMailbox;
             ++i) {
            filler.push_back(randomBytes(kDeliveryPassSize));
        }
        CHECK(storage.registerPasses(alice.fingerprint(), filler, kMaxPassesPerMailbox));
        CHECK(storage.passCount(alice.fingerprint()) == kMaxPassesPerMailbox);
        const auto registerPasses = [port, &alice, &aliceDev](const nlohmann::json& passes) {
            const std::string body = nlohmann::json{{"passes", passes}}.dump();
            return call(port, "POST", "/v1/messaging/passes",
                makeHeaders(aliceDev, "POST", "/v1/messaging/passes", body), body);
        };
        CHECK(registerPasses({toBase64(handleForBob), toBase64(filler.front())}).status == 200);
        CHECK(registerPasses({toBase64(randomBytes(kDeliveryPassSize))}).status == 400);
        CHECK(storage.revokePasses(alice.fingerprint(), filler) == filler.size());
        CHECK(storage.passCount(alice.fingerprint()) == 1);
    }
    {
        const Bytes handleForCarol
            = deliveryPassHandle(deliveryPass(aliceSecret, std::string(52, 'c')));
        CHECK(storage.registerPasses(alice.fingerprint(), {handleForCarol}, kMaxPassesPerMailbox));
        const std::string body
            = nlohmann::json{{"passes", {toBase64(handleForBob)}}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes/revoke",
            makeHeaders(aliceDev, "POST", "/v1/messaging/passes/revoke", body), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("revoked") == 1);
        CHECK(!storage.hasPass(alice.fingerprint(), handleForBob));
        CHECK(storage.hasPass(alice.fingerprint(), handleForCarol));
        CHECK(storage.registerPasses(alice.fingerprint(), {handleForBob}, kMaxPassesPerMailbox));
    }

    const Bytes payload = {'e', '2', 'e', '-', 'b', 'l', 'o', 'b'};
    const Bytes envelope = sealEnvelope(sealingPublic, alice.fingerprint(), "msg-1", passForBob);
    const Key engineSealing = Key::fromPrivatePem(serverSealing.privatePem());
    CHECK(engine.deliver(envelope, payload, kNow, engineSealing, alice.fingerprint(), {}).delivered);
    CHECK(storage.passCount(alice.fingerprint()) == 2);

    {
        const Bytes heavy(kHeavyPayloadBytes, 'h');
        const std::uint64_t quotaBytes = storage.userQuota(alice.fingerprint(), 1024);
        storage.setUserQuota(alice.fingerprint(), heavy.size() * 2);
        const std::size_t before = storage.passCount(alice.fingerprint());

        const Bytes admitted = sealEnvelope(sealingPublic, alice.fingerprint(), "msg-heavy", passForBob);
        CHECK(engine.deliver(admitted, heavy, kNow, engineSealing, alice.fingerprint(), {}).delivered);
        CHECK(storage.passCount(alice.fingerprint()) == before);
        storage.ackBlob(alice.fingerprint(), "msg-heavy", aliceDev.id());
        storage.setUserQuota(alice.fingerprint(), quotaBytes);
    }

    {
        const http::ClientResponse pending = call(port, "GET", "/v1/messaging/pending",
            makeHeaders(aliceDev, "GET", "/v1/messaging/pending", ""));
        CHECK(pending.status == 200);
        const nlohmann::json list = nlohmann::json::parse(pending.body).at("pending");
        CHECK(list.size() == 1);
        CHECK(list[0].at("id") == "msg-1");
        CHECK(list[0].at("class") == "content");
        CHECK(list[0].at("bytes") == payload.size());

        const std::string fetchBody = nlohmann::json{{"ids", {"msg-1", "msg-gone"}}}.dump();
        const http::ClientResponse fetched = call(port, "POST", "/v1/messaging/fetch",
            makeHeaders(aliceDev, "POST", "/v1/messaging/fetch", fetchBody), fetchBody);
        CHECK(fetched.status == 200);
        const nlohmann::json items = bazarish::parseCbor(std::string_view(fetched.body)).at("items");
        CHECK(items.size() == 1);
        CHECK(items[0].at("id") == "msg-1");
        CHECK(Bytes(items[0].at("blob").get_binary().begin(), items[0].at("blob").get_binary().end())
            == payload);

        const auto aliceQueue = [port, &alice, &aliceDev]() {
            const http::ClientResponse clients = call(port, "GET", "/v1/messaging/clients",
                makeHeaders(aliceDev, "GET", "/v1/messaging/clients", ""));
            CHECK(clients.status == 200);
            const nlohmann::json list = nlohmann::json::parse(clients.body).at("clients");
            CHECK(list.size() == 1);
            CHECK(list[0].at("device") == aliceDev.id());
            return list[0].at("queue").get<std::size_t>();
        };
        CHECK(aliceQueue() == 1);

        const std::string ackBody = nlohmann::json{{"ids", {"msg-1"}}}.dump();

        {
            Headers swapped
                = makeHeaders(aliceDev, "POST", "/v1/messaging/ack", ackBody);
            swapped[auth::kHeaderDevice] = toBase64(bobDev.certDer);
            const http::ClientResponse forged
                = call(port, "POST", "/v1/messaging/ack", swapped, ackBody);
            CHECK(forged.status == 401);
            Headers stripped
                = makeHeaders(aliceDev, "POST", "/v1/messaging/ack", ackBody);
            stripped.erase(auth::kHeaderDevice);
            CHECK(call(port, "POST", "/v1/messaging/ack", stripped, ackBody).status == 401);
            CHECK(aliceQueue() == 1);
        }

        const http::ClientResponse acked = call(port, "POST", "/v1/messaging/ack",
            makeHeaders(aliceDev, "POST", "/v1/messaging/ack", ackBody), ackBody);
        CHECK(acked.status == 200);
        CHECK(storage.usage(alice.fingerprint()) == 0);
        CHECK(aliceQueue() == 0);
    }

    {
        storage.registerClient(alice.fingerprint(), alicePhone.id(), "install1");
        CHECK(storage.putBlob(alice.fingerprint(), "seen-here", payload, "content", 1024 * 1024, kNow)
            == DiskStorage::PutResult::eStored);
        storage.ackBlob(alice.fingerprint(), "seen-here", aliceDev.id());
        CHECK(storage.hasBlob(alice.fingerprint(), "seen-here"));
        const std::string body = nlohmann::json{{"ids", {"seen-here"}}}.dump();
        const http::ClientResponse again = call(port, "POST", "/v1/messaging/fetch",
            makeHeaders(aliceDev, "POST", "/v1/messaging/fetch", body), body);
        CHECK(again.status == 200);
        CHECK(bazarish::parseCbor(std::string_view(again.body)).at("items").empty());
        storage.ackBlob(alice.fingerprint(), "seen-here", alicePhone.id());
        storage.unregisterClient(alice.fingerprint(), alicePhone.id());
    }

    {
        const Bytes half(kMaxFetchBytes / 2 + 1, 'f');
        const std::uint64_t quotaBytes = storage.userQuota(alice.fingerprint(), 1024);
        storage.setUserQuota(alice.fingerprint(), half.size() * 2);
        for (const char* const id : {"big-a", "big-b"}) {
            CHECK(storage.putBlob(alice.fingerprint(), id, half, "content", half.size() * 2, kNow)
                == DiskStorage::PutResult::eStored);
        }
        const auto fetch = [port, &alice, &aliceDev](const nlohmann::json& ids) {
            const std::string body = nlohmann::json{{"ids", ids}}.dump();
            return call(port, "POST", "/v1/messaging/fetch",
                makeHeaders(aliceDev, "POST", "/v1/messaging/fetch", body), body);
        };
        CHECK(fetch({"big-a", "big-b"}).status == 400);
        CHECK(fetch(nlohmann::json::array()).status == 400);
        CHECK(fetch({"big-a"}).status == 200);

        nlohmann::json tooMany = nlohmann::json::array();
        for (std::size_t i = 0; i <= kMaxAckIdsPerRequest; ++i) {
            tooMany.push_back("big-a");
        }
        const auto ack = [port, &alice, &aliceDev](const nlohmann::json& ids) {
            const std::string body = nlohmann::json{{"ids", ids}}.dump();
            return call(port, "POST", "/v1/messaging/ack",
                makeHeaders(aliceDev, "POST", "/v1/messaging/ack", body), body);
        };
        CHECK(ack(tooMany).status == 400);
        CHECK(storage.usage(alice.fingerprint()) == half.size() * 2);
        CHECK(ack({"big-a", "big-b"}).status == 200);
        CHECK(storage.usage(alice.fingerprint()) == 0);
        storage.setUserQuota(alice.fingerprint(), quotaBytes);
    }

    {
        const Bytes secret = randomBytes(32);
        const Key replyKey = Key::generateSealing();
        tunnel::Hello hello;
        hello.secret = secret;
        hello.replyKeyDer = replyKey.publicDer();
        hello.signature = auth::signDeviceRequest(aliceDev.credential,
            static_cast<std::int64_t>(std::time(nullptr)), tunnel::kHelloMethod, tunnel::kHelloPath,
            secret);
        const Bytes frame = tunnel::sealHello(hello, sealingPublic);
        http::ClientRequest open;
        open.method = "POST";
        open.target = tunnel::kTunnelPath;
        open.contentType = "application/octet-stream";
        open.body = std::string(frame.begin(), frame.end());
        const http::ClientResponse opened = http::request("127.0.0.1", port, open, {});
        CHECK(opened.status == 200);
        CHECK(tunnel::openWelcome(Bytes(opened.body.begin(), opened.body.end()), replyKey)
                  .expiresUnix
            > 0);

        const std::string sessionId = toHex(sha256(secret)).substr(0, 32);
        const Bytes sessionKey = auth::deriveSessionKey(secret, sessionId);
        const auto maced = [&](const std::uint64_t seq, const std::string& method,
                               const std::string& path, const std::string& body) {
            const auth::Headers headers = auth::macRequest(auth::sessionHandle(secret, seq),
                sessionKey, seq, static_cast<std::int64_t>(std::time(nullptr)), method, path,
                Bytes(body.begin(), body.end()));
            return Headers(headers.begin(), headers.end());
        };
        CHECK(call(port, "GET", "/v1/messaging/storage-usage",
                  maced(1, "GET", "/v1/messaging/storage-usage", ""))
                  .status
            == 200);
        CHECK(call(port, "GET", "/v1/messaging/pending", maced(2, "GET", "/v1/messaging/pending", ""))
                  .status
            == 200);
        CHECK(call(port, "GET", "/v1/messaging/storage-usage",
                  maced(1, "GET", "/v1/messaging/storage-usage", ""))
                  .status
            == 401);
    }

    {
        const std::string install = nlohmann::json{{"install", "install1"}}.dump();
        CHECK(call(port, "POST", "/v1/messaging/clients",
                  makeHeaders(alicePhone, "POST", "/v1/messaging/clients", install), install)
                  .status
            == 200);
        const auto toSelf = [&](const devicetest::Device& from, const std::string& id,
                                const std::string& to) {
            const std::string body = nlohmann::json{{"deliveryId", id},
                {"payload", toBase64(Bytes{1, 2, 3})}, {"to", to}}.dump();
            return call(port, "POST", "/v1/messaging/self",
                makeHeaders(from, "POST", "/v1/messaging/self", body), body);
        };
        const auto pendingIds = [&](const devicetest::Device& device) {
            const http::ClientResponse listed = call(port, "GET", "/v1/messaging/pending",
                makeHeaders(device, "GET", "/v1/messaging/pending", ""));
            std::set<std::string> ids;
            if (listed.status != 200) {
                return ids;
            }
            const nlohmann::json answer = nlohmann::json::parse(listed.body);
            for (const nlohmann::json& entry : answer.at("pending")) {
                ids.insert(entry.at("id").get<std::string>());
            }
            return ids;
        };
        CHECK(toSelf(aliceDev, "to-phone", alicePhone.id()).status == 200);
        CHECK(toSelf(aliceDev, "to-myself", aliceDev.id()).status == 404);
        CHECK(toSelf(aliceDev, "to-nobody", "aaaaaaaaaa").status == 404);
        CHECK(pendingIds(alicePhone).count("to-phone") == 1);
        CHECK(pendingIds(aliceDev).count("to-phone") == 0);
        {
            const std::string body = nlohmann::json{{"ids", {"to-phone"}}}.dump();
            const http::ClientResponse fetched = call(port, "POST", "/v1/messaging/fetch",
                makeHeaders(aliceDev, "POST", "/v1/messaging/fetch", body), body);
            CHECK(bazarish::parseCbor(std::string_view(fetched.body)).at("items").empty());
            CHECK(call(port, "POST", "/v1/messaging/ack",
                      makeHeaders(aliceDev, "POST", "/v1/messaging/ack", body), body)
                      .status
                == 200);
            CHECK(storage.hasBlob(alice.fingerprint(), "to-phone"));
            CHECK(call(port, "POST", "/v1/messaging/ack",
                      makeHeaders(alicePhone, "POST", "/v1/messaging/ack", body), body)
                      .status
                == 200);
            CHECK(!storage.hasBlob(alice.fingerprint(), "to-phone"));
        }

        {
            const std::lock_guard<std::mutex> lock(booksMutex);
            books[alice.fingerprint()] = devicetest::bookOf(
                alice, {&aliceDev, &aliceStray}, kFirstRevocationNumber + 1, {alicePhone.id()});
        }
        const http::ClientResponse revoked = call(port, "GET", "/v1/messaging/pending",
            makeHeaders(alicePhone, "GET", "/v1/messaging/pending", ""));
        CHECK(revoked.status == 403);
        CHECK(nlohmann::json::parse(revoked.body).at("error").at("code") == "DEVICE_REVOKED");
        CHECK(!storage.isClientRegistered(alice.fingerprint(), alicePhone.id()));
        CHECK(call(port, "POST", "/v1/messaging/clients",
                  makeHeaders(alicePhone, "POST", "/v1/messaging/clients", install), install)
                  .status
            == 403);
        CHECK(!storage.isClientRegistered(alice.fingerprint(), alicePhone.id()));
        CHECK(toSelf(aliceDev, "to-revoked", alicePhone.id()).status == 404);
        CHECK(call(port, "GET", "/v1/messaging/pending",
                  makeHeaders(aliceDev, "GET", "/v1/messaging/pending", ""))
                  .status
            == 200);
    }

    {
        const http::ClientResponse result = call(port, "GET", "/v1/messaging/destination",
            makeHeaders(bobDev, "GET", "/v1/messaging/destination", ""));
        CHECK(result.status == 200);
        const nlohmann::json body = nlohmann::json::parse(result.body);
        CHECK(body.at("dest").get<std::string>() == serverDest);
        CHECK(body.at("state").get<std::string>() == "home");
    }

    {
        const std::string keyless = nlohmann::json{
            {"user", "alicefp"}, {"transient", "tb64"}, {"expiresUnix", 1780001234}}
                                        .dump();
        const http::ClientResponse withoutKeys = call(opsPort, "PUT", "/v1/messaging/i2p-dest",
            operatorHeaders(operatorIdentity, "PUT", "/v1/messaging/i2p-dest", keyless), keyless);
        CHECK(withoutKeys.status == 400);
        CHECK(provisionedUser.empty());
        const std::string body = nlohmann::json{{"user", "alicefp"}, {"transient", "tb64"},
            {"expiresUnix", 1780001234}, {"sealingKey", "sealing-pem"},
            {"signingKey", "signing-pem"}}
                                     .dump();
        const http::ClientResponse noAuth
            = call(opsPort, "PUT", "/v1/messaging/i2p-dest", {}, body);
        CHECK(noAuth.status == 403);
        const http::ClientResponse badAuth = call(opsPort, "PUT", "/v1/messaging/i2p-dest",
            operatorHeaders(Identity::generate(), "PUT", "/v1/messaging/i2p-dest", body), body);
        CHECK(badAuth.status == 403);
        const http::ClientResponse ok = call(opsPort, "PUT", "/v1/messaging/i2p-dest",
            operatorHeaders(operatorIdentity, "PUT", "/v1/messaging/i2p-dest", body), body);
        CHECK(ok.status == 200);
        CHECK(provisionedUser == "alicefp");
        CHECK(provisionedTransient == "tb64");
        CHECK(provisionedExpires == 1780001234);
        CHECK(provisionedSealing == "sealing-pem");
        CHECK(provisionedSigning == "signing-pem");
        CHECK(nlohmann::json::parse(ok.body).at("dest").get<std::string>() == serverDest);
        const std::string offlineBody = nlohmann::json{{"user", "alicefp"}}.dump();
        const http::ClientResponse offline = call(opsPort, "PUT", "/v1/messaging/i2p-dest",
            operatorHeaders(operatorIdentity, "PUT", "/v1/messaging/i2p-dest", offlineBody),
            offlineBody);
        CHECK(offline.status == 200);
        CHECK(forgottenUser == "alicefp");
    }

    {
        const std::string seeds = "/internal/i2pseeds.su3";
        CHECK(call(opsPort, "GET", seeds).status == 403);
        CHECK(call(opsPort, "GET", seeds, operatorHeaders(operatorIdentity, "GET", seeds, ""))
                  .status
            == 503);
    }

    {
        const http::ClientResponse unauth = call(opsPort, "GET", "/healthz");
        CHECK(unauth.status == 403);
        const http::ClientResponse ok = call(opsPort, "GET",
            "/healthz", operatorHeaders(operatorIdentity, "GET", "/healthz", ""));
        CHECK(ok.status == 200);
        const nlohmann::json health = nlohmann::json::parse(ok.body);
        CHECK(health.at("service").get<std::string>() == "server-core");
        CHECK(health.contains("ramBytes"));
        CHECK(health.contains("ramPeakBytes"));
    }

    {
        const std::string path = "/v1/messaging/account?user=" + alice.fingerprint();
        const Bytes payload = {'l', 'a', 's', 't'};
        CHECK(engine
                  .deliver(sealEnvelope(sealingPublic, alice.fingerprint(), "msg-last", passForBob),
                      payload, kNow, engineSealing, alice.fingerprint(), {})
                  .delivered);
        CHECK(storage.usage(alice.fingerprint()) > 0);

        CHECK(call(opsPort, "DELETE", path).status == 403);
        CHECK(call(opsPort, "DELETE", path,
                   operatorHeaders(Identity::generate(), "DELETE", path, ""))
                  .status
            == 403);
        const std::string other
            = "/v1/messaging/account?user=" + Identity::generate().fingerprint();
        CHECK(call(opsPort, "DELETE", path, operatorHeaders(operatorIdentity, "DELETE", other, ""))
                  .status
            == 403);
        CHECK(call(opsPort, "DELETE", path,
                  operatorHeaders(operatorIdentity, "DELETE", "/v1/messaging/account", ""))
                  .status
            == 403);

        const http::ClientResponse deleted = call(opsPort, "DELETE", path,
            operatorHeaders(operatorIdentity, "DELETE", path, ""));
        CHECK(deleted.status == 200);
        CHECK(forgottenUser == alice.fingerprint());
        CHECK(storage.usage(alice.fingerprint()) == 0);
        CHECK(storage.listClients(alice.fingerprint()).empty());
        CHECK(storage.passCount(alice.fingerprint()) == 0);
        CHECK(call(opsPort, "DELETE", path, operatorHeaders(operatorIdentity, "DELETE", path, ""))
                  .status
            == 200);
    }

    {
        const std::string path = "/v1/messaging/settings";
        CHECK(call(opsPort, "GET", path).status == 403);

        const http::ClientResponse shown
            = call(opsPort, "GET", path, operatorHeaders(operatorIdentity, "GET", path, {}));
        CHECK(shown.status == 200);
        const nlohmann::json values = nlohmann::json::parse(shown.body);
        CHECK(!values.contains("i2pTunnelQuantity"));
        CHECK(values.at("i2pPrivacy").get<std::string>() == "max");
        CHECK(values.at("i2pLogLevel").get<std::string>() == "none");
        CHECK(!values.contains("i2pLog"));

        const std::string body = nlohmann::json{{"logLevel", "debug"},
            {"i2pPrivacy", "middle"}, {"i2pLogLevel", "info"}}
                                     .dump();
        CHECK(call(opsPort, "PUT", path, operatorHeaders(operatorIdentity, "PUT", path, body), body)
                  .status
            == 200);
        CHECK(bazarish::log::level() == bazarish::log::Level::eDebug);
        CHECK(bazarish::i2p::i2pLogLevel() == bazarish::i2p::I2pLogLevel::eInfo);

        std::ifstream written(configPath);
        const nlohmann::json onDisk = nlohmann::json::parse(written);
        CHECK(onDisk.at("logLevel").get<std::string>() == "debug");
        CHECK(onDisk.at("i2p").at("privacy").get<std::string>() == "middle");
        CHECK(onDisk.at("i2p").at("logLevel").get<std::string>() == "info");
        CHECK(onDisk.at("state").get<std::string>() == "/var/lib/bazarish/server-core");

        const std::string nonsense = nlohmann::json{{"i2pPrivacy", "invisible"}}.dump();
        CHECK(call(opsPort, "PUT", path,
                  operatorHeaders(operatorIdentity, "PUT", path, nonsense), nonsense)
                  .status
            == 400);
        const std::string loud = nlohmann::json{{"i2pLogLevel", "warning"}}.dump();
        CHECK(call(opsPort, "PUT", path, operatorHeaders(operatorIdentity, "PUT", path, loud), loud)
                  .status
            == 400);
        CHECK(bazarish::i2p::i2pLogLevel() == bazarish::i2p::I2pLogLevel::eInfo);
        const std::string moved = nlohmann::json{{"serviceNode", "https://127.0.0.1:9421"}}.dump();
        CHECK(call(opsPort, "PUT", path, operatorHeaders(operatorIdentity, "PUT", path, moved), moved)
                  .status
            == 200);
        std::ifstream rewritten(configPath);
        CHECK(nlohmann::json::parse(rewritten).at("serviceNode").at("url").get<std::string>()
            == "https://127.0.0.1:9421");
        const std::string quiet
            = nlohmann::json{{"logLevel", "info"}, {"i2pLogLevel", "none"}}.dump();
        CHECK(call(opsPort, "PUT", path, operatorHeaders(operatorIdentity, "PUT", path, quiet), quiet)
                  .status
            == 200);

        const std::string restart = "/v1/messaging/restart";
        CHECK(call(opsPort, "POST", restart,
                  operatorHeaders(operatorIdentity, "POST", restart, {}))
                  .status
            == 200);
        CHECK(restarts == 1);
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
