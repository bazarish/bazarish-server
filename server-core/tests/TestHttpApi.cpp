// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Pass.hpp>

#include <bazarish/HttpClient.hpp>
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
#include <memory>
#include <string>
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
using namespace bazarish::server;

namespace {

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
    const std::string& path, const std::string& body, const std::string& clientId)
{
    const auth::Headers signed_ = auth::signRequest(identity,
        static_cast<std::int64_t>(std::time(nullptr)), method, path,
        Bytes(body.begin(), body.end()), clientId);
    Headers headers(signed_.begin(), signed_.end());
    if (!clientId.empty()) {
        headers.emplace("X-Bazarish-Client", clientId);
    }
    return headers;
}

Bytes sealEnvelope(const Key& serverSealingPublic, const nlohmann::json& inner)
{
    const std::string innerText = inner.dump();
    return hybrid::seal(Bytes(innerText.begin(), innerText.end()), serverSealingPublic);
}

}  // namespace

// The engine takes unix seconds; nothing in this test depends on the wall clock.
constexpr std::int64_t kNow = 1780000000;
constexpr std::size_t kHeavyPayloadBytes = 64 * 1024;

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-httpapi-test";
    std::filesystem::remove_all(root);
    DiskStorage storage(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const std::string serverFp = serverIdentity.fingerprint();
    const std::string serverDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
    const Key sealingPublic = Key::fromPublicDer(serverSealing.publicDer());

    DeliveryEngineOptions engineOptions;
    engineOptions.defaultQuotaBytes = 1024;
    DeliveryEngine engine(storage, serverFp,
        std::make_shared<Key>(Key::fromPrivatePem(serverSealing.privatePem())), engineOptions);
    HttpApiOptions httpOptions;
    const auto serverServingKey
        = std::make_shared<Key>(Key::fromPrivatePem(serverSealing.privatePem()));
    httpOptions.assignDestination = [serverDest, serverServingKey](const std::string&) {
        return DestinationAssignment{serverDest, serverServingKey, "home"};
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
    initialSettings.i2pTunnelQuantity = 16;
    initialSettings.federationRateLimit = 240;
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
    std::string revokedUser;
    httpOptions.provisionI2pDest = [&](const std::string& user, const std::string& transientB64,
                                       const std::int64_t expiresUnix)
        -> bazarish::server::DestinationAssignment {
        provisionedUser = user;
        provisionedTransient = transientB64;
        provisionedExpires = expiresUnix;
        return {serverDest, serverServingKey, "building"};
    };
    httpOptions.revokeI2pDest = [&](const std::string& user) { revokedUser = user; };

    HttpApi api(storage, httpOptions);

    const int port = api.bind("127.0.0.1", 0);
    const int opsPort = api.bindOps("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serverThread([&api]() { api.wait(); });

    const Identity alice = Identity::generate();
    const Identity bob = Identity::generate();

    {
        const http::ClientResponse result
            = call(port, "POST", "/v1/messaging/clients", {}, "{}");
        CHECK(result.status == 401);
    }

    for (const auto& [identity, clientId] :
        {std::pair<const Identity&, const char*>{alice, "alicedev"},
            std::pair<const Identity&, const char*>{bob, "bobdev"}}) {
        const std::string body = nlohmann::json{{"clientId", clientId}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/clients",
            makeHeaders(identity, "POST", "/v1/messaging/clients", body, ""), body);
        CHECK(result.status == 200);
    }

    const Bytes aliceSecret = randomBytes(kDeliverySecretSize);
    const Bytes passForBob = deliveryPass(aliceSecret, std::string(52, 'b'));
    const Bytes handleForBob = deliveryPassHandle(passForBob);
    {
        const std::string body
            = nlohmann::json{{"passes", {toBase64(handleForBob)}}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes",
            makeHeaders(alice, "POST", "/v1/messaging/passes", body, "alicedev"), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("held") == 1);
    }
    {
        const std::string body
            = nlohmann::json{{"passes", {toBase64(handleForBob)}}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes",
            makeHeaders(alice, "POST", "/v1/messaging/passes", body, "alicedev"), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("held") == 1);
    }
    CHECK(storage.passCount(alice.fingerprint()) == 1);
    CHECK(storage.hasPass(alice.fingerprint(), handleForBob));

    {
        const std::string body = nlohmann::json{{"passes", nlohmann::json::array()}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes",
            makeHeaders(alice, "POST", "/v1/messaging/passes", body, "unknowndev"), body);
        CHECK(result.status == 403);
    }
    {
        nlohmann::json many = nlohmann::json::array();
        for (std::size_t i = 0; i <= kMaxPassesPerRequest; ++i) {
            many.push_back(toBase64(randomBytes(kDeliveryPassSize)));
        }
        const std::string body = nlohmann::json{{"passes", many}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes",
            makeHeaders(alice, "POST", "/v1/messaging/passes", body, "alicedev"), body);
        CHECK(result.status == 400);
        CHECK(storage.passCount(alice.fingerprint()) == 1);
    }
    {
        const Bytes handleForCarol
            = deliveryPassHandle(deliveryPass(aliceSecret, std::string(52, 'c')));
        storage.registerPasses(alice.fingerprint(), {handleForCarol});
        const std::string body
            = nlohmann::json{{"passes", {toBase64(handleForBob)}}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/passes/revoke",
            makeHeaders(alice, "POST", "/v1/messaging/passes/revoke", body, "alicedev"), body);
        CHECK(result.status == 200);
        CHECK(nlohmann::json::parse(result.body).at("revoked") == 1);
        CHECK(!storage.hasPass(alice.fingerprint(), handleForBob));
        CHECK(storage.hasPass(alice.fingerprint(), handleForCarol));
        storage.registerPasses(alice.fingerprint(), {handleForBob});
    }

    const Bytes payload = {'e', '2', 'e', '-', 'b', 'l', 'o', 'b'};
    const Bytes envelope = sealEnvelope(sealingPublic,
        {{"class", "content"}, {"mailbox", alice.fingerprint()},
            {"pass", toBase64(passForBob)}, {"deliveryId", "msg-1"}});
    const Key engineSealing = Key::fromPrivatePem(serverSealing.privatePem());
    CHECK(engine.deliver(envelope, payload, kNow, engineSealing, alice.fingerprint()).delivered);
    CHECK(storage.passCount(alice.fingerprint()) == 2);

    {
        const Bytes heavy(kHeavyPayloadBytes, 'h');
        const std::uint64_t quotaBytes = storage.userQuota(alice.fingerprint(), 1024);
        storage.setUserQuota(alice.fingerprint(), heavy.size() * 2);
        const std::size_t before = storage.passCount(alice.fingerprint());

        const Bytes admitted = sealEnvelope(sealingPublic,
            {{"class", "content"}, {"mailbox", alice.fingerprint()},
                {"pass", toBase64(passForBob)}, {"deliveryId", "msg-heavy"}});
        CHECK(engine.deliver(admitted, heavy, kNow, engineSealing, alice.fingerprint()).delivered);
        CHECK(storage.passCount(alice.fingerprint()) == before);
        storage.ackBlob(alice.fingerprint(), "msg-heavy", "alicedev");
        storage.setUserQuota(alice.fingerprint(), quotaBytes);
    }

    {
        const http::ClientResponse pending = call(port, "GET", "/v1/messaging/pending",
            makeHeaders(alice, "GET", "/v1/messaging/pending", "", "alicedev"));
        CHECK(pending.status == 200);
        const nlohmann::json list = nlohmann::json::parse(pending.body).at("pending");
        CHECK(list.size() == 1);
        CHECK(list[0].at("id") == "msg-1");
        CHECK(list[0].at("class") == "content");

        const http::ClientResponse blob = call(port, "GET", "/v1/messaging/pending/msg-1",
            makeHeaders(alice, "GET", "/v1/messaging/pending/msg-1", "", "alicedev"));
        CHECK(blob.status == 200);
        CHECK(Bytes(blob.body.begin(), blob.body.end()) == payload);

        const auto aliceQueue = [port, &alice]() {
            const http::ClientResponse clients = call(port, "GET", "/v1/messaging/clients",
                makeHeaders(alice, "GET", "/v1/messaging/clients", "", "alicedev"));
            CHECK(clients.status == 200);
            const nlohmann::json list = nlohmann::json::parse(clients.body).at("clients");
            CHECK(list.size() == 1);
            CHECK(list[0].at("clientId") == "alicedev");
            return list[0].at("queue").get<std::size_t>();
        };
        CHECK(aliceQueue() == 1);

        const std::string ackBody = nlohmann::json{{"blobId", "msg-1"}}.dump();

        {
            Headers swapped
                = makeHeaders(alice, "POST", "/v1/messaging/ack", ackBody, "alicedev");
            swapped["X-Bazarish-Client"] = "bobdev";
            const http::ClientResponse forged
                = call(port, "POST", "/v1/messaging/ack", swapped, ackBody);
            CHECK(forged.status == 401);
            Headers stripped
                = makeHeaders(alice, "POST", "/v1/messaging/ack", ackBody, "alicedev");
            stripped.erase("X-Bazarish-Client");
            CHECK(call(port, "POST", "/v1/messaging/ack", stripped, ackBody).status == 401);
            CHECK(aliceQueue() == 1);
        }

        const http::ClientResponse acked = call(port, "POST", "/v1/messaging/ack",
            makeHeaders(alice, "POST", "/v1/messaging/ack", ackBody, "alicedev"), ackBody);
        CHECK(acked.status == 200);
        CHECK(storage.usage(alice.fingerprint()) == 0);
        CHECK(aliceQueue() == 0);
    }

    {
        const Bytes secret = randomBytes(32);
        const Key replyKey = Key::generateSealing();
        const std::string inner = nlohmann::json{{"secret", toBase64(secret)},
            {"replyKey", toBase64(replyKey.publicDer())}}.dump();
        const std::string openBody = nlohmann::json{{"sealed",
            toBase64(hybrid::seal(Bytes(inner.begin(), inner.end()), sealingPublic))}}.dump();

        const http::ClientResponse opened = call(port, "POST", "/v1/auth/session",
            makeHeaders(alice, "POST", "/v1/auth/session", openBody, "alicedev"), openBody);
        CHECK(opened.status == 200);
        const Bytes answer = hybrid::unseal(
            fromBase64(nlohmann::json::parse(opened.body).at("sealed").get<std::string>()),
            replyKey);
        const nlohmann::json term = nlohmann::json::parse(answer.begin(), answer.end());
        CHECK(term.at("expiresUnix").get<std::int64_t>() > 0);

        const std::string sessionId = toHex(sha256(secret)).substr(0, 32);
        const Bytes sessionKey = auth::deriveSessionKey(secret, sessionId);
        const auto maced = [&](const std::uint64_t seq, const std::string& method,
                               const std::string& path, const std::string& body,
                               const std::string& clientId) {
            const auth::Headers headers = auth::macRequest(auth::sessionHandle(secret, seq),
                sessionKey, seq, static_cast<std::int64_t>(std::time(nullptr)), method, path,
                Bytes(body.begin(), body.end()), clientId);
            Headers out(headers.begin(), headers.end());
            out.emplace("X-Bazarish-Client", clientId);
            return out;
        };
        CHECK(call(port, "GET", "/v1/messaging/storage-usage",
                  maced(1, "GET", "/v1/messaging/storage-usage", "", "alicedev"))
                  .status
            == 200);
        {
            Headers swapped = maced(2, "GET", "/v1/messaging/storage-usage", "", "alicedev");
            swapped["X-Bazarish-Client"] = "bobdev";
            CHECK(call(port, "GET", "/v1/messaging/storage-usage", swapped).status == 401);
        }

        const http::ClientResponse chained = call(port, "POST", "/v1/auth/session",
            maced(3, "POST", "/v1/auth/session", openBody, "alicedev"), openBody);
        CHECK(chained.status == 401);
        CHECK(nlohmann::json::parse(chained.body).at("error").at("code") == "SESSION_INVALID");
    }

    {
        const http::ClientResponse result = call(port, "GET", "/v1/messaging/destination",
            makeHeaders(bob, "GET", "/v1/messaging/destination", "", "bobdev"));
        CHECK(result.status == 200);
        const nlohmann::json body = nlohmann::json::parse(result.body);
        CHECK(body.at("dest").get<std::string>() == serverDest);
        CHECK(body.at("servingKey").get<std::string>() == toBase64(serverServingKey->publicDer()));
        CHECK(body.at("state").get<std::string>() == "home");
    }

    {
        const std::string body = nlohmann::json{
            {"user", "alicefp"}, {"transient", "tb64"}, {"expiresUnix", 1780001234}}
                                     .dump();
        const http::ClientResponse noAuth
            = call(opsPort, "PUT", "/v1/messaging/i2p-dest", {}, body);
        CHECK(noAuth.status == 403);
        const http::ClientResponse badAuth = call(opsPort, "PUT", "/v1/messaging/i2p-dest",
            makeHeaders(Identity::generate(), "PUT", "/v1/messaging/i2p-dest", body, ""), body);
        CHECK(badAuth.status == 403);
        const http::ClientResponse ok = call(opsPort, "PUT", "/v1/messaging/i2p-dest",
            makeHeaders(operatorIdentity, "PUT", "/v1/messaging/i2p-dest", body, ""), body);
        CHECK(ok.status == 200);
        CHECK(provisionedUser == "alicefp");
        CHECK(provisionedTransient == "tb64");
        CHECK(provisionedExpires == 1780001234);
        {
            const nlohmann::json served = nlohmann::json::parse(ok.body);
            CHECK(served.at("dest").get<std::string>() == serverDest);
            CHECK(served.at("servingKey").get<std::string>()
                == toBase64(serverServingKey->publicDer()));
        }
        const std::string revokeBody = nlohmann::json{{"user", "alicefp"}}.dump();
        const http::ClientResponse revoked = call(opsPort, "PUT", "/v1/messaging/i2p-dest",
            makeHeaders(operatorIdentity, "PUT", "/v1/messaging/i2p-dest", revokeBody, ""),
            revokeBody);
        CHECK(revoked.status == 200);
        CHECK(revokedUser == "alicefp");
    }

    {
        const http::ClientResponse unauth = call(opsPort, "GET", "/healthz");
        CHECK(unauth.status == 403);
        const http::ClientResponse ok = call(opsPort, "GET",
            "/healthz", makeHeaders(operatorIdentity, "GET", "/healthz", "", ""));
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
                  .deliver(sealEnvelope(sealingPublic,
                               {{"class", "content"}, {"mailbox", alice.fingerprint()},
                                   {"pass", toBase64(passForBob)}, {"deliveryId", "msg-last"}}),
                      payload, kNow, engineSealing, alice.fingerprint())
                  .delivered);
        CHECK(storage.usage(alice.fingerprint()) > 0);

        CHECK(call(opsPort, "DELETE", path).status == 403);
        CHECK(call(opsPort, "DELETE", path,
                   makeHeaders(Identity::generate(), "DELETE", "/v1/messaging/account", "", ""))
                  .status
            == 403);

        const http::ClientResponse deleted = call(opsPort, "DELETE", path,
            makeHeaders(operatorIdentity, "DELETE", "/v1/messaging/account", "", ""));
        CHECK(deleted.status == 200);
        CHECK(storage.usage(alice.fingerprint()) == 0);
        CHECK(storage.listClients(alice.fingerprint()).empty());
        CHECK(storage.passCount(alice.fingerprint()) == 0);
        CHECK(call(opsPort, "DELETE", path,
                   makeHeaders(operatorIdentity, "DELETE", "/v1/messaging/account", "", ""))
                  .status
            == 200);
    }

    {
        const std::string path = "/v1/messaging/settings";
        CHECK(call(opsPort, "GET", path).status == 403);

        const http::ClientResponse shown
            = call(opsPort, "GET", path, makeHeaders(operatorIdentity, "GET", path, {}, {}));
        CHECK(shown.status == 200);
        const nlohmann::json values = nlohmann::json::parse(shown.body);
        CHECK(values.at("federationRateLimit").get<int>() == 240);
        CHECK(values.at("i2pPrivacy").get<std::string>() == "max");
        CHECK(values.at("i2pTunnelQuantityMax").get<int>() == bazarish::i2p::kMaxTunnelQuantity);

        const std::string body = nlohmann::json{{"logLevel", "debug"},
            {"i2pPrivacy", "middle"}, {"federationRateLimit", 60}}
                                     .dump();
        CHECK(call(opsPort, "PUT", path, makeHeaders(operatorIdentity, "PUT", path, body, {}), body)
                  .status
            == 200);
        CHECK(bazarish::log::level() == bazarish::log::Level::eDebug);
        CHECK(serverSettings->get().federationRateLimit == 60);

        std::ifstream written(configPath);
        const nlohmann::json onDisk = nlohmann::json::parse(written);
        CHECK(onDisk.at("logLevel").get<std::string>() == "debug");
        CHECK(onDisk.at("i2p").at("privacy").get<std::string>() == "middle");
        CHECK(onDisk.at("federationRateLimit").get<int>() == 60);
        CHECK(onDisk.at("state").get<std::string>() == "/var/lib/bazarish/server-core");

        const std::string nonsense = nlohmann::json{{"i2pPrivacy", "invisible"}}.dump();
        CHECK(call(opsPort, "PUT", path,
                  makeHeaders(operatorIdentity, "PUT", path, nonsense, {}), nonsense)
                  .status
            == 400);
        const std::string tooMany = nlohmann::json{{"i2pTunnelQuantity", 99}}.dump();
        CHECK(call(opsPort, "PUT", path,
                  makeHeaders(operatorIdentity, "PUT", path, tooMany, {}), tooMany)
                  .status
            == 400);
        const std::string quiet = nlohmann::json{{"logLevel", "info"}}.dump();
        CHECK(call(opsPort, "PUT", path, makeHeaders(operatorIdentity, "PUT", path, quiet, {}), quiet)
                  .status
            == 200);

        const std::string restart = "/v1/messaging/restart";
        CHECK(call(opsPort, "POST", restart,
                  makeHeaders(operatorIdentity, "POST", restart, {}, {}))
                  .status
            == 503);
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
