// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Tokens.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
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


// Signs a request with the caller identity and optionally attaches the
// client ID header.
httplib::Headers makeHeaders(const Identity& identity, const std::string& method,
    const std::string& path, const std::string& body, const std::string& clientId)
{
    const auth::Headers signed_ = auth::signRequest(identity,
        static_cast<std::int64_t>(std::time(nullptr)), method, path,
        Bytes(body.begin(), body.end()));
    httplib::Headers headers(signed_.begin(), signed_.end());
    if (!clientId.empty()) {
        headers.emplace("X-Bazarish-Client", clientId);
    }
    return headers;
}

std::string makeEnvelope(const std::string& toDest, const Key& serverSealingPublic,
    const nlohmann::json& inner, const Bytes& payload)
{
    const std::string innerText = inner.dump();
    const Bytes sealed
        = cms::seal(Bytes(innerText.begin(), innerText.end()), serverSealingPublic);
    const nlohmann::json envelope = {
        {"toDest", toDest},
        {"sealed", toBase64(sealed)},
        {"payload", toBase64(payload)},
    };
    return envelope.dump();
}

// Submits a send request and polls the attempt to completion.
nlohmann::json sendAndPoll(httplib::Client& client, const Identity& sender,
    const std::string& clientId, const std::string& envelope)
{
    const httplib::Result posted = client.Post("/v1/messaging/send",
        makeHeaders(sender, "POST", "/v1/messaging/send", envelope, clientId), envelope,
        "application/json");
    CHECK(posted && posted->status == 200);
    const std::string attemptId
        = nlohmann::json::parse(posted->body).at("attemptId").get<std::string>();

    // Delivery now runs on a background worker (store-and-forward), so the
    // attempt starts "pending"; poll until it reaches a terminal state.
    const std::string pollPath = "/v1/messaging/send/" + attemptId;
    nlohmann::json body;
    for (int i = 0; i < 200; ++i) {
        const httplib::Result polled
            = client.Get(pollPath, makeHeaders(sender, "GET", pollPath, "", clientId));
        CHECK(polled && polled->status == 200);
        body = nlohmann::json::parse(polled->body);
        if (body.at("status") != "pending") {
            return body;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return body;
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-httpapi-test";
    std::filesystem::remove_all(root);
    DiskStorage storage(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const std::string serverFp = serverIdentity.fingerprint();
    // A valid .b32.i2p destination for routing - the send path now enforces the
    // .b32.i2p invariant, so a bare fingerprint placeholder no longer routes.
    const std::string serverDest = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";
    const Key sealingPublic = Key::fromPublicDer(serverSealing.publicDer());

    DeliveryEngineOptions engineOptions;
    engineOptions.defaultQuotaBytes = 1024;
    engineOptions.contactRequestLimitBytes = 256;
    DeliveryEngine engine(storage, serverFp, Key::fromPrivatePem(serverSealing.privatePem()),
        engineOptions);
    HttpApiOptions httpOptions;
    // No retries in tests: a federated (unreachable) send should reach its terminal
    // "failed" at once instead of looping for minutes.
    httpOptions.deliveryMaxRounds = 1;
    // Routing is by destination. The tests assign every user the same
    // destination (serverDest, a valid .b32.i2p host) with the server's sealing
    // key, so a send to serverDest is a same-destination local delivery; a send
    // to any other destination federates (unreachable here).
    const auto serverServingKey
        = std::make_shared<Key>(Key::fromPrivatePem(serverSealing.privatePem()));
    httpOptions.assignDestination = [serverDest, serverServingKey](const std::string&) {
        return DestinationAssignment{serverDest, serverServingKey, "home"};
    };
    // Stub blob proxy: records the unsend (DELETE) op so the test can assert the
    // endpoint validated and forwarded it without a live router.
    // Operator-internal per-user destination: stub the manager so the test can
    // assert the endpoint authenticates and dispatches provision/revoke. The
    // operator is authorised by signature (its fingerprint), not a shared secret.
    const Identity operatorIdentity = Identity::generate();
    httpOptions.operatorFingerprints = {operatorIdentity.fingerprint()};
    std::string provisionedUser;
    std::string provisionedTransient;
    std::int64_t provisionedExpires = 0;
    std::string revokedUser;
    httpOptions.provisionI2pDest = [&](const std::string& user, const std::string& transientB64,
                                       const std::int64_t expiresUnix) {
        provisionedUser = user;
        provisionedTransient = transientB64;
        provisionedExpires = expiresUnix;
    };
    httpOptions.revokeI2pDest = [&](const std::string& user) { revokedUser = user; };

    // Stub federation fetch relay (proxy fallback): record the op + toDest and
    // return a canned sealed response.
    std::string relayedOp;
    std::string relayedToDest;
    RemoteFetchFn remoteFetchStub = [&relayedOp, &relayedToDest](const std::string& toDest,
                                        const std::string& op, const Bytes& sealed) {
        relayedToDest = toDest;
        relayedOp = op;
        (void)sealed;
        RemoteFetchResult result;
        result.reachable = true;
        result.ok = true;
        result.sealed = Bytes{0xAB, 0xCD};
        return result;
    };
    HttpApi api(storage, engine, httpOptions, {}, std::move(remoteFetchStub));

    const int port = api.bindToAnyPort("127.0.0.1");
    CHECK(port > 0);
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });
    httplib::Client client("127.0.0.1", port);
    CHECK(client.is_valid());

    const Identity alice = Identity::generate();
    const Identity bob = Identity::generate();

    // Unauthenticated requests are rejected.
    {
        const httplib::Result result
            = client.Post("/v1/messaging/clients", "{}", "application/json");
        CHECK(result && result->status == 401);
    }

    // Client registration for both users.
    for (const auto& [identity, clientId] :
        {std::pair<const Identity&, const char*>{alice, "alicedev"},
            std::pair<const Identity&, const char*>{bob, "bobdev"}}) {
        const std::string body = nlohmann::json{{"clientId", clientId}}.dump();
        const httplib::Result result = client.Post("/v1/messaging/clients",
            makeHeaders(identity, "POST", "/v1/messaging/clients", body, ""), body,
            "application/json");
        CHECK(result && result->status == 200);
    }

    // Messaging endpoints demand a registered client ID.
    {
        const std::string body = nlohmann::json{{"hashes", nlohmann::json::array()}}.dump();
        const httplib::Result result = client.Post("/v1/messaging/tokens",
            makeHeaders(alice, "POST", "/v1/messaging/tokens", body, "unknowndev"), body,
            "application/json");
        CHECK(result && result->status == 403);
        CHECK(nlohmann::json::parse(result->body).at("error").at("code")
            == "CLIENT_UNREGISTERED");
    }

    // Alice registers two one-time token hashes.
    const Bytes token1 = generateDeliveryToken();
    const Bytes token2 = generateDeliveryToken();
    {
        const std::string body = nlohmann::json{
            {"hashes",
                {toBase64(deliveryTokenHash(token1)), toBase64(deliveryTokenHash(token2))}},
        }.dump();
        const httplib::Result result = client.Post("/v1/messaging/tokens",
            makeHeaders(alice, "POST", "/v1/messaging/tokens", body, "alicedev"), body,
            "application/json");
        CHECK(result && result->status == 200);
    }
    CHECK(storage.tokenHashCount(alice.fingerprint()) == 2);

    // Bob delivers a message to Alice through the full local pipeline.
    const Bytes payload = {'e', '2', 'e', '-', 'b', 'l', 'o', 'b'};
    const std::string envelope = makeEnvelope(serverDest, sealingPublic,
        {{"class", "content"}, {"mailbox", alice.fingerprint()}, {"token", toBase64(token1)},
            {"messageId", "msg-1"}},
        payload);
    CHECK(sendAndPoll(client, bob, "bobdev", envelope).at("status") == "delivered");
    CHECK(storage.tokenHashCount(alice.fingerprint()) == 1);

    // An identical retry is deduplicated and consumes no second token.
    CHECK(sendAndPoll(client, bob, "bobdev", envelope).at("status") == "delivered");
    CHECK(storage.tokenHashCount(alice.fingerprint()) == 1);

    // Alice sees the message, fetches it and acks it away.
    {
        const httplib::Result pending = client.Get("/v1/messaging/pending",
            makeHeaders(alice, "GET", "/v1/messaging/pending", "", "alicedev"));
        CHECK(pending && pending->status == 200);
        const nlohmann::json list = nlohmann::json::parse(pending->body).at("pending");
        CHECK(list.size() == 1);
        CHECK(list[0].at("id") == "msg-1");
        CHECK(list[0].at("class") == "content");

        const httplib::Result blob = client.Get("/v1/messaging/pending/msg-1",
            makeHeaders(alice, "GET", "/v1/messaging/pending/msg-1", "", "alicedev"));
        CHECK(blob && blob->status == 200);
        CHECK(Bytes(blob->body.begin(), blob->body.end()) == payload);

        const std::string ackBody = nlohmann::json{{"blobId", "msg-1"}}.dump();
        const httplib::Result acked = client.Post("/v1/messaging/ack",
            makeHeaders(alice, "POST", "/v1/messaging/ack", ackBody, "alicedev"), ackBody,
            "application/json");
        CHECK(acked && acked->status == 200);
        // Alice's only client acked: deleted immediately.
        CHECK(storage.usage(alice.fingerprint()) == 0);
    }

    // A bogus token is rejected without detail.
    {
        const std::string bad = makeEnvelope(serverDest, sealingPublic,
            {{"class", "content"}, {"mailbox", alice.fingerprint()},
                {"token", toBase64(generateDeliveryToken())}, {"messageId", "msg-2"}},
            payload);
        const nlohmann::json result = sendAndPoll(client, bob, "bobdev", bad);
        CHECK(result.at("status") == "failed");
        CHECK(result.at("error").at("code") == "DELIVERY_REJECTED");
    }

    // Tokenless contact requests pass within the size cap and fail above it.
    {
        const std::string request = makeEnvelope(serverDest, sealingPublic,
            {{"class", "contact"}, {"mailbox", alice.fingerprint()},
                {"messageId", "req-1"}},
            Bytes(200, 0x55));
        CHECK(sendAndPoll(client, bob, "bobdev", request).at("status") == "delivered");

        const std::string oversized = makeEnvelope(serverDest, sealingPublic,
            {{"class", "contact"}, {"mailbox", alice.fingerprint()},
                {"messageId", "req-2"}},
            Bytes(300, 0x55));
        const nlohmann::json result = sendAndPoll(client, bob, "bobdev", oversized);
        CHECK(result.at("status") == "failed");
        CHECK(result.at("error").at("code") == "CONTACT_REQUEST_TOO_LARGE");
    }

    // Quota exhaustion restores the consumed token (STORAGE_FULL is only
    // visible past a valid token).
    {
        const std::string big = makeEnvelope(serverDest, sealingPublic,
            {{"class", "content"}, {"mailbox", alice.fingerprint()},
                {"token", toBase64(token2)}, {"messageId", "msg-3"}},
            Bytes(2000, 0x77));
        const nlohmann::json result = sendAndPoll(client, bob, "bobdev", big);
        CHECK(result.at("status") == "failed");
        CHECK(result.at("error").at("code") == "STORAGE_FULL");
        CHECK(storage.tokenHashCount(alice.fingerprint()) == 1);
    }

    // A different destination (not the sender's own) federates rather than
    // delivering locally - even though no other-destination recipient exists
    // here, so it stays unreachable (no federation transport wired in tests).
    // This is the timing guarantee: a cross-destination recipient is never a
    // fast local delivery. An exhausted-unreachable outcome is reported as
    // "unconfirmed" (not "failed"): the envelope may have been stored while only
    // its acknowledgement was lost, so a red failure would be a false negative.
    {
        const std::string remote = makeEnvelope(toBase32(Bytes(32, 0x42)) + ".b32.i2p", sealingPublic,
            {{"class", "content"}, {"mailbox", alice.fingerprint()},
                {"token", toBase64(token2)}, {"messageId", "msg-4"}},
            payload);
        const nlohmann::json result = sendAndPoll(client, bob, "bobdev", remote);
        CHECK(result.at("status") == "unconfirmed");
        CHECK(!result.contains("error"));
    }

    // The destination endpoint surfaces the caller's assigned destination + the
    // public serving sealing key (the test assignment: serverDest + server key).
    {
        const httplib::Result result = client.Get("/v1/messaging/destination",
            makeHeaders(bob, "GET", "/v1/messaging/destination", "", "bobdev"));
        CHECK(result && result->status == 200);
        const nlohmann::json body = nlohmann::json::parse(result->body);
        CHECK(body.at("dest").get<std::string>() == serverDest);
        CHECK(body.at("servingKey").get<std::string>() == toBase64(serverServingKey->publicDer()));
        CHECK(body.at("state").get<std::string>() == "home");
    }

    // First-contact discovery relay: a sealed fetch is forwarded to toDest over
    // the (stubbed) federation transport and the sealed response is returned.
    {
        const std::string body
            = nlohmann::json(
                  {{"toDest", serverDest}, {"op", "card"}, {"sealed", toBase64(Bytes{1, 2, 3})}})
                  .dump();
        const httplib::Result result = client.Post("/v1/messaging/fetch",
            makeHeaders(bob, "POST", "/v1/messaging/fetch", body, "bobdev"), body,
            "application/json");
        CHECK(result && result->status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result->body);
        CHECK(reply.at("ok").get<bool>());
        CHECK(fromBase64(reply.at("sealed").get<std::string>()) == (Bytes{0xAB, 0xCD}));
        CHECK(relayedOp == "card");
        CHECK(relayedToDest == serverDest);
    }

    // A non-.b32.i2p toDest in a fetch is refused (the .b32.i2p invariant).
    {
        const std::string body
            = nlohmann::json(
                  {{"toDest", "stats.i2p"}, {"op", "card"}, {"sealed", toBase64(Bytes{1})}})
                  .dump();
        const httplib::Result result = client.Post("/v1/messaging/fetch",
            makeHeaders(bob, "POST", "/v1/messaging/fetch", body, "bobdev"), body,
            "application/json");
        CHECK(result && result->status == 400);
    }

    // Unknown attempt IDs are reported as such.
    {
        const httplib::Result result = client.Get("/v1/messaging/send/deadbeef",
            makeHeaders(bob, "GET", "/v1/messaging/send/deadbeef", "", "bobdev"));
        CHECK(result && result->status == 404);
        CHECK(nlohmann::json::parse(result->body).at("error").at("code") == "ATTEMPT_UNKNOWN");
    }

    // Per-user I2P destination endpoint (operator signature): auth + dispatch.
    {
        const std::string body = nlohmann::json{
            {"user", "alicefp"}, {"transient", "tb64"}, {"expiresUnix", 1780001234}}
                                     .dump();
        // No signature, then a signature from an unauthorised identity -> 403.
        const httplib::Result noAuth
            = client.Put("/v1/messaging/i2p-dest", body, "application/json");
        CHECK(noAuth && noAuth->status == 403);
        const httplib::Result badAuth = client.Put("/v1/messaging/i2p-dest",
            makeHeaders(Identity::generate(), "PUT", "/v1/messaging/i2p-dest", body, ""), body,
            "application/json");
        CHECK(badAuth && badAuth->status == 403);
        // The authorised operator's signature with a transient provisions.
        const httplib::Result ok = client.Put("/v1/messaging/i2p-dest",
            makeHeaders(operatorIdentity, "PUT", "/v1/messaging/i2p-dest", body, ""), body,
            "application/json");
        CHECK(ok && ok->status == 200);
        CHECK(provisionedUser == "alicefp");
        CHECK(provisionedTransient == "tb64");
        CHECK(provisionedExpires == 1780001234);
        // The authorised operator's signature without a transient revokes.
        const std::string revokeBody = nlohmann::json{{"user", "alicefp"}}.dump();
        const httplib::Result revoked = client.Put("/v1/messaging/i2p-dest",
            makeHeaders(operatorIdentity, "PUT", "/v1/messaging/i2p-dest", revokeBody, ""),
            revokeBody, "application/json");
        CHECK(revoked && revoked->status == 200);
        CHECK(revokedUser == "alicefp");
    }

    // /healthz: operator-signed liveness with memory info; unsigned is rejected.
    {
        const httplib::Result unauth = client.Get("/healthz");
        CHECK(unauth && unauth->status == 403);
        const httplib::Result ok = client.Get(
            "/healthz", makeHeaders(operatorIdentity, "GET", "/healthz", "", ""));
        CHECK(ok && ok->status == 200);
        const nlohmann::json health = nlohmann::json::parse(ok->body);
        CHECK(health.at("service").get<std::string>() == "server-core");
        CHECK(health.contains("ramBytes"));
        CHECK(health.contains("ramPeakBytes"));
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
