// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Tokens.hpp>

#include <bazarish/HttpClient.hpp>
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

// Signs a request with the caller identity and optionally attaches the
// client ID header.
Headers makeHeaders(const Identity& identity, const std::string& method,
    const std::string& path, const std::string& body, const std::string& clientId)
{
    const auth::Headers signed_ = auth::signRequest(identity,
        static_cast<std::int64_t>(std::time(nullptr)), method, path,
        Bytes(body.begin(), body.end()));
    Headers headers(signed_.begin(), signed_.end());
    if (!clientId.empty()) {
        headers.emplace("X-Bazarish-Client", clientId);
    }
    return headers;
}

// A delivery envelope sealed to a destination's serving key. Outgoing mail is
// the client's own business now, so what reaches this server's engine arrives on
// a destination's accept loop, not through a route of its own - and this test
// hands it straight to the engine, exactly as that loop does.
Bytes sealEnvelope(const Key& serverSealingPublic, const nlohmann::json& inner)
{
    const std::string innerText = inner.dump();
    return cms::seal(Bytes(innerText.begin(), innerText.end()), serverSealingPublic);
}

}  // namespace

// The engine takes unix seconds; nothing in this test depends on the wall clock.
constexpr std::int64_t kNow = 1780000000;

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
    DeliveryEngine engine(storage, serverFp, Key::fromPrivatePem(serverSealing.privatePem()),
        engineOptions);
    HttpApiOptions httpOptions;
    // Routing is by destination, and a destination belongs to one user - so a
    // delivery to serverDest is only ever local when the sender is the user it
    // was assigned to. Every user here is assigned serverDest, which makes a
    // send to oneself the local path and a send to a peer federate (unreachable
    // here), exactly as it does in a deployment where each user has their own.
    const auto serverServingKey
        = std::make_shared<Key>(Key::fromPrivatePem(serverSealing.privatePem()));
    httpOptions.assignDestination = [serverDest, serverServingKey](const std::string&) {
        return DestinationAssignment{serverDest, serverServingKey, "home"};
    };
    // Private reseed: the sampler stands in for the running router's netDb and
    // records what was asked of it.
    std::size_t reseedAsked = 0;
    std::size_t reseedAvailable = 3;
    httpOptions.reseedSample = [&](const std::size_t count) {
        reseedAsked = count;
        std::vector<Bytes> routers;
        for (std::size_t i = 0; i < std::min(count, reseedAvailable); ++i) {
            const std::string router = "routerinfo-" + std::to_string(i);
            routers.emplace_back(router.begin(), router.end());
        }
        return routers;
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

    HttpApi api(storage, engine, httpOptions);

    const int port = api.bindToAnyPort("127.0.0.1");
    CHECK(port > 0);
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });

    const Identity alice = Identity::generate();
    const Identity bob = Identity::generate();

    // Unauthenticated requests are rejected.
    {
        const http::ClientResponse result
            = call(port, "POST", "/v1/messaging/clients", {}, "{}");
        CHECK(result.status == 401);
    }

    // Client registration for both users.
    for (const auto& [identity, clientId] :
        {std::pair<const Identity&, const char*>{alice, "alicedev"},
            std::pair<const Identity&, const char*>{bob, "bobdev"}}) {
        const std::string body = nlohmann::json{{"clientId", clientId}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/clients",
            makeHeaders(identity, "POST", "/v1/messaging/clients", body, ""), body);
        CHECK(result.status == 200);
    }

    // Messaging endpoints demand a registered client ID.
    {
        const std::string body = nlohmann::json{{"hashes", nlohmann::json::array()}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/tokens",
            makeHeaders(alice, "POST", "/v1/messaging/tokens", body, "unknowndev"), body);
        CHECK(result.status == 403);
        CHECK(nlohmann::json::parse(result.body).at("error").at("code")
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
        const http::ClientResponse result = call(port, "POST", "/v1/messaging/tokens",
            makeHeaders(alice, "POST", "/v1/messaging/tokens", body, "alicedev"), body);
        CHECK(result.status == 200);
    }
    CHECK(storage.tokenHashCount(alice.fingerprint()) == 2);

    // A delivery into Alice's mailbox, as her correspondent's client makes it:
    // dialled to the destination she is served on, admitted by the engine on the
    // envelope alone. What this test cares about from here is the mailbox side -
    // what she can fetch, and what acking it does.
    const Bytes payload = {'e', '2', 'e', '-', 'b', 'l', 'o', 'b'};
    const Bytes envelope = sealEnvelope(sealingPublic,
        {{"class", "content"}, {"mailbox", alice.fingerprint()}, {"token", toBase64(token1)},
            {"deliveryId", "msg-1"}});
    const Key engineSealing = Key::fromPrivatePem(serverSealing.privatePem());
    CHECK(engine.deliver(envelope, payload, kNow, engineSealing, alice.fingerprint()).delivered);
    CHECK(storage.tokenHashCount(alice.fingerprint()) == 1);

    // Alice sees the message, fetches it and acks it away.
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

        // The device list reports what each device still holds: fetching does
        // not clear it, acking does.
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
        const http::ClientResponse acked = call(port, "POST", "/v1/messaging/ack",
            makeHeaders(alice, "POST", "/v1/messaging/ack", ackBody, "alicedev"), ackBody);
        CHECK(acked.status == 200);
        // Alice's only client acked: deleted immediately.
        CHECK(storage.usage(alice.fingerprint()) == 0);
        CHECK(aliceQueue() == 0);
    }

    // The destination endpoint surfaces the caller's assigned destination + the
    // public serving sealing key (the test assignment: serverDest + server key).
    {
        const http::ClientResponse result = call(port, "GET", "/v1/messaging/destination",
            makeHeaders(bob, "GET", "/v1/messaging/destination", "", "bobdev"));
        CHECK(result.status == 200);
        const nlohmann::json body = nlohmann::json::parse(result.body);
        CHECK(body.at("dest").get<std::string>() == serverDest);
        CHECK(body.at("servingKey").get<std::string>() == toBase64(serverServingKey->publicDer()));
        CHECK(body.at("state").get<std::string>() == "home");
    }

    // Per-user I2P destination endpoint (operator signature): auth + dispatch.
    {
        const std::string body = nlohmann::json{
            {"user", "alicefp"}, {"transient", "tb64"}, {"expiresUnix", 1780001234}}
                                     .dump();
        // No signature, then a signature from an unauthorised identity -> 403.
        const http::ClientResponse noAuth
            = call(port, "PUT", "/v1/messaging/i2p-dest", {}, body);
        CHECK(noAuth.status == 403);
        const http::ClientResponse badAuth = call(port, "PUT", "/v1/messaging/i2p-dest",
            makeHeaders(Identity::generate(), "PUT", "/v1/messaging/i2p-dest", body, ""), body);
        CHECK(badAuth.status == 403);
        // The authorised operator's signature with a transient provisions.
        const http::ClientResponse ok = call(port, "PUT", "/v1/messaging/i2p-dest",
            makeHeaders(operatorIdentity, "PUT", "/v1/messaging/i2p-dest", body, ""), body);
        CHECK(ok.status == 200);
        CHECK(provisionedUser == "alicefp");
        CHECK(provisionedTransient == "tb64");
        CHECK(provisionedExpires == 1780001234);
        // The authorised operator's signature without a transient revokes.
        const std::string revokeBody = nlohmann::json{{"user", "alicefp"}}.dump();
        const http::ClientResponse revoked = call(port, "PUT", "/v1/messaging/i2p-dest",
            makeHeaders(operatorIdentity, "PUT", "/v1/messaging/i2p-dest", revokeBody, ""),
            revokeBody);
        CHECK(revoked.status == 200);
        CHECK(revokedUser == "alicefp");
    }

    // Private reseed: unauthenticated on purpose (the client has no transport
    // yet), random slice per call, and bounded so one caller cannot pull the
    // whole netDb.
    {
        const http::ClientResponse result = call(port, "GET", "/v1/messaging/reseed");
        CHECK(result.status == 200);
        const nlohmann::json body = nlohmann::json::parse(result.body);
        CHECK(body.at("routers").size() == 3);
        const Bytes first = fromBase64(body.at("routers")[0].get<std::string>());
        CHECK(std::string(first.begin(), first.end()) == "routerinfo-0");
        CHECK(reseedAsked == 75);  // the default sample

        // An oversized ask is clamped, not honoured.
        const http::ClientResponse capped = call(port, "GET", "/v1/messaging/reseed?count=100000");
        CHECK(capped.status == 200);
        CHECK(reseedAsked == 200);

        // An empty netDb is an explicit typed error, never an empty success.
        reseedAvailable = 0;
        const http::ClientResponse empty = call(port, "GET", "/v1/messaging/reseed");
        CHECK(empty.status == 503);
        CHECK(nlohmann::json::parse(empty.body).at("error").at("code") == "I2P_UNAVAILABLE");
        reseedAvailable = 3;
    }

    // /healthz: operator-signed liveness with memory info; unsigned is rejected.
    {
        const http::ClientResponse unauth = call(port, "GET", "/healthz");
        CHECK(unauth.status == 403);
        const http::ClientResponse ok = call(port, "GET", 
            "/healthz", makeHeaders(operatorIdentity, "GET", "/healthz", "", ""));
        CHECK(ok.status == 200);
        const nlohmann::json health = nlohmann::json::parse(ok.body);
        CHECK(health.at("service").get<std::string>() == "server-core");
        CHECK(health.contains("ramBytes"));
        CHECK(health.contains("ramPeakBytes"));
    }

    // An account deleted on the node takes its mailbox with it: everything this
    // server held for the fingerprint goes, and only an operator can ask.
    {
        const std::string path = "/v1/messaging/account?user=" + alice.fingerprint();
        const Bytes payload = {'l', 'a', 's', 't'};
        CHECK(engine
                  .deliver(sealEnvelope(sealingPublic,
                               {{"class", "content"}, {"mailbox", alice.fingerprint()},
                                   {"token", toBase64(token2)}, {"deliveryId", "msg-last"}}),
                      payload, kNow, engineSealing, alice.fingerprint())
                  .delivered);
        CHECK(storage.usage(alice.fingerprint()) > 0);

        // Unsigned, and signed by somebody who is not an operator.
        CHECK(call(port, "DELETE", path).status == 403);
        CHECK(call(port, "DELETE", path,
                   makeHeaders(Identity::generate(), "DELETE", "/v1/messaging/account", "", ""))
                  .status
            == 403);

        const http::ClientResponse deleted = call(port, "DELETE", path,
            makeHeaders(operatorIdentity, "DELETE", "/v1/messaging/account", "", ""));
        CHECK(deleted.status == 200);
        CHECK(storage.usage(alice.fingerprint()) == 0);
        CHECK(storage.listClients(alice.fingerprint()).empty());
        CHECK(storage.tokenHashCount(alice.fingerprint()) == 0);
        // Idempotent: a fingerprint this server holds nothing for is already in
        // the state the deletion asks for.
        CHECK(call(port, "DELETE", path,
                   makeHeaders(operatorIdentity, "DELETE", "/v1/messaging/account", "", ""))
                  .status
            == 200);
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
