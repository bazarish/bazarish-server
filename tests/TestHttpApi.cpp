// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Cms.hpp>
#include <bazarish/Tokens.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
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

std::string makeEnvelope(const std::string& toServer, const Key& serverSealingPublic,
    const nlohmann::json& inner, const Bytes& payload)
{
    const std::string innerText = inner.dump();
    const Bytes sealed
        = cms::seal(Bytes(innerText.begin(), innerText.end()), serverSealingPublic);
    const nlohmann::json envelope = {
        {"toServer", toServer},
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

    const std::string pollPath = "/v1/messaging/send/" + attemptId;
    const httplib::Result polled
        = client.Get(pollPath, makeHeaders(sender, "GET", pollPath, "", clientId));
    CHECK(polled && polled->status == 200);
    return nlohmann::json::parse(polled->body);
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
    const Key sealingPublic = Key::fromPublicDer(serverSealing.publicDer());

    DeliveryEngineOptions engineOptions;
    engineOptions.defaultQuotaBytes = 1024;
    engineOptions.contactRequestLimitBytes = 256;
    DeliveryEngine engine(storage, serverFp, Key::fromPrivatePem(serverSealing.privatePem()),
        engineOptions);
    HttpApiOptions httpOptions;
    // Stub blob proxy: echoes the requested host+path back so the test can assert
    // the endpoint validated and forwarded without a live router.
    std::string proxiedHost;
    std::string proxiedPath;
    httpOptions.blobProxyFetch
        = [&proxiedHost, &proxiedPath](const std::string& host, const std::string& path) {
              proxiedHost = host;
              proxiedPath = path;
              const std::string body = "ciphertext-for-" + path;
              return BlobProxyResult{200, Bytes(body.begin(), body.end())};
          };
    HttpApi api(storage, engine, httpOptions);

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
    const std::string envelope = makeEnvelope(serverFp, sealingPublic,
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
        const std::string bad = makeEnvelope(serverFp, sealingPublic,
            {{"class", "content"}, {"mailbox", alice.fingerprint()},
                {"token", toBase64(generateDeliveryToken())}, {"messageId", "msg-2"}},
            payload);
        const nlohmann::json result = sendAndPoll(client, bob, "bobdev", bad);
        CHECK(result.at("status") == "failed");
        CHECK(result.at("error").at("code") == "DELIVERY_REJECTED");
    }

    // Tokenless contact requests pass within the size cap and fail above it.
    {
        const std::string request = makeEnvelope(serverFp, sealingPublic,
            {{"class", "contact"}, {"mailbox", alice.fingerprint()},
                {"messageId", "req-1"}},
            Bytes(200, 0x55));
        CHECK(sendAndPoll(client, bob, "bobdev", request).at("status") == "delivered");

        const std::string oversized = makeEnvelope(serverFp, sealingPublic,
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
        const std::string big = makeEnvelope(serverFp, sealingPublic,
            {{"class", "content"}, {"mailbox", alice.fingerprint()},
                {"token", toBase64(token2)}, {"messageId", "msg-3"}},
            Bytes(2000, 0x77));
        const nlohmann::json result = sendAndPoll(client, bob, "bobdev", big);
        CHECK(result.at("status") == "failed");
        CHECK(result.at("error").at("code") == "STORAGE_FULL");
        CHECK(storage.tokenHashCount(alice.fingerprint()) == 1);
    }

    // Unknown destination server: unreachable until federation lands.
    {
        const std::string remote = makeEnvelope(toBase32(Bytes(32, 0x42)), sealingPublic,
            {{"class", "content"}, {"mailbox", alice.fingerprint()},
                {"token", toBase64(token2)}, {"messageId", "msg-4"}},
            payload);
        const nlohmann::json result = sendAndPoll(client, bob, "bobdev", remote);
        CHECK(result.at("status") == "failed");
        CHECK(result.at("error").at("code") == "RECIPIENT_SERVER_UNREACHABLE");
    }

    // Unknown attempt IDs are reported as such.
    {
        const httplib::Result result = client.Get("/v1/messaging/send/deadbeef",
            makeHeaders(bob, "GET", "/v1/messaging/send/deadbeef", "", "bobdev"));
        CHECK(result && result->status == 404);
        CHECK(nlohmann::json::parse(result->body).at("error").at("code") == "ATTEMPT_UNKNOWN");
    }

    // Blob proxy: an authed client request for a .b32.i2p host is forwarded and
    // the fetched ciphertext relayed back.
    {
        const std::string b33
            = "yhfjbu7hkuqyqwp3pvpuf6vk63bdlwtryjcueunavz52ai5y3yuvwdkh.b32.i2p";
        const httplib::Result result = client.Get("/v1/messaging/blob-proxy?host=" + b33 + "&path=/b/cap1",
            makeHeaders(alice, "GET", "/v1/messaging/blob-proxy", "", "alicedev"));
        CHECK(result && result->status == 200);
        CHECK(result->body == "ciphertext-for-/b/cap1");
        CHECK(proxiedHost == b33);
        CHECK(proxiedPath == "/b/cap1");
    }

    // A non-.b32.i2p host is refused (never an open proxy).
    {
        const httplib::Result result
            = client.Get("/v1/messaging/blob-proxy?host=evil.example.com&path=/x",
                makeHeaders(alice, "GET", "/v1/messaging/blob-proxy", "", "alicedev"));
        CHECK(result && result->status == 400);
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    return 0;
}
