// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
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

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-moderation-test";
    std::filesystem::remove_all(root);
    SubscriptionStore store(root);
    GrantStore grants(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const std::string serverFp = serverIdentity.fingerprint();
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    const Bytes cardDer
        = ServerCard::issue(serverIdentity, Key::fromPublicDer(serverSealing.publicDer()), now);

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
    int pubCalls = 0;
    options.publishI2pTransient = [&pubCalls](const std::string&, const std::string&,
                                      std::int64_t) -> std::optional<ServedDestination> {
        ++pubCalls;
        return ServedDestination{};
    };
    AccountApi api(store, grants, options);

    const int port = api.bind("127.0.0.1", 0);
    const int opsPort = api.bindOps("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serverThread([&api]() { api.wait(); });

    const std::string transientBody
        = nlohmann::json{{"transient", "t-b64"}, {"expiresUnix", now + 7 * 24 * 3600}}.dump();

    {
        grants.grantSubscription(
            alice.fingerprint(), kQuota, now);
        const Bytes card = ContactCard::issue(alice, now);
        const std::string body = nlohmann::json{{"card", toBase64(card)}}.dump();
        const http::ClientResponse result = call(port, "POST", "/v1/account/card",
            makeHeaders(alice, "POST", "/v1/account/card", body), body);
        CHECK(result.status == 200);
        const nlohmann::json reply = nlohmann::json::parse(result.body);
        CHECK(reply.at("approval") == "pending");
        CHECK(reply.at("registrationMessage") == kHoldMessage);
    }

    {
        const http::ClientResponse result = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", transientBody), transientBody);
        CHECK(result.status == 403);
        const nlohmann::json error = nlohmann::json::parse(result.body).at("error");
        CHECK(error.at("code") == "ACCOUNT_PENDING_APPROVAL");
        CHECK(error.at("message") == kHoldMessage);
        CHECK(pubCalls == 0);
    }

    {
        const http::ClientResponse result = call(opsPort, "GET", "/v1/account/users?state=pending",
            makeHeaders(panel, "GET", "/v1/account/users", ""));
        CHECK(result.status == 200);
        const nlohmann::json users = nlohmann::json::parse(result.body).at("users");
        CHECK(users.size() == 1);
        CHECK(users.at(0).at("user") == alice.fingerprint());
        CHECK(users.at(0).at("approval") == "pending");
    }

    {
        const std::string body = nlohmann::json{{"user", alice.fingerprint()}}.dump();
        const http::ClientResponse forged = call(opsPort, "POST", "/v1/account/approve",
            makeHeaders(alice, "POST", "/v1/account/approve", body), body);
        CHECK(forged.status == 403);
        CHECK(grants.peekApproval(alice.fingerprint())->pending());

        const http::ClientResponse result = call(opsPort, "POST", "/v1/account/approve",
            makeHeaders(panel, "POST", "/v1/account/approve", body), body);
        CHECK(result.status == 200);
    }

    {
        const http::ClientResponse result = call(port, "POST", "/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", transientBody), transientBody);
        CHECK(result.status == 200);
        CHECK(pubCalls == 1);

        const http::ClientResponse pending = call(opsPort, "GET", "/v1/account/users?state=pending",
            makeHeaders(panel, "GET", "/v1/account/users", ""));
        CHECK(nlohmann::json::parse(pending.body).at("users").empty());
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    std::printf("TestModeratedRegistration: all checks passed\n");
    return 0;
}
