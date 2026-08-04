// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "GrantStore.hpp"
#include "LedgerStore.hpp"
#include "ServiceLifecycle.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

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

httplib::Headers makeHeaders(const Identity& identity, const std::string& method,
    const std::string& path, const std::string& body)
{
    const auth::Headers signed_ = auth::signRequest(identity,
        static_cast<std::int64_t>(std::time(nullptr)), method, path, Bytes(body.begin(), body.end()));
    return httplib::Headers(signed_.begin(), signed_.end());
}

}  // namespace

int main()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-i2pdestapi-" + toHex(randomBytes(8)));
    fs::remove_all(root);
    fs::create_directories(root);

    SubscriptionStore store(root);
    GrantStore grants(root);
    LedgerStore ledger(root, "XMR");

    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    constexpr std::int64_t kTerm = 30 * 24 * 3600;
    constexpr std::uint64_t kPrice = 100;

    std::vector<std::string> revoked;
    ServiceLifecycle life(grants, ledger, {kPrice, kTerm}, {0, 0}, 0, 10 * 1024 * 1024, {},
        [&revoked](const std::string& user) { revoked.push_back(user); });

    AccountApiOptions options;
    options.serverFingerprint = Identity::generate().fingerprint();
    std::vector<std::string> pubTransients;
    options.publishI2pTransient = [&pubTransients](const std::string& /*user*/,
                                      const std::string& transientB64, std::int64_t /*expires*/) {
        pubTransients.push_back(transientB64);
    };
    options.lifecycle = &life;
    AccountApi api(store, grants, options);

    const int port = api.bindToAnyPort("127.0.0.1");
    CHECK(port > 0);
    std::thread serverThread([&api]() { (void)api.listenAfterBind(); });
    httplib::Client client("127.0.0.1", port);
    CHECK(client.is_valid());

    const Identity alice = Identity::generate();
    // Delegating a transient needs an approved account; this suite exercises the
    // paid toggle, not moderation, so register her as an open-node account.
    grants.recordRegistration(alice.fingerprint(), now, true);

    // Status before enabling: off and inactive.
    {
        const httplib::Result r
            = client.Get("/v1/account/i2p-status", makeHeaders(alice, "GET", "/v1/account/i2p-status", ""));
        CHECK(r && r->status == 200);
        const nlohmann::json j = nlohmann::json::parse(r->body);
        CHECK(j.at("enabled") == false && j.at("active") == false);
        CHECK(j.at("balanceAtomic").get<std::string>() == "0");
    }

    const auto setting = [&](bool enabled) {
        const std::string body = nlohmann::json{{"enabled", enabled}}.dump();
        return client.Post("/v1/account/i2p-dest/setting",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest/setting", body), body, "application/json");
    };

    // Enable with an empty balance is refused (402).
    {
        const httplib::Result r = setting(true);
        CHECK(r && r->status == 402);
    }

    // Top up, then enable: charges one term and goes active.
    {
        ledger.credit(alice.fingerprint(), 100, "topup", now);
        const httplib::Result r = setting(true);
        CHECK(r && r->status == 200);
        const httplib::Result s
            = client.Get("/v1/account/i2p-status", makeHeaders(alice, "GET", "/v1/account/i2p-status", ""));
        const nlohmann::json j = nlohmann::json::parse(s->body);
        CHECK(j.at("enabled") == true && j.at("active") == true);
        CHECK(j.at("balanceAtomic").get<std::string>() == "0");
        CHECK(j.at("paidThrough").get<std::int64_t>() == now + kTerm);
    }

    // Upload a transient: accepted and its validity is recorded in the status.
    {
        const std::int64_t expires = now + 7 * 24 * 3600;
        const std::string body
            = nlohmann::json{{"transient", "transient-blob-b64"}, {"expiresUnix", expires}}.dump();
        const httplib::Result r = client.Post("/v1/account/i2p-dest",
            makeHeaders(alice, "POST", "/v1/account/i2p-dest", body), body, "application/json");
        CHECK(r && r->status == 200);
        CHECK(pubTransients.size() == 1 && pubTransients.back() == "transient-blob-b64");
        const httplib::Result s
            = client.Get("/v1/account/i2p-status", makeHeaders(alice, "GET", "/v1/account/i2p-status", ""));
        const nlohmann::json j = nlohmann::json::parse(s->body);
        CHECK(j.at("transientExpires").get<std::int64_t>() == expires);
        CHECK(j.at("transientUpdatedAt").get<std::int64_t>() > 0);
    }

    // Disable: revokes the destination and the status goes off.
    {
        const httplib::Result r = setting(false);
        CHECK(r && r->status == 200);
        CHECK(revoked.size() == 1 && revoked.back() == alice.fingerprint());
        const httplib::Result s
            = client.Get("/v1/account/i2p-status", makeHeaders(alice, "GET", "/v1/account/i2p-status", ""));
        const nlohmann::json j = nlohmann::json::parse(s->body);
        CHECK(j.at("enabled") == false && j.at("active") == false);
    }

    api.stop();
    serverThread.join();
    fs::remove_all(root);
    std::printf("TestI2pDestApi: all checks passed\n");
    return 0;
}
