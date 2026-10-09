// Bazarish project (c) 2026
#include "AccountApi.hpp"

#include "SubscriptionStore.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>

#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
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

namespace http = bazarish::http;

using Headers = std::map<std::string, std::string>;

using bazarish::nowSeconds;

Headers signedHeaders(const Identity& identity, const std::string& method, const std::string& path,
    const std::string& body)
{
    const auth::Headers headers = auth::signRequest(
        identity, nowSeconds(), method, path, Bytes(body.begin(), body.end()));
    return Headers(headers.begin(), headers.end());
}

http::ClientResponse call(const int port, const Identity& identity, const std::string& method,
    const std::string& target, const std::string& body = {})
{
    const std::string path = target.substr(0, target.find('?'));
    http::ClientRequest request;
    request.method = method;
    request.target = target;
    request.headers = signedHeaders(identity, method, path, body);
    request.body = body;
    if (!body.empty()) {
        request.contentType = "application/json";
    }
    return http::request("127.0.0.1", port, request, {});
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-operator-test";
    std::filesystem::remove_all(root);
    SubscriptionStore store(root);
    GrantStore grants(root);

    const Identity panel = Identity::generate();
    const Identity stranger = Identity::generate();
    const std::int64_t now = nowSeconds();

    constexpr std::uint64_t kQuota = 20 * 1024 * 1024;
    AccountApiOptions options;
    options.serverFingerprint = "server-fp";
    options.operatorFingerprints = {panel.fingerprint()};
    std::string quotaUser;
    std::uint64_t quotaPushed = 0;
    std::string revokedUser;
    std::string revokedTransient = "not-called";
    options.publishI2pTransient = [&](const std::string& user, const std::string& transientB64,
                                      const std::int64_t) -> std::optional<ServedDestination> {
        revokedUser = user;
        revokedTransient = transientB64;
        return ServedDestination{};
    };
    options.publishQuota = [&](const std::string& user, const std::uint64_t quotaBytes) {
        quotaUser = user;
        quotaPushed = quotaBytes;
    };
    std::filesystem::create_directories(root);
    const std::filesystem::path configPath = root / "service-node.json";
    {
        std::ofstream config(configPath);
        config << "{}\n";
    }
    NodeSettings::Values initial;
    initial.loginConsumer
        = LoginConsumer{"Bazarish stand", {"http://127.0.0.1:8431"}, "Account owner"};
    initial.logLevel = "info";
    initial.defaultQuotaBytes = kQuota;
    const auto settings = std::make_shared<NodeSettings>(configPath, initial);
    options.settings = settings;

    AccountApi api(store, grants, options);
    const int port = api.bind("127.0.0.1", 0);
    const int opsPort = api.bindOps("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serverThread([&api]() { api.wait(); });

    const std::string served = Identity::generate().fingerprint();
    const std::string waitingOne = Identity::generate().fingerprint();
    const std::string waitingTwo = Identity::generate().fingerprint();
    const std::string unknown = Identity::generate().fingerprint();
    grants.recordRegistration(served, now, true);
    grants.recordRegistration(waitingOne, now, false);
    grants.recordRegistration(waitingTwo, now, false);
    grants.grantSubscription(served, kQuota, now);
    std::vector<std::string> inOrder = {served, waitingOne, waitingTwo};
    std::sort(inOrder.begin(), inOrder.end());

    CHECK(call(opsPort, stranger, "GET", "/v1/account/users").status == 403);

    {
        const http::ClientResponse all = call(opsPort, panel, "GET", "/v1/account/users");
        CHECK(all.status == 200);
        const nlohmann::json body = nlohmann::json::parse(all.body);
        CHECK(body.at("total").get<std::size_t>() == 3);
        CHECK(body.at("users").size() == 3);
    }

    {
        const http::ClientResponse pending
            = call(opsPort, panel, "GET", "/v1/account/users?state=pending");
        CHECK(pending.status == 200);
        const nlohmann::json body = nlohmann::json::parse(pending.body);
        CHECK(body.at("total").get<std::size_t>() == 2);
        CHECK(body.at("users").at(0).at("approval").get<std::string>() == "pending");
    }

    {
        constexpr std::size_t kSearchStart = 8;
        constexpr std::size_t kSearchLength = 20;
        std::string needle = waitingTwo.substr(kSearchStart, kSearchLength);
        for (char& c : needle) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        const http::ClientResponse found
            = call(opsPort, panel, "GET", "/v1/account/users?q=" + needle);
        CHECK(found.status == 200);
        const nlohmann::json body = nlohmann::json::parse(found.body);
        CHECK(body.at("total").get<std::size_t>() == 1);
        CHECK(body.at("users").at(0).at("user").get<std::string>() == waitingTwo);

        const http::ClientResponse none
            = call(opsPort, panel, "GET", "/v1/account/users?q=zzzznobodyhere");
        CHECK(nlohmann::json::parse(none.body).at("total").get<std::size_t>() == 0);
    }

    {
        const http::ClientResponse page
            = call(opsPort, panel, "GET", "/v1/account/users?limit=1&offset=1");
        CHECK(page.status == 200);
        const nlohmann::json body = nlohmann::json::parse(page.body);
        CHECK(body.at("total").get<std::size_t>() == 3);
        CHECK(body.at("users").size() == 1);
        CHECK(body.at("users").at(0).at("user").get<std::string>() == inOrder.at(1));
    }

    {
        const http::ClientResponse one
            = call(opsPort, panel, "GET", "/v1/account/user?user=" + served);
        CHECK(one.status == 200);
        const nlohmann::json body = nlohmann::json::parse(one.body);
        CHECK(body.at("approval").get<std::string>() == "approved");
        CHECK(body.at("quotaBytes").get<std::uint64_t>() == kQuota);
        CHECK(body.at("grantPending").get<bool>());

        CHECK(call(opsPort, panel, "GET", "/v1/account/user?user=" + unknown).status == 404);
        CHECK(call(opsPort, panel, "GET", "/v1/account/user?user=not-a-fingerprint").status == 400);
    }

    {
        const std::uint64_t raised = 50 * 1024 * 1024;
        const std::string body
            = nlohmann::json{{"user", served}, {"quotaBytes", raised}}.dump();
        const http::ClientResponse set
            = call(opsPort, panel, "PUT", "/v1/account/quota", body);
        CHECK(set.status == 200);
        CHECK(nlohmann::json::parse(set.body).at("quotaBytes").get<std::uint64_t>() == raised);
        CHECK(quotaUser == served);
        CHECK(quotaPushed == raised);
        CHECK(grants.peekSubscription(served)->quotaBytes == raised);

        const std::string missing
            = nlohmann::json{{"user", unknown}, {"quotaBytes", raised}}.dump();
        CHECK(call(opsPort, panel, "PUT", "/v1/account/quota", missing).status == 404);
        CHECK(call(opsPort, stranger, "PUT", "/v1/account/quota", body).status == 403);
    }

    {
        const std::string body = nlohmann::json{{"user", served},
            {"message", "Talk to the operator before this comes back."}}
                                     .dump();
        CHECK(call(opsPort, panel, "POST", "/v1/account/undelegate",
                   nlohmann::json{{"user", served}}.dump())
                  .status
            == 400);

        const http::ClientResponse held
            = call(opsPort, panel, "POST", "/v1/account/undelegate", body);
        CHECK(held.status == 200);
        CHECK(revokedUser == served);
        CHECK(revokedTransient.empty());
        const nlohmann::json record = nlohmann::json::parse(held.body);
        CHECK(record.at("approval").get<std::string>() == "pending");
        CHECK(record.at("holdMessage").get<std::string>()
            == "Talk to the operator before this comes back.");
        CHECK(grants.peekApproval(served)->pending());
    }

    {
        const http::ClientResponse gone
            = call(opsPort, panel, "DELETE", "/v1/account/user?user=" + waitingOne);
        CHECK(gone.status == 200);
        CHECK(!grants.peekApproval(waitingOne).has_value());
        CHECK(call(opsPort, panel, "GET", "/v1/account/user?user=" + waitingOne).status == 404);
    }

    {
        const std::string body
            = nlohmann::json{{"user", waitingTwo}, {"reason", "Spam"}}.dump();
        CHECK(call(opsPort, panel, "POST", "/v1/account/ban", body).status == 200);
        CHECK(!grants.peekApproval(waitingTwo).has_value());
        CHECK(grants.peekBan(waitingTwo)->reason == "Spam");

        const http::ClientResponse listed
            = call(opsPort, panel, "GET", "/v1/account/users?q=" + waitingTwo);
        const nlohmann::json record = nlohmann::json::parse(listed.body).at("users").at(0);
        CHECK(record.at("banned").get<bool>());
        CHECK(record.at("banReason").get<std::string>() == "Spam");

        const std::string bare = nlohmann::json{{"user", served}}.dump();
        CHECK(call(opsPort, panel, "POST", "/v1/account/ban", bare).status == 200);
        CHECK(grants.peekBan(served)->reason == "Banned");

        CHECK(call(opsPort, panel, "POST", "/v1/account/unban", body).status == 200);
        CHECK(!grants.peekBan(waitingTwo).has_value());
    }

    {
        const nlohmann::json banned = nlohmann::json::parse(
            call(opsPort, panel, "GET", "/v1/account/users?state=banned").body);
        CHECK(banned.at("total").get<std::size_t>() == 1);
        CHECK(banned.at("users").at(0).at("user").get<std::string>() == served);
        CHECK(banned.at("users").at(0).at("banned").get<bool>());

        const nlohmann::json everyone = nlohmann::json::parse(
            call(opsPort, panel, "GET", "/v1/account/users").body);
        CHECK(everyone.at("total").get<std::size_t>() == 1);
        CHECK(everyone.at("users").at(0).at("user").get<std::string>() == served);

        const nlohmann::json waiting = nlohmann::json::parse(
            call(opsPort, panel, "GET", "/v1/account/users?state=pending").body);
        CHECK(waiting.at("total").get<std::size_t>() == 0);
    }

    {
        const nlohmann::json shown
            = nlohmann::json::parse(call(opsPort, panel, "GET", "/v1/account/settings").body);
        CHECK(shown.at("loginConsumer").at("name").get<std::string>() == "Bazarish stand");
        CHECK(shown.at("loginConsumer").at("role").get<std::string>() == "Account owner");

        const std::string renamed = nlohmann::json{{"loginConsumer",
            {{"name", "Bazarish alpha"},
                {"place", {"https://alpha.example", "http://alpha.b32.i2p"}},
                {"role", "Alpha tester"}}}}
                                        .dump();
        CHECK(call(opsPort, panel, "PUT", "/v1/account/settings", renamed).status == 200);
        const std::vector<std::string> bothPlaces
            = {"https://alpha.example", "http://alpha.b32.i2p"};
        CHECK(settings->get().loginConsumer.place == bothPlaces);

        std::ifstream written(configPath);
        const nlohmann::json onDisk = nlohmann::json::parse(written);
        CHECK(onDisk.at("portal").at("name").get<std::string>() == "Bazarish alpha");
        CHECK(onDisk.at("portal").at("address").at(0).get<std::string>()
            == "https://alpha.example");
        CHECK(onDisk.at("portal").at("address").at(1).get<std::string>()
            == "http://alpha.b32.i2p");
        CHECK(onDisk.at("portal").at("role").get<std::string>() == "Alpha tester");

        CHECK(bazarish::log::level() != bazarish::log::Level::eDebug);
        const std::string louder = nlohmann::json{{"logLevel", "debug"}}.dump();
        CHECK(call(opsPort, panel, "PUT", "/v1/account/settings", louder).status == 200);
        CHECK(bazarish::log::level() == bazarish::log::Level::eDebug);
        CHECK(settings->get().logLevel == "debug");
        const std::string nonsense = nlohmann::json{{"logLevel", "loud"}}.dump();
        CHECK(call(opsPort, panel, "PUT", "/v1/account/settings", nonsense).status == 400);
        const std::string quieter = nlohmann::json{{"logLevel", "info"}}.dump();
        CHECK(call(opsPort, panel, "PUT", "/v1/account/settings", quieter).status == 200);
        CHECK(bazarish::log::level() == bazarish::log::Level::eInfo);

        const std::string wiring
            = nlohmann::json{{"portalListen", {{"host", "0.0.0.0"}, {"port", 8531}}}}.dump();
        CHECK(call(opsPort, panel, "PUT", "/v1/account/settings", wiring).status == 200);
        std::ifstream rewritten(configPath);
        const nlohmann::json onDiskAgain = nlohmann::json::parse(rewritten);
        CHECK(onDiskAgain.at("portal").at("listen").at("port").get<int>() == 8531);
        const std::string badPort = nlohmann::json{{"listen", {{"port", 0}}}}.dump();
        CHECK(call(opsPort, panel, "PUT", "/v1/account/settings", badPort).status == 400);

        const std::string nameless = nlohmann::json{{"loginConsumer", {{"name", ""}}}}.dump();
        CHECK(call(opsPort, panel, "PUT", "/v1/account/settings", nameless).status == 400);
        CHECK(settings->get().loginConsumer.name == "Bazarish alpha");
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    std::printf("TestOperatorApi: all checks passed\n");
    return 0;
}
