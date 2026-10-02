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

// One signed operator call. The path carries the query string, and the signature
// covers the path without it, exactly as the panel signs it.
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

// The surface the admin panel drives: list, search, read and set a quota. The
// search runs on this side, so a panel never has to hold the whole account list
// to find one fingerprint in it.
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
                                      const std::int64_t) {
        revokedUser = user;
        revokedTransient = transientB64;
        return true;
    };
    options.publishQuota = [&](const std::string& user, const std::uint64_t quotaBytes) {
        quotaUser = user;
        quotaPushed = quotaBytes;
    };
    // The knobs the panel edits, backed by a config file: a change an operator
    // makes has to be where the next start reads it.
    std::filesystem::create_directories(root);
    const std::filesystem::path configPath = root / "service-node.json";
    {
        std::ofstream config(configPath);
        config << "{}\n";
    }
    NodeSettings::Values initial;
    initial.loginConsumer
        = LoginConsumer{"Bazarish stand", "http://127.0.0.1:8431", "Account owner"};
    initial.logLevel = "info";
    initial.defaultQuotaBytes = kQuota;
    const auto settings = std::make_shared<NodeSettings>(configPath, initial);
    options.settings = settings;

    AccountApi api(store, grants, options);
    const int port = api.bind("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serverThread([&api]() { api.wait(); });

    // Three accounts: one served, two still waiting for the operator.
    const std::string served = Identity::generate().fingerprint();
    const std::string waitingOne = Identity::generate().fingerprint();
    const std::string waitingTwo = Identity::generate().fingerprint();
    // A well-formed fingerprint this node has never heard of.
    const std::string unknown = Identity::generate().fingerprint();
    grants.recordRegistration(served, now, true);
    grants.recordRegistration(waitingOne, now, false);
    grants.recordRegistration(waitingTwo, now, false);
    grants.grantSubscription(served, kQuota, now);
    // The listing is in fingerprint order, so paging is checked against that.
    std::vector<std::string> inOrder = {served, waitingOne, waitingTwo};
    std::sort(inOrder.begin(), inOrder.end());

    // Only an authorised operator sees any of it.
    CHECK(call(port, stranger, "GET", "/v1/account/users").status == 403);

    {
        const http::ClientResponse all = call(port, panel, "GET", "/v1/account/users");
        CHECK(all.status == 200);
        const nlohmann::json body = nlohmann::json::parse(all.body);
        CHECK(body.at("total").get<std::size_t>() == 3);
        CHECK(body.at("users").size() == 3);
    }

    {
        const http::ClientResponse pending
            = call(port, panel, "GET", "/v1/account/users?state=pending");
        CHECK(pending.status == 200);
        const nlohmann::json body = nlohmann::json::parse(pending.body);
        CHECK(body.at("total").get<std::size_t>() == 2);
        CHECK(body.at("users").at(0).at("approval").get<std::string>() == "pending");
    }

    // The search is a substring of the fingerprint, matched here - and it is
    // case-insensitive, because an operator pastes what they were given.
    {
        constexpr std::size_t kSearchStart = 8;
        constexpr std::size_t kSearchLength = 20;
        std::string needle = waitingTwo.substr(kSearchStart, kSearchLength);
        for (char& c : needle) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        const http::ClientResponse found
            = call(port, panel, "GET", "/v1/account/users?q=" + needle);
        CHECK(found.status == 200);
        const nlohmann::json body = nlohmann::json::parse(found.body);
        CHECK(body.at("total").get<std::size_t>() == 1);
        CHECK(body.at("users").at(0).at("user").get<std::string>() == waitingTwo);

        const http::ClientResponse none
            = call(port, panel, "GET", "/v1/account/users?q=zzzznobodyhere");
        CHECK(nlohmann::json::parse(none.body).at("total").get<std::size_t>() == 0);
    }

    // Paging: the page is what the caller asked for, the total is the truth.
    {
        const http::ClientResponse page
            = call(port, panel, "GET", "/v1/account/users?limit=1&offset=1");
        CHECK(page.status == 200);
        const nlohmann::json body = nlohmann::json::parse(page.body);
        CHECK(body.at("total").get<std::size_t>() == 3);
        CHECK(body.at("users").size() == 1);
        CHECK(body.at("users").at(0).at("user").get<std::string>() == inOrder.at(1));
    }

    {
        const http::ClientResponse one
            = call(port, panel, "GET", "/v1/account/user?user=" + served);
        CHECK(one.status == 200);
        const nlohmann::json body = nlohmann::json::parse(one.body);
        CHECK(body.at("approval").get<std::string>() == "approved");
        CHECK(body.at("quotaBytes").get<std::uint64_t>() == kQuota);
        CHECK(body.at("grantPending").get<bool>());

        CHECK(call(port, panel, "GET", "/v1/account/user?user=" + unknown).status == 404);
        // Not a fingerprint at all is a bad request, not a missing account.
        CHECK(call(port, panel, "GET", "/v1/account/user?user=not-a-fingerprint").status == 400);
    }

    // Setting a quota moves the grant with it and pushes it to the messaging
    // server, which would otherwise go on serving its own default.
    {
        const std::uint64_t raised = 50 * 1024 * 1024;
        const std::string body
            = nlohmann::json{{"user", served}, {"quotaBytes", raised}}.dump();
        const http::ClientResponse set
            = call(port, panel, "PUT", "/v1/account/quota", body);
        CHECK(set.status == 200);
        CHECK(nlohmann::json::parse(set.body).at("quotaBytes").get<std::uint64_t>() == raised);
        CHECK(quotaUser == served);
        CHECK(quotaPushed == raised);
        CHECK(grants.peekSubscription(served)->quotaBytes == raised);

        const std::string missing
            = nlohmann::json{{"user", unknown}, {"quotaBytes", raised}}.dump();
        CHECK(call(port, panel, "PUT", "/v1/account/quota", missing).status == 404);
        CHECK(call(port, stranger, "PUT", "/v1/account/quota", body).status == 403);
    }

    // Taking an account out of service: the destination is revoked and the
    // account waits again, with the operator's own words for its owner.
    {
        const std::string body = nlohmann::json{{"user", served},
            {"message", "Talk to the operator before this comes back."}}
                                     .dump();
        // A hold with nothing to say is refused: saying something is the point.
        CHECK(call(port, panel, "POST", "/v1/account/undelegate",
                   nlohmann::json{{"user", served}}.dump())
                  .status
            == 400);

        const http::ClientResponse held
            = call(port, panel, "POST", "/v1/account/undelegate", body);
        CHECK(held.status == 200);
        CHECK(revokedUser == served);
        CHECK(revokedTransient.empty());
        const nlohmann::json record = nlohmann::json::parse(held.body);
        CHECK(record.at("approval").get<std::string>() == "pending");
        CHECK(record.at("holdMessage").get<std::string>()
            == "Talk to the operator before this comes back.");
        CHECK(grants.peekApproval(served)->pending());
    }

    // Deleting takes the account away and leaves the key free to come back.
    {
        const http::ClientResponse gone
            = call(port, panel, "DELETE", "/v1/account/user?user=" + waitingOne);
        CHECK(gone.status == 200);
        CHECK(!grants.peekApproval(waitingOne).has_value());
        CHECK(call(port, panel, "GET", "/v1/account/user?user=" + waitingOne).status == 404);
    }

    // A ban takes the account away too, and stays behind so the key cannot
    // register again; the operator's reason is what its owner is shown.
    {
        const std::string body
            = nlohmann::json{{"user", waitingTwo}, {"reason", "Spam"}}.dump();
        CHECK(call(port, panel, "POST", "/v1/account/ban", body).status == 200);
        CHECK(!grants.peekApproval(waitingTwo).has_value());
        CHECK(grants.peekBan(waitingTwo)->reason == "Spam");

        // A banned key is still listed - it is the only way back to lifting it.
        const http::ClientResponse listed
            = call(port, panel, "GET", "/v1/account/users?q=" + waitingTwo);
        const nlohmann::json record = nlohmann::json::parse(listed.body).at("users").at(0);
        CHECK(record.at("banned").get<bool>());
        CHECK(record.at("banReason").get<std::string>() == "Spam");

        // An empty reason still says something.
        const std::string bare = nlohmann::json{{"user", served}}.dump();
        CHECK(call(port, panel, "POST", "/v1/account/ban", bare).status == 200);
        CHECK(grants.peekBan(served)->reason == "Banned");

        CHECK(call(port, panel, "POST", "/v1/account/unban", body).status == 200);
        CHECK(!grants.peekBan(waitingTwo).has_value());
    }

    // What a user is shown before signing a login is the operator's to set, and
    // it is written where the next start will read it.
    {
        const nlohmann::json shown
            = nlohmann::json::parse(call(port, panel, "GET", "/v1/account/settings").body);
        CHECK(shown.at("loginConsumer").at("name").get<std::string>() == "Bazarish stand");
        CHECK(shown.at("loginConsumer").at("role").get<std::string>() == "Account owner");

        const std::string renamed = nlohmann::json{{"loginConsumer",
            {{"name", "Bazarish alpha"}, {"place", "https://alpha.example"},
                {"role", "Alpha tester"}}}}
                                        .dump();
        CHECK(call(port, panel, "PUT", "/v1/account/settings", renamed).status == 200);
        CHECK(settings->get().loginConsumer.place == "https://alpha.example");

        std::ifstream written(configPath);
        const nlohmann::json onDisk = nlohmann::json::parse(written);
        CHECK(onDisk.at("portal").at("name").get<std::string>() == "Bazarish alpha");
        CHECK(onDisk.at("portal").at("address").get<std::string>() == "https://alpha.example");
        CHECK(onDisk.at("portal").at("role").get<std::string>() == "Alpha tester");

        // The log level is the one setting here that is not a restart away: an
        // operator makes a node talkative while it is running the problem.
        CHECK(bazarish::log::level() != bazarish::log::Level::eDebug);
        const std::string louder = nlohmann::json{{"logLevel", "debug"}}.dump();
        CHECK(call(port, panel, "PUT", "/v1/account/settings", louder).status == 200);
        CHECK(bazarish::log::level() == bazarish::log::Level::eDebug);
        CHECK(settings->get().logLevel == "debug");
        const std::string nonsense = nlohmann::json{{"logLevel", "loud"}}.dump();
        CHECK(call(port, panel, "PUT", "/v1/account/settings", nonsense).status == 400);
        const std::string quieter = nlohmann::json{{"logLevel", "info"}}.dump();
        CHECK(call(port, panel, "PUT", "/v1/account/settings", quieter).status == 200);
        CHECK(bazarish::log::level() == bazarish::log::Level::eInfo);

        // Startup values are written for the next start rather than applied now.
        const std::string wiring
            = nlohmann::json{{"portalListen", {{"host", "0.0.0.0"}, {"port", 8531}}}}.dump();
        CHECK(call(port, panel, "PUT", "/v1/account/settings", wiring).status == 200);
        std::ifstream rewritten(configPath);
        const nlohmann::json onDiskAgain = nlohmann::json::parse(rewritten);
        CHECK(onDiskAgain.at("portal").at("listen").at("port").get<int>() == 8531);
        const std::string badPort = nlohmann::json{{"listen", {{"port", 0}}}}.dump();
        CHECK(call(port, panel, "PUT", "/v1/account/settings", badPort).status == 400);

        // A portal that will not say who it is has no business asking anyone to
        // sign for it, and the words it had stand.
        const std::string nameless = nlohmann::json{{"loginConsumer", {{"name", ""}}}}.dump();
        CHECK(call(port, panel, "PUT", "/v1/account/settings", nameless).status == 400);
        CHECK(settings->get().loginConsumer.name == "Bazarish alpha");
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    std::printf("TestOperatorApi: all checks passed\n");
    return 0;
}
