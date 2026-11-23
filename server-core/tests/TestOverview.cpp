// Bazarish project (c) 2026
#include "EventGate.hpp"
#include "HttpApi.hpp"
#include "DeviceTestKit.hpp"
#include "HttpTestUtil.hpp"
#include "TestUtil.hpp"

#include "DiskStorage.hpp"
#include "ServerSettings.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/HttpClient.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::server;

namespace {

using testutil::Headers;

constexpr const char* kOverview = "/v1/messaging/overview";
constexpr const char* kSelf = "/v1/messaging/self";
constexpr std::chrono::seconds kSoon{5};
constexpr std::size_t kPayloadBytes = 64;
constexpr std::uint64_t kGrantedQuota = 7 * 1024 * 1024;
constexpr std::int64_t kTransientExpires = 1900000000;

Headers signedFor(const devicetest::Device& device, const std::string& method,
    const std::string& path, const std::string& body)
{
    return testutil::deviceHeaders(device.credential, method, path, body);
}

std::string heldSince(const std::string& version)
{
    return std::string(kOverview) + "?hold=1&since=" + version;
}

std::future<http::ClientResponse> holdFor(
    const int port, const devicetest::Device& device, const std::string& target)
{
    return std::async(std::launch::async, [port, &device, target]() {
        http::ClientOptions unbounded;
        unbounded.readTimeout = std::chrono::seconds(0);
        return testutil::call(
            port, "GET", target, signedFor(device, "GET", target, ""), {}, unbounded);
    });
}

nlohmann::json askAtOnce(const int port, const devicetest::Device& device)
{
    const http::ClientResponse response
        = testutil::call(port, "GET", kOverview, signedFor(device, "GET", kOverview, ""));
    CHECK(response.status == 200);
    return nlohmann::json::parse(response.body);
}

nlohmann::json answerOf(std::future<http::ClientResponse>& held)
{
    CHECK(held.wait_for(kSoon) == std::future_status::ready);
    const http::ClientResponse response = held.get();
    CHECK(response.status == 200);
    return nlohmann::json::parse(response.body);
}

void sendToSelf(const int port, const devicetest::Device& from, const devicetest::Device& to,
    const std::string& deliveryId)
{
    const std::string body = nlohmann::json{{"deliveryId", deliveryId},
        {"payload", toBase64(randomBytes(kPayloadBytes))}, {"to", to.id()}}.dump();
    CHECK(testutil::call(port, "POST", kSelf, signedFor(from, "POST", kSelf, body), body).status
        == 200);
}

}  // namespace

int main()
try {
    const testutil::ScratchDir scratch("overview-test");
    const std::filesystem::path& root = scratch.path();
    DiskStorage storage(root);
    const std::filesystem::path configPath = root / "server-core.json";
    {
        std::ofstream config(configPath);
        config << "{\n  \"state\": \"" << root.string() << "\"\n}\n";
    }
    ServerSettings::Values values;
    values.listenHost = "127.0.0.1";
    HttpApiOptions options;
    options.settings = std::make_shared<ServerSettings>(configPath, values);
    options.identity = std::make_shared<const Identity>(Identity::generate());
    options.fingerprint = options.identity->fingerprint();
    options.sealingKey = std::make_shared<Key>(Key::generateSealing());
    const Identity alice = Identity::generate();
    const Identity bob = Identity::generate();
    const devicetest::Device phone(alice);
    const devicetest::Device laptop(alice, DeviceRole::eSecondary);
    options.accountRevocation
        = [](const std::string&) { return std::optional<Revocation>(Revocation{}); };
    options.accountCard = [](const std::string&) { return std::optional<Bytes>(); };
    std::mutex destMutex;
    DestinationAssignment served{std::string(52, 'd') + ".b32.i2p", "building", kTransientExpires};
    std::atomic<int> destinationReads{0};
    options.assignDestination = [&](const std::string&) {
        ++destinationReads;
        const std::lock_guard<std::mutex> lock(destMutex);
        return served;
    };
    options.reseedSample = [](std::size_t) { return std::vector<Bytes>{}; };
    options.requestRestart = []() {};

    EventGate gate;
    HttpApi api(storage, gate, options);
    const int port = api.bind("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serving([&api]() { api.wait(); });

    for (const devicetest::Device* const device : {&phone, &laptop}) {
        const std::string body = nlohmann::json{{"install", "install1"},
            {"sealing", toBase64(device->keys.sealing().publicDer())}}
                                     .dump();
        CHECK(testutil::call(port, "POST", "/v1/messaging/clients",
                  signedFor(*device, "POST", "/v1/messaging/clients", body), body)
                  .status
            == 200);
    }
    storage.setUserQuota(alice.fingerprint(), kGrantedQuota);

    {
        const nlohmann::json first = askAtOnce(port, phone);
        CHECK(first.at("dest") == served.dest);
        CHECK(first.at("state") == "building");
        CHECK(first.at("transientExpires") == kTransientExpires);
        CHECK(first.at("usedBytes") == 0);
        CHECK(first.at("quotaBytes") == kGrantedQuota);
        CHECK(first.at("clients").size() == 2);
        for (const nlohmann::json& client : first.at("clients")) {
            CHECK(client.at("current") == (client.at("device") == phone.id()));
            CHECK(client.at("queue") == 0);
        }
        CHECK(!first.at("version").get<std::string>().empty());
        CHECK(askAtOnce(port, phone).at("version") == first.at("version"));
        CHECK(askAtOnce(port, laptop).at("version") != first.at("version"));

        std::future<http::ClientResponse> stale = holdFor(port, phone, heldSince("not-a-version"));
        CHECK(answerOf(stale).at("version") == first.at("version"));
    }

    {
        const nlohmann::json before = askAtOnce(port, phone);
        const int readsBefore = destinationReads.load();
        std::future<http::ClientResponse> held
            = holdFor(port, phone, heldSince(before.at("version").get<std::string>()));
        CHECK(held.wait_for(kSoon) == std::future_status::timeout);
        storage.setUserQuota(bob.fingerprint(), kGrantedQuota);
        storage.setUserQuota(alice.fingerprint(), kGrantedQuota);
        api.overviewChanged()(bob.fingerprint());
        CHECK(held.wait_for(kSoon) == std::future_status::timeout);
        const int readsWhileHeld = destinationReads.load() - readsBefore;
        std::printf("a held overview read the destination %d time(s) in %lld s\n", readsWhileHeld,
            static_cast<long long>(2 * kSoon.count()));
        CHECK(readsWhileHeld == 2);

        sendToSelf(port, laptop, phone, "from-the-laptop");
        const nlohmann::json after = answerOf(held);
        CHECK(after.at("version") != before.at("version"));
        CHECK(after.at("usedBytes").get<std::uint64_t>() >= kPayloadBytes);
        for (const nlohmann::json& client : after.at("clients")) {
            CHECK(client.at("queue") == (client.at("device") == phone.id() ? 1 : 0));
        }
    }

    {
        const nlohmann::json before = askAtOnce(port, phone);
        std::future<http::ClientResponse> held
            = holdFor(port, phone, heldSince(before.at("version").get<std::string>()));
        CHECK(held.wait_for(kSoon) == std::future_status::timeout);
        {
            const std::lock_guard<std::mutex> lock(destMutex);
            served.state = "active";
        }
        api.overviewChanged()(alice.fingerprint());
        const nlohmann::json after = answerOf(held);
        CHECK(after.at("state") == "active");
        CHECK(after.at("version") != before.at("version"));
    }

    {
        const nlohmann::json before = askAtOnce(port, phone);
        const std::string since = before.at("version").get<std::string>();
        std::future<http::ClientResponse> held = holdFor(port, phone, heldSince(since));
        CHECK(held.wait_for(kSoon) == std::future_status::timeout);
        std::future<http::ClientResponse> laptopHeld = holdFor(port, laptop,
            heldSince(askAtOnce(port, laptop).at("version").get<std::string>()));
        CHECK(laptopHeld.wait_for(kSoon) == std::future_status::timeout);
        CHECK(askAtOnce(port, phone).at("version") == since);
        CHECK(answerOf(held).at("version") == since);
        CHECK(laptopHeld.wait_for(kSoon) == std::future_status::timeout);
        sendToSelf(port, phone, laptop, "from-the-phone");
        CHECK(answerOf(laptopHeld).at("version") != since);
    }

    api.stop();
    serving.join();
    std::printf("TestOverview ok\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
