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
#include <bazarish/Limits.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::server;

namespace {

using testutil::Headers;

constexpr const char* kEvents = "/v1/messaging/events";
constexpr const char* kHeld = "/v1/messaging/events?hold=1";
constexpr const char* kSelf = "/v1/messaging/self";
// Past the 30 s a held wait used to be capped at.
constexpr std::chrono::seconds kBeyondOldCap{31};
constexpr std::chrono::seconds kSoon{5};
constexpr std::size_t kPayloadBytes = 64;

Headers signedFor(const devicetest::Device& device, const std::string& method,
    const std::string& path, const std::string& body)
{
    return testutil::deviceHeaders(device.credential, method, path, body);
}

std::future<http::ClientResponse> holdFor(
    const int port, const devicetest::Device& device, const std::string& target = kHeld)
{
    return std::async(std::launch::async, [port, &device, target]() {
        http::ClientOptions unbounded;
        unbounded.readTimeout = std::chrono::seconds(0);
        return testutil::call(
            port, "GET", target, signedFor(device, "GET", target, ""), {}, unbounded);
    });
}

http::ClientResponse askAtOnce(
    const int port, const devicetest::Device& device, const std::string& target)
{
    return testutil::call(port, "GET", target, signedFor(device, "GET", target, ""));
}

std::size_t pendingIn(const http::ClientResponse& response)
{
    return nlohmann::json::parse(response.body).at("pending").size();
}

}  // namespace

int main()
{
    const std::filesystem::path root = testutil::freshDir("held-mail-wait-test");
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
    const devicetest::Device phone(alice);
    const devicetest::Device laptop(alice, DeviceRole::eSecondary);
    const DeviceBook devices = devicetest::bookOf(alice, {&phone, &laptop});
    options.accountDevices = [&devices](const std::string&) { return std::optional<DeviceBook>(devices); };
    options.assignDestination = [](const std::string&) {
        return DestinationAssignment{std::string(52, 'd') + ".b32.i2p", "home"};
    };
    options.reseedSample = [](std::size_t) { return std::vector<Bytes>{}; };
    options.requestRestart = []() {};

    EventGate gate;
    HttpApi api(storage, gate, options);
    const int port = api.bind("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serving([&api]() { api.wait(); });

    for (const devicetest::Device* const device : {&phone, &laptop}) {
        const std::string body = nlohmann::json{{"install", "install1"}}.dump();
        CHECK(testutil::call(port, "POST", "/v1/messaging/clients",
                  signedFor(*device, "POST", "/v1/messaging/clients", body), body)
                  .status
            == 200);
    }

    const http::ClientResponse atOnce
        = testutil::call(port, "GET", kEvents, signedFor(phone, "GET", kEvents, ""));
    CHECK(atOnce.status == 200);
    CHECK(pendingIn(atOnce) == 0);

    std::future<http::ClientResponse> stale = holdFor(port, phone);
    CHECK(stale.wait_for(kSoon) == std::future_status::timeout);
    std::future<http::ClientResponse> held = holdFor(port, phone);
    CHECK(stale.wait_for(kSoon) == std::future_status::ready);
    CHECK(stale.get().status == 200);

    const auto heldSince = std::chrono::steady_clock::now();
    CHECK(held.wait_for(kBeyondOldCap) == std::future_status::timeout);
    CHECK(gate.waiting() == 1);

    const std::string body = nlohmann::json{{"deliveryId", "from-the-laptop"},
        {"payload", toBase64(randomBytes(kPayloadBytes))}, {"to", phone.id()}}.dump();
    CHECK(testutil::call(port, "POST", kSelf, signedFor(laptop, "POST", kSelf, body), body)
              .status
        == 200);
    CHECK(held.wait_for(kSoon) == std::future_status::ready);
    const http::ClientResponse answered = held.get();
    CHECK(answered.status == 200);
    CHECK(pendingIn(answered) == 1);
    std::printf("a held wait answered by mail after %lld s\n",
        static_cast<long long>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - heldSince)
                                   .count()));

    const std::string keptId
        = nlohmann::json::parse(answered.body).at("pending").at(0).at("id").get<std::string>();
    const std::string deferring = std::string(kHeld) + "&deferred=" + keptId;
    const http::ClientResponse unknownNamed
        = askAtOnce(port, phone, std::string(kHeld) + "&deferred=not-held-here");
    CHECK(unknownNamed.status == 200);
    CHECK(pendingIn(unknownNamed) == 1);
    std::string tooMany = std::string(kHeld) + "&deferred=";
    for (std::size_t i = 0; i <= kMaxDeferredMailItems; ++i) {
        tooMany += (i == 0 ? "" : ",") + ("held-" + std::to_string(i));
    }
    CHECK(askAtOnce(port, phone, tooMany).status == 400);

    std::future<http::ClientResponse> deferredHeld = holdFor(port, phone, deferring);
    CHECK(deferredHeld.wait_for(kSoon) == std::future_status::timeout);
    const std::string another = nlohmann::json{{"deliveryId", "another-from-the-laptop"},
        {"payload", toBase64(randomBytes(kPayloadBytes))}, {"to", phone.id()}}.dump();
    CHECK(testutil::call(port, "POST", kSelf, signedFor(laptop, "POST", kSelf, another), another)
              .status
        == 200);
    CHECK(deferredHeld.wait_for(kSoon) == std::future_status::ready);
    const http::ClientResponse withNews = deferredHeld.get();
    CHECK(withNews.status == 200);
    CHECK(pendingIn(withNews) == 2);

    api.stop();
    serving.join();
    std::filesystem::remove_all(root);
    std::printf("TestHeldMailWait ok\n");
    return 0;
}
