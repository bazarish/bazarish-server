// Bazarish project (c) 2026
#include "LogFeed.hpp"
#include "OpsClient.hpp"
#include "TestUtil.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Tls.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <future>
#include <memory>
#include <string>
#include <thread>

using namespace bazarish;
using bazarish::log::Level;

namespace {

constexpr std::chrono::milliseconds kTestWait{1500};
constexpr std::chrono::milliseconds kSettle{200};
constexpr std::chrono::seconds kConnect{2};
constexpr std::chrono::seconds kExchange{10};
constexpr std::int64_t kSomeMillis = 1700000000000;
constexpr int kOk = 200;
constexpr int kBadRequest = 400;
constexpr int kForbidden = 403;

nlohmann::json pageOf(const http::ClientResponse& answer)
{
    CHECK(answer.status == kOk);
    return nlohmann::json::parse(answer.body);
}

}  // namespace

int main()
{
    bazarish::log::setLevel(Level::eError);
    const std::filesystem::path root = testutil::freshDir("log-feed-test");
    const tls::Credential serverKeys = tls::selfSigned(root / "server");
    const tls::Credential clientKeys = tls::selfSigned(root / "client");
    const Identity panel = Identity::generate();
    const Identity stranger = Identity::generate();
    const std::vector<std::string> operators{panel.fingerprint()};
    auth::ReplayCache replays;

    http::Server::Options options;
    options.port = 0;
    options.threads = 1;
    options.certificate = serverKeys.certificate.string();
    options.key = serverKeys.key.string();
    options.clientPins = {clientKeys.pin};
    http::Server ops(options);
    const auto ring = std::make_shared<server::LogRing>();
    ring->append(Level::eInfo, "first", kSomeMillis);
    ring->append(Level::eWarn, "second", kSomeMillis);
    std::atomic<int> pings{0};
    ops.get("/ping", [&pings](const http::Request&) {
        ++pings;
        return http::Response{kOk, "application/json", {}, "{}"};
    });
    {
        const server::LogFeed feed(
            ops, "/logs", ring, server::operatorCheck(operators, replays), kTestWait);
        const int port = ops.start();
        CHECK(port > 0);
        const server::OpsTarget target{"https://127.0.0.1:" + std::to_string(port),
            serverKeys.pin, clientKeys.certificate.string(), clientKeys.key.string()};
        const server::OpsTimeouts timeouts{kConnect, kExchange};
        const auto ask = [&](const Identity& who, const std::string& pathAndQuery) {
            return server::opsCall(target, who, "GET", pathAndQuery, {}, timeouts);
        };

        CHECK(ask(stranger, "/logs?after=0").status == kForbidden);
        CHECK(ask(panel, "/logs?after=two").status == kBadRequest);

        const nlohmann::json all = pageOf(ask(panel, "/logs?after=0"));
        CHECK(all.at("instance") == ring->instance());
        CHECK(all.at("first") == 1);
        CHECK(all.at("lines").size() == 2);
        CHECK(all.at("lines")[1].at("text") == "second");
        CHECK(all.at("lines")[1].at("level") == "warn");

        const auto beyondAsked = std::chrono::steady_clock::now();
        const nlohmann::json beyond = pageOf(ask(panel, "/logs?after=99"));
        CHECK(std::chrono::steady_clock::now() - beyondAsked < kTestWait);
        CHECK(beyond.at("lines").empty());
        CHECK(beyond.at("instance") == ring->instance());

        std::atomic<bool> answered{false};
        const auto heldAsked = std::chrono::steady_clock::now();
        std::future<http::ClientResponse> held = std::async(std::launch::async, [&]() {
            http::ClientResponse answer = ask(panel, "/logs?after=2");
            answered = true;
            return answer;
        });
        std::this_thread::sleep_for(kSettle);
        CHECK(!answered);
        CHECK(ask(panel, "/ping").status == kOk);
        CHECK(pings == 1);
        CHECK(!answered);
        ring->append(Level::eError, "third", kSomeMillis);
        const nlohmann::json woken = pageOf(held.get());
        const auto heldFor = std::chrono::steady_clock::now() - heldAsked;
        CHECK(heldFor >= kSettle);
        CHECK(heldFor < kTestWait);
        CHECK(woken.at("lines").size() == 1);
        CHECK(woken.at("lines")[0].at("seq") == 3);
        CHECK(woken.at("lines")[0].at("text") == "third");

        const auto idleAsked = std::chrono::steady_clock::now();
        const nlohmann::json idle = pageOf(ask(panel, "/logs?after=3"));
        CHECK(std::chrono::steady_clock::now() - idleAsked >= kTestWait);
        CHECK(idle.at("lines").empty());
        CHECK(idle.at("first") == 1);

        ring->append(Level::eInfo, std::string("bad \xff byte"), kSomeMillis);
        const nlohmann::json mangled = pageOf(ask(panel, "/logs?after=3"));
        CHECK(mangled.at("lines").size() == 1);

        ops.stop();
    }
    std::filesystem::remove_all(root);
    std::printf("TestLogFeed OK\n");
    return 0;
}
