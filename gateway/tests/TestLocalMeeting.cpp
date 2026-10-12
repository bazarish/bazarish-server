// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Tls.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <thread>
#include <filesystem>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/2b8e61a0d7c4";
constexpr const char* kToken = "a-third-static-token";
constexpr int kWaitSeconds = 20;
constexpr const char* kServerDest = "fkc4nkqn6k2bwrqsgbabnkyx4g5s2cp3nvnrdnkqxz4bzcbzrfaa.b32.i2p";

i2p::RouterConfig borrowedFrom(const int port)
{
    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayToken = kToken;
    config.gatewayTls = false;
    return config;
}

bool waitFor(const std::function<bool()>& done)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kWaitSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return done();
}

bool routedLocally(const i2p::Router& router, const std::string& host)
{
    for (const i2p::LocalDestination& destination : router.localDestinations()) {
        if (destination.host == host) {
            return destination.localRoute;
        }
    }
    return false;
}

std::string readAll(i2p::Stream& stream, const std::size_t expected)
{
    std::string got;
    std::vector<char> buffer(256);
    while (got.size() < expected) {
        const std::size_t read = stream.readSome(buffer.data(), buffer.size());
        if (read == 0) {
            break;
        }
        got.append(buffer.data(), read);
    }
    return got;
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-meeting-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.token = kToken;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";

    const tls::Credential server = tls::selfSigned(root / "server");
    http::Server::Options serverOptions;
    serverOptions.port = 0;
    serverOptions.threads = 1;
    serverOptions.certificate = server.certificate.string();
    serverOptions.key = server.key.string();
    http::Server listener(serverOptions);
    listener.get("/v1/server/card", [](const http::Request&) {
        return http::Response{200, "application/json", {}, R"({"card":"here"})"};
    });
    const int listenerPort = listener.start();
    CHECK(listenerPort > 0);
    DirectRoute route;
    route.dest = kServerDest;
    route.host = "127.0.0.1";
    route.port = listenerPort;
    route.pin = server.pin;
    settings.direct.push_back(route);

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));

    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    i2p::Router alice(borrowedFrom(port));
    i2p::Router bob(borrowedFrom(port));
    alice.start();
    bob.start();

    i2p::EndpointConfig serving;
    serving.privacy = i2p::Privacy::eMinimal;
    serving.published = true;
    const std::shared_ptr<i2p::Endpoint> hers = alice.createEndpoint(serving);
    const std::string host = hers->routingHost();
    CHECK(host.find(".b32.i2p") != std::string::npos);

    i2p::EndpointConfig dialling;
    dialling.privacy = i2p::Privacy::eMinimal;
    dialling.published = false;
    dialling.bulk = true;
    const std::shared_ptr<i2p::Endpoint> his = bob.createEndpoint(dialling);

    CHECK(waitFor([&]() { return gateway.sockets() == 3; }));

    CHECK(!routedLocally(bob, his->routingHost()));
    const std::unique_ptr<i2p::Stream> out
        = his->connect(host, std::chrono::seconds(kWaitSeconds));
    CHECK(out != nullptr);
    CHECK(waitFor([&]() {
        return routedLocally(bob, his->routingHost()) && routedLocally(alice, host);
    }));

    std::string caller;
    const std::unique_ptr<i2p::Stream> in
        = hers->accept(caller, std::chrono::seconds(kWaitSeconds));
    CHECK(in != nullptr);
    CHECK(!caller.empty());

    const std::string noise = "media";
    CHECK_THROWS(his->sendRawDatagram(host, noise.data(), noise.size()));
    CHECK_THROWS(hers->receiveRawDatagram(std::chrono::milliseconds(10)));

    const std::string question = "who is there";
    out->writeAll(question.data(), question.size());
    CHECK(readAll(*in, question.size()) == question);

    const std::string answer = "somebody on the same gateway";
    in->writeAll(answer.data(), answer.size());
    CHECK(readAll(*out, answer.size()) == answer);

    std::string bulk;
    while (bulk.size() < 3 * kStreamWindowBytes) {
        bulk += "0123456789abcdef";
    }
    out->writeAll(bulk.data(), bulk.size());
    CHECK(readAll(*in, bulk.size()) == bulk);

    const std::string last = "goodbye";
    in->writeAll(last.data(), last.size());
    in->close();
    std::string tail;
    std::vector<char> buffer(64);
    for (;;) {
        const std::size_t read = out->readSome(buffer.data(), buffer.size());
        if (read == 0) {
            break;
        }
        tail.append(buffer.data(), read);
    }
    CHECK(tail == last);

    const std::unique_ptr<i2p::Stream> second
        = his->connect(host, std::chrono::seconds(kWaitSeconds));
    CHECK(second != nullptr);
    std::string another;
    const std::unique_ptr<i2p::Stream> taken
        = hers->accept(another, std::chrono::seconds(kWaitSeconds));
    CHECK(taken != nullptr);
    std::atomic<bool> ended{false};
    std::thread reader([&]() {
        std::vector<char> idle(64);
        try {
            (void)taken->readSome(idle.data(), idle.size());
        } catch (const std::exception&) {
        }
        ended.store(true);
    });
    hers->stop();
    CHECK(waitFor([&]() { return ended.load(); }));
    reader.join();

    CHECK(gateway.refusals() == 0);

    i2p::EndpointConfig toServer;
    toServer.privacy = i2p::Privacy::eMinimal;
    toServer.published = false;
    const std::shared_ptr<i2p::Endpoint> link = bob.createEndpoint(toServer);
    CHECK(!routedLocally(bob, link->routingHost()));
    const std::unique_ptr<i2p::Stream> card
        = link->connect(kServerDest, std::chrono::seconds(kWaitSeconds));
    CHECK(card != nullptr);
    CHECK(waitFor([&]() { return routedLocally(bob, link->routingHost()); }));
    card->close();
    link->stop();

    out->close();
    his->stop();
    hers->stop();
    bob.stop();
    alice.stop();
    gateway.stop();
    listener.stop();
    std::filesystem::remove_all(root);
    std::printf("TestLocalMeeting ok\n");
    return 0;
}
