// Bazarish project (c) 2026
#include "Gateway.hpp"

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <bazarish/HttpServer.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Tls.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/7c1e05a9d3b2";
constexpr const char* kToken = "a-fifth-static-token";
constexpr const char* kServerDest = "fkc4nkqn6k2bwrqsgbabnkyx4g5s2cp3nvnrdnkqxz4bzcbzrfaa.b32.i2p";
constexpr int kWaitSeconds = 20;
constexpr int kRequests = 30;
constexpr int kLongestAnswerDelayMs = 1500;
constexpr std::size_t kAnswerBytes = 3000;

}  // namespace

// Answers that come back while the client is between two control sockets must not be lost.
int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-churn-direct-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const tls::Credential served = tls::selfSigned(root / "served");
    http::Server::Options options;
    options.port = 0;
    options.threads = 4;
    options.certificate = served.certificate.string();
    options.key = served.key.string();
    http::Server listener(options);
    int counter = 0;
    listener.get("/slow", [&counter](const http::Request&) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds((++counter * 337) % kLongestAnswerDelayMs));
        return http::Response{200, "text/plain", {}, std::string(kAnswerBytes, 'z')};
    });
    const int listenerPort = listener.start();
    CHECK(listenerPort > 0);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.token = kToken;
    settings.stateDir = root / "state";
    settings.notFoundBody = "<html>nothing</html>";
    DirectRoute route;
    route.dest = kServerDest;
    route.host = "127.0.0.1";
    route.port = listenerPort;
    route.pin = served.pin;
    settings.direct.push_back(route);

    i2p::Router engine(i2p::offlineRouter(root / "i2p"));
    Gateway gateway(settings, engine);
    const int port = gateway.start();
    CHECK(port > 0);

    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = "127.0.0.1";
    config.gatewayPort = port;
    config.gatewayPath = kPath;
    config.gatewayToken = kToken;
    config.gatewayTls = false;
    config.gatewayControlMinLife = std::chrono::seconds(1);
    config.gatewayControlMaxLife = std::chrono::seconds(1);
    config.gatewayControlMaxGap = std::chrono::seconds(1);
    i2p::Router client(config);
    client.start();

    i2p::EndpointConfig dialling;
    dialling.published = false;
    const std::shared_ptr<i2p::Endpoint> link = client.createEndpoint(dialling);

    int whole = 0;
    for (int request = 0; request < kRequests; ++request) {
        const std::unique_ptr<i2p::Stream> stream
            = link->connect(kServerDest, std::chrono::seconds(kWaitSeconds));
        CHECK(stream != nullptr);
        stream->setReadTimeout(std::chrono::seconds(kWaitSeconds));
        const std::string ask = "GET /slow HTTP/1.1\r\nHost: served\r\nConnection: close\r\n\r\n";
        std::string heard;
        std::vector<char> buffer(4096);
        try {
            stream->writeAll(ask.data(), ask.size());
            for (;;) {
                const std::size_t got = stream->readSome(buffer.data(), buffer.size());
                if (got == 0) {
                    break;
                }
                heard.append(buffer.data(), got);
            }
        } catch (const std::exception& error) {
            std::printf("request %d: %s after %zu bytes\n", request, error.what(), heard.size());
        }
        whole += heard.find(std::string(kAnswerBytes, 'z')) != std::string::npos ? 1 : 0;
    }
    std::printf("%d of %d answers whole, %zu rejoins\n", whole, kRequests, gateway.rejoins());
    CHECK(whole == kRequests);
    CHECK(gateway.rejoins() >= 2);

    link->stop();
    client.stop();
    gateway.stop();
    listener.stop();
    std::filesystem::remove_all(root);
    std::printf("TestChurnDirect ok\n");
    return 0;
}
