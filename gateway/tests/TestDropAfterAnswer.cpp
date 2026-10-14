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
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/a41f7d2c9e60";
constexpr const char* kToken = "a-seventh-static-token";
constexpr const char* kServerDest = "fkc4nkqn6k2bwrqsgbabnkyx4g5s2cp3nvnrdnkqxz4bzcbzrfaa.b32.i2p";
constexpr std::chrono::seconds kWait{10};
constexpr int kExchanges = 400;
constexpr std::size_t kAnswerBytes = 300;
constexpr const char* kHeaderEnd = "\r\n\r\n";

}  // namespace

// A stream dropped the moment its answer is read races the frames the gateway still sends for it.
int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-drop-after-answer-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const tls::Credential served = tls::selfSigned(root / "served");
    http::Server::Options options;
    options.port = 0;
    options.threads = 4;
    options.certificate = served.certificate.string();
    options.key = served.key.string();
    http::Server listener(options);
    listener.get("/card", [](const http::Request&) {
        return http::Response{200, "text/plain", {}, std::string(kAnswerBytes, 'c')};
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
    i2p::Router client(config);
    client.start();

    i2p::EndpointConfig dialling;
    dialling.published = false;
    const std::shared_ptr<i2p::Endpoint> link = client.createEndpoint(dialling);

    int whole = 0;
    for (int exchange = 0; exchange < kExchanges; ++exchange) {
        std::unique_ptr<i2p::Stream> stream = link->connect(kServerDest, kWait);
        CHECK(stream != nullptr);
        stream->setReadTimeout(kWait);
        const std::string ask = "GET /card HTTP/1.1\r\nHost: served\r\nConnection: close\r\n\r\n";
        stream->writeAll(ask.data(), ask.size());
        std::string heard;
        std::vector<char> buffer(4096);
        try {
            for (;;) {
                const std::size_t headers = heard.find(kHeaderEnd);
                if (headers != std::string::npos
                    && heard.size() - headers - std::string(kHeaderEnd).size() >= kAnswerBytes) {
                    break;
                }
                const std::size_t got = stream->readSome(buffer.data(), buffer.size());
                if (got == 0) {
                    break;
                }
                heard.append(buffer.data(), got);
            }
        } catch (const std::exception& error) {
            std::printf("exchange %d: %s after %zu bytes\n", exchange, error.what(), heard.size());
        }
        stream.reset();
        const bool complete = heard.find(std::string(kAnswerBytes, 'c')) != std::string::npos;
        if (!complete) {
            std::printf("exchange %d ended after %zu bytes\n", exchange, heard.size());
        }
        whole += complete ? 1 : 0;
    }
    std::printf("%d of %d answers whole\n", whole, kExchanges);
    CHECK(whole == kExchanges);

    link->stop();
    client.stop();
    gateway.stop();
    listener.stop();
    std::filesystem::remove_all(root);
    std::printf("TestDropAfterAnswer ok\n");
    return 0;
}
