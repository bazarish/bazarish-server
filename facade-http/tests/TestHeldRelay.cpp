// Bazarish project (c) 2026
#include "Facade.hpp"
#include "HttpTestUtil.hpp"
#include "TestUtil.hpp"

#include <bazarish/HttpClient.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Tls.hpp>
#include <bazarish/Tunnel.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace http = bazarish::http;

namespace {

// Past the 60 s the facade once gave its backend: a held mail wait inside the tunnel.
constexpr std::chrono::seconds kHeldFor{62};
constexpr const char* kAnswer = "mail arrived";

}  // namespace

int main()
{
    const std::filesystem::path state = testutil::freshDir("facade-held-relay");
    const bazarish::tls::Credential backendCredential
        = bazarish::tls::selfSigned(state / "backend");
    http::Server::Options backendOptions;
    backendOptions.port = 0;
    backendOptions.certificate = backendCredential.certificate.string();
    backendOptions.key = backendCredential.key.string();
    http::Server backend(backendOptions);
    std::mutex answering;
    std::vector<std::thread> answerers;
    backend.routeAsync("POST", std::string(bazarish::tunnel::kTunnelPath),
        [&answering, &answerers](const http::Request&,
            http::Responder respond) -> std::optional<http::Response> {
            const std::lock_guard<std::mutex> lock(answering);
            answerers.emplace_back([respond]() {
                std::this_thread::sleep_for(kHeldFor);
                respond(http::Response{200, "text/plain", {}, kAnswer});
            });
            return std::nullopt;
        });
    const int backendPort = backend.start();
    CHECK(backendPort > 0);

    const std::filesystem::path configPath = state / "facade.json";
    {
        std::ofstream config(configPath);
        config << "{\n  \"logLevel\": \"info\"\n}\n";
    }
    bazarish::facade::FacadeSettings::Values values;
    values.logLevel = "info";
    values.messagingHost = "127.0.0.1";
    values.messagingPort = backendPort;
    bazarish::facade::FacadeOptions options;
    options.messaging = {"127.0.0.1", backendPort, backendCredential.pin};
    options.serviceNode = {"127.0.0.1", backendPort, backendCredential.pin};
    options.address = "example.b32.i2p";
    options.settings = std::make_shared<bazarish::facade::FacadeSettings>(configPath, values);
    options.stateDirectory = (state / "facade").string();
    options.requestRestart = []() {};
    bazarish::facade::Facade facade(options);
    const int facadePort = facade.bind("127.0.0.1", 0);
    CHECK(facadePort > 0);

    http::ClientOptions unbounded;
    unbounded.readTimeout = std::chrono::seconds(0);
    const auto asked = std::chrono::steady_clock::now();
    const http::ClientResponse relayed = testutil::call(facadePort, "POST",
        std::string(bazarish::tunnel::kTunnelPath), {}, "sealed", unbounded);
    const auto took = std::chrono::steady_clock::now() - asked;
    CHECK(relayed.status == 200);
    CHECK(relayed.body == kAnswer);
    CHECK(took >= kHeldFor);

    facade.stop();
    {
        const std::lock_guard<std::mutex> lock(answering);
        for (std::thread& answerer : answerers) {
            answerer.join();
        }
    }
    backend.stop();
    std::filesystem::remove_all(state);
    std::printf("TestHeldRelay ok\n");
    return 0;
}
