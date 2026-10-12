// Bazarish project (c) 2026
#include "Conduit.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Tls.hpp>

#include "TestUtil.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace bazarish;
using namespace bazarish::gateway;

int main()
{
    const fs::path root = fs::temp_directory_path() / ("bazarish-direct-" + toHex(randomBytes(8)));
    const tls::Credential served = tls::selfSigned(root / "served");
    const tls::Credential other = tls::selfSigned(root / "other");

    http::Server::Options options;
    options.port = 0;
    options.threads = 1;
    options.certificate = served.certificate.string();
    options.key = served.key.string();
    http::Server listener(options);
    listener.get("/v1/server/card", [](const http::Request&) {
        return http::Response{200, "application/json", {}, R"({"card":"here"})"};
    });
    const int port = listener.start();
    CHECK(port > 0);

    DirectRoute route;
    route.dest = "fkc4nkqn6k2bwrqsgbabnkyx4g5s2cp3nvnrdnkqxz4bzcbzrfaa.b32.i2p";
    route.host = "127.0.0.1";
    route.port = port;
    route.pin = served.pin;

    const std::unique_ptr<Conduit> pipe = overTls(route, std::chrono::seconds(5));
    const std::string ask
        = "GET /v1/server/card HTTP/1.1\r\nHost: served\r\nConnection: close\r\n\r\n";
    pipe->writeAll(ask.data(), ask.size());

    std::string heard;
    std::string buffer(1024, '\0');
    for (;;) {
        const std::size_t got = pipe->readSome(buffer.data(), buffer.size());
        if (got == 0) {
            break;
        }
        heard.append(buffer, 0, got);
    }
    CHECK(heard.find("200") != std::string::npos);
    CHECK(heard.find(R"({"card":"here"})") != std::string::npos);
    pipe->close();

    DirectRoute wrong = route;
    wrong.pin = other.pin;
    CHECK_THROWS(overTls(wrong, std::chrono::seconds(5)));

    DirectRoute nobody = route;
    nobody.port = 1;
    CHECK_THROWS(overTls(nobody, std::chrono::seconds(2)));

    listener.stop();
    fs::remove_all(root);
    std::printf("TestDirectRoute: all checks passed\n");
    return 0;
}
