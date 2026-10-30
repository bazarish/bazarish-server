// Bazarish project (c) 2026
#include "HttpApi.hpp"

#include "DiskStorage.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Tunnel.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::server;

namespace {

namespace http = bazarish::http;

bool opensAsAnswer(const std::string& body, const Bytes& tunnelKey)
{
    try {
        (void)tunnel::decodeResponse(tunnel::open(Bytes(body.begin(), body.end()), tunnelKey));
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

int main()
{
    bazarish::log::setLevel(bazarish::log::Level::eError);
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-tunnel-test";
    std::filesystem::remove_all(root);
    DiskStorage storage(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const Bytes card = ServerCard::issue(serverIdentity, ServerCard::Service::eMessaging,
        Key::fromPublicDer(serverSealing.publicDer()), nowSeconds());

    HttpApiOptions options;
    options.sealingKey = std::make_shared<Key>(Key::fromPrivatePem(serverSealing.privatePem()));
    options.serverCardDer = card;
    const auto serving = std::make_shared<Key>(Key::fromPrivatePem(serverSealing.privatePem()));
    options.assignDestination = [serving](const std::string&) {
        return DestinationAssignment{"x.b32.i2p", serving, "home"};
    };

    HttpApi api(storage, options);
    const int port = api.bind("127.0.0.1", 0);
    CHECK(port > 0);
    std::thread serverThread([&api]() { api.wait(); });

    const auto post = [port](const Bytes& frame) {
        http::ClientRequest request;
        request.method = "POST";
        request.target = tunnel::kTunnelPath;
        request.contentType = "application/octet-stream";
        request.body = std::string(frame.begin(), frame.end());
        return http::request("127.0.0.1", port, request, {});
    };

    const Identity alice = Identity::generate();
    const Bytes secret = randomBytes(32);
    const Key replyKey = Key::generateSealing();
    tunnel::Hello hello;
    hello.secret = secret;
    hello.replyKeyDer = replyKey.publicDer();
    hello.signature = auth::signRequest(
        alice, nowSeconds(), tunnel::kHelloMethod, tunnel::kHelloPath, secret);
    const http::ClientResponse welcome
        = post(tunnel::sealHello(hello, Key::fromPublicDer(serverSealing.publicDer())));
    CHECK(welcome.status == 200);
    const tunnel::Welcome opened
        = tunnel::openWelcome(Bytes(welcome.body.begin(), welcome.body.end()), replyKey);
    CHECK(opened.expiresUnix > nowSeconds());

    const std::string id = toHex(sha256(secret)).substr(0, 32);
    const Bytes tunnelKey = tunnel::deriveTunnelKey(secret, id);

    std::uint64_t seq = 0;
    const auto carry = [&](const std::string& method, const std::string& path,
                           const Bytes& body = {}) {
        tunnel::Request inner;
        inner.method = method;
        inner.path = path;
        inner.body = body;
        if (!body.empty()) {
            inner.contentType = "application/octet-stream";
        }
        return post(tunnel::carry(
            auth::sessionHandle(secret, ++seq), tunnelKey, tunnel::encodeRequest(inner)));
    };

    {
        const http::ClientResponse answered = carry("GET", tunnel::kServerCardPath);
        CHECK(answered.status == 200);
        const tunnel::Response inner = tunnel::decodeResponse(
            tunnel::open(Bytes(answered.body.begin(), answered.body.end()), tunnelKey));
        CHECK(inner.status == 200);
        CHECK(inner.body == card);
    }

    {
        const http::ClientResponse answered = carry("GET", "/no/such/route");
        CHECK(answered.status == 200);
        const tunnel::Response inner = tunnel::decodeResponse(
            tunnel::open(Bytes(answered.body.begin(), answered.body.end()), tunnelKey));
        CHECK(inner.status == 404);
    }

    {
        tunnel::Request innermost;
        innermost.method = "GET";
        innermost.path = tunnel::kServerCardPath;
        const Bytes nested = tunnel::carry(
            auth::sessionHandle(secret, 1000), tunnelKey, tunnel::encodeRequest(innermost));
        for (const char* const path : {tunnel::kTunnelPath, tunnel::kNodeTunnelPath}) {
            const http::ClientResponse answered = carry("POST", path, nested);
            CHECK(answered.status == 200);
            CHECK(!opensAsAnswer(answered.body, tunnelKey));
        }
    }

    {
        const http::ClientResponse answered = carry("GET", "/internal/i2pseeds.su3");
        CHECK(answered.status == 200);
        CHECK(!opensAsAnswer(answered.body, tunnelKey));
    }

    {
        const http::ClientResponse answered = post(tunnel::carry(
            auth::sessionHandle(randomBytes(32), 1), tunnelKey, Bytes{'x'}));
        CHECK(answered.status == 200);
        CHECK(!opensAsAnswer(answered.body, tunnelKey));
    }

    api.stop();
    serverThread.join();
    std::filesystem::remove_all(root);
    std::printf("TestTunnelFace OK\n");
    return 0;
}
