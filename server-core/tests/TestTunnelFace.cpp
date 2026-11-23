// Bazarish project (c) 2026
#include "HttpApi.hpp"
#include "EventGate.hpp"
#include "DeviceTestKit.hpp"
#include "TestUtil.hpp"

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

using namespace bazarish;
using namespace bazarish::server;

namespace {

namespace http = bazarish::http;

bool opensAsAnswer(const std::string& body, const SecretBytes& tunnelKey, const std::string& handle)
{
    try {
        (void)tunnel::decodeResponse(tunnel::open(
            Bytes(body.begin(), body.end()), tunnelKey, tunnel::Direction::eAnswer, handle));
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

int main()
try {
    bazarish::log::setLevel(bazarish::log::Level::eError);
    const testutil::ScratchDir scratch("tunnel-test");
    const std::filesystem::path& root = scratch.path();
    DiskStorage storage(root);

    const Identity serverIdentity = Identity::generate();
    const Key serverSealing = Key::generateSealing();
    const Bytes card = ServerCard::issue(serverIdentity, ServerCard::Service::eMessaging,
        Key::fromPublicDer(serverSealing.publicDer()));

    HttpApiOptions options;
    options.fingerprint = serverIdentity.fingerprint();
    options.sealingKey = std::make_shared<Key>(Key::fromPrivatePem(serverSealing.privatePem()));
    options.serverCardDer = card;
    options.assignDestination
        = [](const std::string&) { return DestinationAssignment{"x.b32.i2p", "home"}; };
    options.accountRevocation
        = [](const std::string&) { return std::optional<Revocation>(Revocation{}); };
    options.accountCard = [](const std::string&) { return std::optional<Bytes>(); };

    EventGate eventGate;
    HttpApi api(storage, eventGate, options);
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

    const devicetest::Account alice;
    const SecretBytes secret(randomBytes(32));
    const Key replyKey = Key::generateSealing();
    tunnel::Hello hello;
    hello.secret = secret;
    hello.replyKeyDer = replyKey.publicDer();
    {
        tunnel::Hello forAnother = hello;
        forAnother.signature = auth::signDeviceRequest(alice.device, nowSeconds(),
            tunnel::kHelloMethod, tunnel::kHelloPath,
            tunnel::helloSigned(secret, Identity::generate().fingerprint()).bytes());
        const http::ClientResponse refused
            = post(tunnel::sealHello(forAnother, Key::fromPublicDer(serverSealing.publicDer())));
        CHECK(refused.status == 200);
        CHECK_THROWS(tunnel::openWelcome(Bytes(refused.body.begin(), refused.body.end()), replyKey));
    }
    hello.signature = auth::signDeviceRequest(alice.device, nowSeconds(), tunnel::kHelloMethod,
        tunnel::kHelloPath, tunnel::helloSigned(secret, serverIdentity.fingerprint()).bytes());
    const http::ClientResponse welcome
        = post(tunnel::sealHello(hello, Key::fromPublicDer(serverSealing.publicDer())));
    CHECK(welcome.status == 200);
    const tunnel::Welcome opened
        = tunnel::openWelcome(Bytes(welcome.body.begin(), welcome.body.end()), replyKey);
    CHECK(opened.expiresUnix > nowSeconds());

    const std::string id = toHex(sha256(secret.bytes())).substr(0, 32);
    const SecretBytes tunnelKey = tunnel::deriveTunnelKey(secret, id);

    std::uint64_t seq = 0;
    std::string handle;
    const auto carry = [&](const std::string& method, const std::string& path,
                           const Bytes& body = {}) {
        tunnel::Request inner;
        inner.method = method;
        inner.path = path;
        inner.body = SecretBytes(body);
        if (!body.empty()) {
            inner.contentType = "application/octet-stream";
        }
        handle = auth::sessionHandle(secret, ++seq);
        return post(tunnel::carry(
            handle, tunnelKey, tunnel::Direction::eRequest, tunnel::encodeRequest(inner)));
    };

    {
        const http::ClientResponse answered = carry("GET", tunnel::kServerCardPath);
        CHECK(answered.status == 200);
        const tunnel::Response inner = tunnel::decodeResponse(
            tunnel::open(Bytes(answered.body.begin(), answered.body.end()), tunnelKey,
                tunnel::Direction::eAnswer, handle));
        CHECK(inner.status == 200);
        CHECK(inner.body == card);
    }

    {
        const http::ClientResponse answered = carry("GET", "/no/such/route");
        CHECK(answered.status == 200);
        const tunnel::Response inner = tunnel::decodeResponse(
            tunnel::open(Bytes(answered.body.begin(), answered.body.end()), tunnelKey,
                tunnel::Direction::eAnswer, handle));
        CHECK(inner.status == 404);
    }

    {
        tunnel::Request innermost;
        innermost.method = "GET";
        innermost.path = tunnel::kServerCardPath;
        const Bytes nested = tunnel::carry(auth::sessionHandle(secret, 1000), tunnelKey,
            tunnel::Direction::eRequest, tunnel::encodeRequest(innermost));
        for (const char* const path : {tunnel::kTunnelPath, tunnel::kNodeTunnelPath}) {
            const http::ClientResponse answered = carry("POST", path, nested);
            CHECK(answered.status == 200);
            CHECK(!opensAsAnswer(answered.body, tunnelKey, handle));
        }
    }

    {
        const std::string strangers = auth::sessionHandle(SecretBytes(randomBytes(32)), 1);
        const http::ClientResponse answered
            = post(tunnel::carry(strangers, tunnelKey, tunnel::Direction::eRequest, SecretBytes(Bytes{'x'})));
        CHECK(answered.status == 200);
        CHECK(!opensAsAnswer(answered.body, tunnelKey, strangers));
    }

    api.stop();
    serverThread.join();
    std::printf("TestTunnelFace OK\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
