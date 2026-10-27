// Bazarish project (c) 2026
#include "Gateway.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/HttpClient.hpp>
#include <bazarish/Tls.hpp>

#include "TestRouter.hpp"
#include "TestUtil.hpp"

#include <utility>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <set>
#include <thread>
#include <string>
#include <vector>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace bhttp = boost::beast::http;
namespace websocket = boost::beast::websocket;
using asio::ip::tcp;
using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr const char* kPath = "/f3a9c2e1b7d4";
constexpr const char* kToken = "a-static-token";
constexpr const char* kHealthPath = "/healthz";
constexpr int kSweepGraceSeconds = 5;
constexpr int kDialDeadlineSeconds = 4;
constexpr std::size_t kDecoyLow = 1024;
constexpr std::size_t kDecoyHigh = 4096;

struct Answer {
    unsigned status = 0;
    std::string body;
    std::string contentType;
    std::string server;
};

Answer request(const int port, const std::string& method, const std::string& path,
    const std::string& token, const auth::Headers& signed_ = {})
{
    asio::io_context io;
    tcp::socket socket(io);
    socket.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"),
        static_cast<unsigned short>(port)));
    bhttp::request<bhttp::string_body> out{bhttp::string_to_verb(method), path, 11};
    out.set(bhttp::field::host, "127.0.0.1");
    if (!token.empty()) {
        out.set(kTokenHeader, token);
    }
    for (const auto& [name, value] : signed_) {
        out.set(name, value);
    }
    out.prepare_payload();
    bhttp::write(socket, out);
    beast::flat_buffer buffer;
    bhttp::response<bhttp::string_body> in;
    bhttp::read(socket, buffer, in);
    Answer answer;
    answer.status = in.result_int();
    answer.body = in.body();
    answer.contentType = std::string(in[bhttp::field::content_type]);
    answer.server = std::string(in[bhttp::field::server]);
    return answer;
}

int unusedPort()
{
    asio::io_context io;
    const tcp::acceptor door(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    return door.local_endpoint().port();
}

http::ClientResponse askOps(const int port, const std::string& pin,
    const auth::Headers& signed_ = {})
{
    http::ClientRequest out;
    out.method = "GET";
    out.target = kHealthPath;
    out.headers = signed_;
    http::ClientOptions options;
    options.tls = true;
    options.pin = pin;
    return http::request("127.0.0.1", port, out, options);
}

struct Dialled {
    std::unique_ptr<websocket::stream<tcp::socket>> socket;
    unsigned refusedWith = 0;
};

Dialled dial(asio::io_context& io, const int port, const std::string& token,
    const std::string& cookie)
{
    tcp::socket raw(io);
    raw.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"),
        static_cast<unsigned short>(port)));
    auto stream = std::make_unique<websocket::stream<tcp::socket>>(std::move(raw));
    stream->set_option(
        websocket::stream_base::decorator([token, cookie](websocket::request_type& request) {
            request.set(kTokenHeader, token);
            if (!cookie.empty()) {
                request.set(kSessionHeader, cookie);
            }
            request.set(bhttp::field::sec_websocket_protocol, kSubprotocol);
        }));
    websocket::response_type response;
    boost::system::error_code error;
    stream->handshake(response, "127.0.0.1", kPath, error);
    Dialled out;
    if (error) {
        out.refusedWith = static_cast<unsigned>(response.result_int());
        return out;
    }
    stream->binary(true);
    out.socket = std::move(stream);
    return out;
}

void send(websocket::stream<tcp::socket>& socket, const Bytes& frame)
{
    socket.write(asio::buffer(frame.data(), frame.size()));
}

Frame receive(websocket::stream<tcp::socket>& socket)
{
    beast::flat_buffer buffer;
    socket.read(buffer);
    return decode(buffer.data().data(), buffer.size());
}

nlohmann::json greet(websocket::stream<tcp::socket>& socket, const int version = kProtocolVersion)
{
    send(socket, encodeJson(FrameType::eHello, 2, {{"version", version}}));
    const Frame answer = receive(socket);
    return {{"type", static_cast<int>(answer.type)}, {"ref", answer.ref},
        {"body", bodyJson(answer)}};
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = std::filesystem::temp_directory_path() / "bazarish-gateway-test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
    settings.token = kToken;
    settings.stateDir = root / "state";
    settings.decoyMinBytes = kDecoyLow;
    settings.decoyMaxBytes = kDecoyHigh;
    settings.notFoundBody = "<html>nothing</html>";
    settings.sessionTtlSeconds = 2;
    const Identity operatorIdentity = Identity::generate();
    settings.operators.push_back(operatorIdentity.fingerprint());
    settings.opsHost = "127.0.0.1";
    settings.opsPort = unusedPort();

    i2p::Router router(i2p::offlineRouter(root / "i2p"));

    Gateway gateway(settings, router);
    const int port = gateway.start();
    CHECK(port > 0);

    const Answer stranger = request(port, "GET", "/", {});
    CHECK(stranger.status == 404);
    CHECK(stranger.body == settings.notFoundBody);
    CHECK(stranger.server == settings.serverName);

    const Answer noToken = request(port, "GET", kPath, {});
    const Answer wrongToken = request(port, "GET", kPath, "not-the-token");
    const Answer deepPath = request(port, "GET", std::string(kPath) + "/more", kToken);
    CHECK(noToken.body == stranger.body);
    CHECK(noToken.status == stranger.status);
    CHECK(noToken.contentType == stranger.contentType);
    CHECK(wrongToken.body == stranger.body);
    CHECK(wrongToken.status == stranger.status);
    CHECK(deepPath.body == stranger.body);

    CHECK(request(port, "GET", std::string(kPath) + kHealthPath, kToken).body == stranger.body);

    const std::string opsPin = tls::selfSigned(settings.stateDir).pin;
    CHECK(askOps(settings.opsPort, opsPin).status == 403);
    const Identity stranger2 = Identity::generate();
    CHECK(askOps(settings.opsPort, opsPin,
              auth::signRequest(stranger2, nowSeconds(), "GET", kHealthPath, Bytes()))
              .status
        == 403);
    const http::ClientResponse reported = askOps(settings.opsPort, opsPin,
        auth::signRequest(operatorIdentity, nowSeconds(), "GET", kHealthPath, Bytes()));
    CHECK(reported.status == 200);
    const nlohmann::json report = nlohmann::json::parse(reported.body);
    CHECK(report["service"] == "gateway");
    CHECK(report.contains("sessions"));
    CHECK(report.contains("destinations"));
    CHECK(report.contains("sockets"));
    CHECK(report["refused"] == 0);

    const Answer decoyOne = request(port, "POST", kPath, kToken);
    const Answer decoyTwo = request(port, "POST", kPath, kToken);
    CHECK(decoyOne.status == 200);
    CHECK(decoyOne.body.size() >= kDecoyLow);
    CHECK(decoyOne.body.size() <= kDecoyHigh);
    CHECK(decoyTwo.body.size() >= kDecoyLow);
    CHECK(decoyOne.body != decoyTwo.body);
    CHECK(decoyOne.server == settings.serverName);

    asio::io_context io;

    const Dialled refused = dial(io, port, "wrong-token", {});
    CHECK(refused.socket == nullptr);

    Dialled first = dial(io, port, kToken, {});
    CHECK(first.socket != nullptr);
    const nlohmann::json ready = greet(*first.socket);
    CHECK(ready["type"] == static_cast<int>(FrameType::eReady));
    CHECK(ready["ref"] == 2);
    CHECK(ready["body"]["version"] == kProtocolVersion);
    CHECK(ready["body"]["resumed"] == false);
    CHECK(ready["body"]["capabilities"]["routerCounters"] == false);
    CHECK(ready["body"]["capabilities"]["proxy"] == false);
    CHECK(ready["body"]["capabilities"]["offlineKeys"] == false);
    const std::string cookie = ready["body"]["session"];
    CHECK(!cookie.empty());

    send(*first.socket, encodeJson(FrameType::eHello, 4, {{"version", kProtocolVersion}}));
    const Frame twice = receive(*first.socket);
    CHECK(twice.type == FrameType::eError);
    CHECK(bodyJson(twice)["code"] == "bad-frame");

    boost::system::error_code ignored;
    first.socket->close(websocket::close_code::normal, ignored);
    first.socket.reset();

    Dialled again = dial(io, port, kToken, cookie);
    CHECK(again.socket != nullptr);
    const nlohmann::json resumed = greet(*again.socket);
    CHECK(resumed["body"]["resumed"] == true);
    CHECK(resumed["body"]["session"] == cookie);
    again.socket->close(websocket::close_code::normal, ignored);
    again.socket.reset();

    Dialled stale = dial(io, port, kToken, "a-cookie-from-nowhere");
    CHECK(stale.socket != nullptr);
    const nlohmann::json fresh = greet(*stale.socket);
    CHECK(fresh["body"]["resumed"] == false);
    CHECK(fresh["body"]["session"] != cookie);
    stale.socket->close(websocket::close_code::normal, ignored);
    stale.socket.reset();

    Dialled ancient = dial(io, port, kToken, {});
    CHECK(ancient.socket != nullptr);
    const nlohmann::json refusal = greet(*ancient.socket, kProtocolVersion + 1);
    CHECK(refusal["type"] == static_cast<int>(FrameType::eError));
    CHECK(refusal["body"]["code"] == "version");
    ancient.socket.reset();

    Dialled nonsense = dial(io, port, kToken, {});
    CHECK(nonsense.socket != nullptr);
    const Bytes garbage = {0x7F, 0x00, 0x00, 0x00, 0x01};
    send(*nonsense.socket, garbage);
    const Frame complaint = receive(*nonsense.socket);
    CHECK(complaint.type == FrameType::eError);
    CHECK(bodyJson(complaint)["code"] == "bad-frame");
    nonsense.socket.reset();

    Dialled twiceOver = dial(io, port, kToken, {});
    CHECK(twiceOver.socket != nullptr);
    (void)greet(*twiceOver.socket);

    std::set<std::string> warm;
    for (const i2p::LocalDestination& destination : router.localDestinations()) {
        warm.insert(destination.host);
    }
    CHECK(warm.size() == gateway.pooled());
    const nlohmann::json ask = {{"kind", "stream"},
        {"published", false}, {"realtime", false}};
    send(*twiceOver.socket, encodeJson(FrameType::eEndpointCreate, 6, ask));
    const Frame once = receive(*twiceOver.socket);
    CHECK(once.type == FrameType::eOk);
    CHECK(warm.count(bodyJson(once)["host"].get<std::string>()) == 1);
    CHECK(router.localDestinations().size() == gateway.pooled() + 1);
    send(*twiceOver.socket, encodeJson(FrameType::eEndpointCreate, 6, ask));
    const Frame repeat = receive(*twiceOver.socket);
    CHECK(repeat.type == FrameType::eOk);
    CHECK(bodyJson(repeat)["host"] == bodyJson(once)["host"]);
    twiceOver.socket->close(websocket::close_code::normal, ignored);
    twiceOver.socket.reset();

    const std::size_t refusedBefore = gateway.refusals();
    Dialled asking = dial(io, port, kToken, {});
    CHECK(asking.socket != nullptr);
    (void)greet(*asking.socket);
    send(*asking.socket,
        encodeJson(FrameType::eEndpointCreate, 8,
            {{"kind", "stream"},
                {"published", false}, {"realtime", false}}));
    CHECK(receive(*asking.socket).type == FrameType::eOk);
    const nlohmann::json dialAsk = {{"endpoint", 8},
        {"host", "anything.b32.i2p"}, {"deadline", kDialDeadlineSeconds}};
    send(*asking.socket, encodeJson(FrameType::eStreamOpen, 10, dialAsk));
    send(*asking.socket, encodeJson(FrameType::eStreamOpen, 10, dialAsk));
    const Frame dialled = receive(*asking.socket);
    CHECK(dialled.type == FrameType::eStreamReset);
    CHECK(dialled.ref == 10);
    CHECK(gateway.dials() == 1);
    CHECK(gateway.refusals() == refusedBefore);
    {
        const i2p::Keys presence = i2p::Keys::generate();
        const nlohmann::json readers = nlohmann::json::array(
            {standardToI2pBase64(toBase64(Key::generateX25519().rawPublic()))});
        const nlohmann::json withMaster = {{"kind", "raw"}, {"published", true},
            {"keys", presence.privateBase64()}, {"readers", readers}};
        send(*asking.socket, encodeJson(FrameType::eEndpointCreate, 12, withMaster));
        const Frame refused = receive(*asking.socket);
        CHECK(refused.type == FrameType::eError);
        CHECK(bodyJson(refused)["code"] == "bad-frame");
        const nlohmann::json withDelegation = {{"kind", "raw"}, {"published", true},
            {"keys", presence.issueTransient(1).privateBase64()}, {"readers", readers}};
        send(*asking.socket, encodeJson(FrameType::eEndpointCreate, 14, withDelegation));
        const Frame made = receive(*asking.socket);
        CHECK(made.type == FrameType::eOk);
        CHECK(bodyJson(made)["host"] == i2p::routingHost(presence.publicBase64()));
    }
    asking.socket->close(websocket::close_code::normal, ignored);
    asking.socket.reset();

    Dialled held = dial(io, port, kToken, {});
    CHECK(held.socket != nullptr);
    const std::string doomed = greet(*held.socket)["body"]["session"];
    send(*held.socket,
        encodeJson(FrameType::eEndpointCreate, 4,
            {{"kind", "stream"},
                {"published", true}, {"realtime", false}}));
    const Frame made = receive(*held.socket);
    CHECK(made.type == FrameType::eOk);
    CHECK(!bodyJson(made)["host"].get<std::string>().empty());
    held.socket->close(websocket::close_code::normal, ignored);
    held.socket.reset();

    const auto sweptBy = std::chrono::steady_clock::now()
        + std::chrono::seconds(settings.sessionTtlSeconds + kSweepGraceSeconds);
    while (router.localDestinations().size() != gateway.pooled()
        && std::chrono::steady_clock::now() < sweptBy) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    CHECK(router.localDestinations().size() == gateway.pooled());

    Dialled after = dial(io, port, kToken, doomed);
    CHECK(after.socket != nullptr);
    const nlohmann::json born = greet(*after.socket);
    CHECK(born["body"]["resumed"] == false);
    CHECK(born["body"]["session"] != doomed);
    CHECK(born["body"]["endpoints"].empty());
    after.socket->close(websocket::close_code::normal, ignored);
    after.socket.reset();

    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestGateway ok\n");
    return 0;
}
