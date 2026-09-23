// Bazarish project (c) 2026
#include "Gateway.hpp"

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
constexpr std::size_t kDecoyLow = 1024;
constexpr std::size_t kDecoyHigh = 4096;

struct Answer {
    unsigned status = 0;
    std::string body;
    std::string contentType;
    std::string server;
};

Answer request(const int port, const std::string& method, const std::string& path,
    const std::string& token)
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

// A client socket, and what the handshake made of it.
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
    // Seconds instead of minutes, so a sweep can be watched rather than argued
    // about.
    settings.sessionTtlSeconds = 2;

    i2p::RouterConfig routerConfig;
    routerConfig.dataDir = root / "i2p";
    i2p::Router router(routerConfig);

    Gateway gateway(settings, router);
    const int port = gateway.start();
    CHECK(port > 0);

    // Everything that is not this gateway gets one answer.
    const Answer stranger = request(port, "GET", "/", {});
    CHECK(stranger.status == 404);
    CHECK(stranger.body == settings.notFoundBody);
    CHECK(stranger.server == settings.serverName);

    // The right path with no token, and with the wrong one, is that same answer
    // byte for byte. A 404 that differs when the path is right is an oracle.
    const Answer noToken = request(port, "GET", kPath, {});
    const Answer wrongToken = request(port, "GET", kPath, "not-the-token");
    const Answer deepPath = request(port, "GET", std::string(kPath) + "/more", kToken);
    CHECK(noToken.body == stranger.body);
    CHECK(noToken.status == stranger.status);
    CHECK(noToken.contentType == stranger.contentType);
    CHECK(wrongToken.body == stranger.body);
    CHECK(wrongToken.status == stranger.status);
    CHECK(deepPath.body == stranger.body);

    // A decoy: random in, random out, and the client does not say how much
    // comes back.
    const Answer decoyOne = request(port, "POST", kPath, kToken);
    const Answer decoyTwo = request(port, "POST", kPath, kToken);
    CHECK(decoyOne.status == 200);
    CHECK(decoyOne.body.size() >= kDecoyLow);
    CHECK(decoyOne.body.size() <= kDecoyHigh);
    CHECK(decoyTwo.body.size() >= kDecoyLow);
    CHECK(decoyOne.body != decoyTwo.body);
    CHECK(decoyOne.server == settings.serverName);

    asio::io_context io;

    // An upgrade without the token is refused. That it is refused with the same
    // page as everything else is what the plain requests above already prove -
    // and not every Beast version fills the response object on a handshake that
    // failed, which is a fact about the library and not about this gateway.
    const Dialled refused = dial(io, port, "wrong-token", {});
    CHECK(refused.socket == nullptr);

    // An upgrade with it opens a session and is handed a cookie.
    Dialled first = dial(io, port, kToken, {});
    CHECK(first.socket != nullptr);
    const nlohmann::json ready = greet(*first.socket);
    CHECK(ready["type"] == static_cast<int>(FrameType::eReady));
    CHECK(ready["ref"] == 2);
    CHECK(ready["body"]["version"] == kProtocolVersion);
    CHECK(ready["body"]["resumed"] == false);
    CHECK(ready["body"]["capabilities"]["routerCounters"] == true);
    CHECK(ready["body"]["capabilities"]["proxy"] == false);
    CHECK(ready["body"]["capabilities"]["offlineKeys"] == false);
    const std::string cookie = ready["body"]["session"];
    CHECK(!cookie.empty());

    // Saying hello twice on one socket is a client that lost its place.
    send(*first.socket, encodeJson(FrameType::eHello, 4, {{"version", kProtocolVersion}}));
    const Frame twice = receive(*first.socket);
    CHECK(twice.type == FrameType::eError);
    CHECK(bodyJson(twice)["code"] == "bad-frame");

    // The session outlives the socket that opened it: dropping on purpose is
    // what the client does to keep a watcher from seeing one long connection.
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

    // A cookie that names nothing is not an error: a fresh session, a fresh
    // cookie, and one field saying so.
    Dialled stale = dial(io, port, kToken, "a-cookie-from-nowhere");
    CHECK(stale.socket != nullptr);
    const nlohmann::json fresh = greet(*stale.socket);
    CHECK(fresh["body"]["resumed"] == false);
    CHECK(fresh["body"]["session"] != cookie);
    stale.socket->close(websocket::close_code::normal, ignored);
    stale.socket.reset();

    // One version, so there is nothing to negotiate.
    Dialled ancient = dial(io, port, kToken, {});
    CHECK(ancient.socket != nullptr);
    const nlohmann::json refusal = greet(*ancient.socket, kProtocolVersion + 1);
    CHECK(refusal["type"] == static_cast<int>(FrameType::eError));
    CHECK(refusal["body"]["code"] == "version");
    ancient.socket.reset();

    // A frame type that does not exist closes the socket rather than being
    // half understood.
    Dialled nonsense = dial(io, port, kToken, {});
    CHECK(nonsense.socket != nullptr);
    const Bytes garbage = {0x7F, 0x00, 0x00, 0x00, 0x01};
    send(*nonsense.socket, garbage);
    const Frame complaint = receive(*nonsense.socket);
    CHECK(complaint.type == FrameType::eError);
    CHECK(bodyJson(complaint)["code"] == "bad-frame");
    nonsense.socket.reset();

    // A session that outlives nothing is swept, and what it held goes with it.
    // The destination below is published, so the gateway is holding a thread
    // for it: a sweep that could not join one would hang here rather than fail.
    Dialled held = dial(io, port, kToken, {});
    CHECK(held.socket != nullptr);
    const std::string doomed = greet(*held.socket)["body"]["session"];
    send(*held.socket,
        encodeJson(FrameType::eEndpointCreate, 4,
            {{"kind", "stream"}, {"privacy", "minimal"}, {"tunnels", 2},
                {"published", true}, {"realtime", false}}));
    const Frame made = receive(*held.socket);
    CHECK(made.type == FrameType::eOk);
    CHECK(!bodyJson(made)["host"].get<std::string>().empty());
    held.socket->close(websocket::close_code::normal, ignored);
    held.socket.reset();

    std::this_thread::sleep_for(std::chrono::seconds(settings.sessionTtlSeconds + 1));

    // The next connection sweeps it: the cookie names nothing, and the client
    // is told so in one field rather than left to find out.
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
