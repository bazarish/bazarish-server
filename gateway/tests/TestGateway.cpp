// Bazarish project (c) 2026
#include "Gateway.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/GatewayChannel.hpp>
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
#include <deque>
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
    const auth::Headers& signed_ = {})
{
    asio::io_context io;
    tcp::socket socket(io);
    socket.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"),
        static_cast<unsigned short>(port)));
    bhttp::request<bhttp::string_body> out{bhttp::string_to_verb(method), path, 11};
    out.set(bhttp::field::host, "127.0.0.1");
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

struct Seat {
    Bytes key;
    std::deque<Bytes> tickets;
};

struct Dialled {
    std::unique_ptr<websocket::stream<tcp::socket>> socket;
    std::shared_ptr<Records> records;
    Seat* seat = nullptr;
};

Bytes readRaw(websocket::stream<tcp::socket>& socket)
{
    beast::flat_buffer buffer;
    socket.read(buffer);
    const auto* const begin = static_cast<const unsigned char*>(buffer.data().data());
    return Bytes(begin, begin + buffer.size());
}

void writeRaw(websocket::stream<tcp::socket>& socket, const Bytes& message)
{
    socket.write(asio::buffer(message.data(), message.size()));
}

Dialled dial(asio::io_context& io, const int port, const std::string& fingerprint, Seat& seat,
    const bool join)
{
    tcp::socket raw(io);
    raw.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"),
        static_cast<unsigned short>(port)));
    auto stream = std::make_unique<websocket::stream<tcp::socket>>(std::move(raw));
    stream->handshake("127.0.0.1", kPath);
    stream->binary(true);
    Dialled out;
    const Cover cover(fingerprint);
    const std::optional<Bytes> card = cover.open(readRaw(*stream));
    if (!card.has_value()) {
        return out;
    }
    const Key sealing = cardSealingKey(unpadded(*card), fingerprint);
    if (join && !seat.tickets.empty()) {
        const Bytes ticket = seat.tickets.front();
        seat.tickets.pop_front();
        const std::shared_ptr<Records> joining
            = std::make_shared<Records>(seat.key, ticket, Side::eClient);
        writeRaw(*stream, makeJoin(ticket, *joining));
        const std::optional<Bytes> answer = joining->open(readRaw(*stream));
        if (answer.has_value() && isJoined(*answer)) {
            out.records = joining;
        }
    }
    if (out.records == nullptr) {
        const Hello hello = makeHello(cover, sealing);
        writeRaw(*stream, hello.message);
        const std::optional<Welcome> welcome
            = openWelcome(cover, readRaw(*stream), hello.ephemeral, fingerprint);
        CHECK(welcome.has_value());
        seat.key = welcome->sessionKey;
        seat.tickets.assign(welcome->tickets.begin(), welcome->tickets.end());
        out.records = std::make_shared<Records>(welcome->sessionKey, welcome->salt, Side::eClient);
    }
    out.socket = std::move(stream);
    out.seat = &seat;
    return out;
}

void send(Dialled& dialled, const Bytes& frame)
{
    writeRaw(*dialled.socket, dialled.records->seal(frame));
}

Frame receive(Dialled& dialled)
{
    while (true) {
        const std::optional<Bytes> opened = dialled.records->open(readRaw(*dialled.socket));
        CHECK(opened.has_value());
        const Frame frame = decode(*opened);
        if (frame.type != FrameType::eTickets) {
            return frame;
        }
        const nlohmann::json body = bodyJson(frame);
        for (const nlohmann::json& ticket : body.at("tickets")) {
            dialled.seat->tickets.push_back(fromBase64(ticket.get<std::string>()));
        }
    }
}

nlohmann::json greet(Dialled& dialled, const int version = kProtocolVersion)
{
    send(dialled, encodeJson(FrameType::eHello, 2, {{"version", version}}));
    const Frame answer = receive(dialled);
    return {{"type", static_cast<int>(answer.type)}, {"ref", answer.ref},
        {"body", bodyJson(answer)}};
}

}  // namespace

int main()
{
    const std::filesystem::path root
        = testutil::freshDir("gateway-test");
    std::filesystem::create_directories(root);

    Settings settings;
    settings.listenHost = "127.0.0.1";
    settings.listenPort = 0;
    settings.basePath = kPath;
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

    const Answer deepPath = request(port, "GET", std::string(kPath) + "/more");
    CHECK(deepPath.body == stranger.body);
    CHECK(deepPath.status == stranger.status);
    CHECK(deepPath.contentType == stranger.contentType);

    CHECK(request(port, "GET", std::string(kPath) + kHealthPath).body == stranger.body);

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

    const Answer decoyOne = request(port, "POST", kPath);
    const Answer decoyTwo = request(port, "POST", kPath);
    CHECK(decoyOne.status == 200);
    CHECK(decoyOne.body.size() >= kDecoyLow);
    CHECK(decoyOne.body.size() <= kDecoyHigh);
    CHECK(decoyTwo.body.size() >= kDecoyLow);
    CHECK(decoyOne.body != decoyTwo.body);
    CHECK(decoyOne.server == settings.serverName);

    asio::io_context io;

    Seat nobody;
    const Dialled refused = dial(io, port, Identity::generate().fingerprint(), nobody, false);
    CHECK(refused.socket == nullptr);

    const std::string fingerprint = gateway.fingerprint();
    Seat seat;
    Dialled first = dial(io, port, fingerprint, seat, false);
    CHECK(first.socket != nullptr);
    CHECK(seat.tickets.size() == kTicketsHeld);
    const nlohmann::json ready = greet(first);
    CHECK(ready["type"] == static_cast<int>(FrameType::eReady));
    CHECK(ready["ref"] == 2);
    CHECK(ready["body"]["version"] == kProtocolVersion);
    CHECK(ready["body"]["resumed"] == false);
    CHECK(ready["body"]["capabilities"]["routerCounters"] == false);
    CHECK(ready["body"]["capabilities"]["proxy"] == false);
    CHECK(ready["body"]["capabilities"]["offlineKeys"] == false);
    CHECK(!ready["body"].contains("session"));

    send(first, encodeJson(FrameType::eHello, 4, {{"version", kProtocolVersion}}));
    const Frame twice = receive(first);
    CHECK(twice.type == FrameType::eError);
    CHECK(bodyJson(twice)["code"] == "bad-frame");

    boost::system::error_code ignored;
    first.socket->close(websocket::close_code::normal, ignored);
    first.socket.reset();

    const Bytes sessionKey = seat.key;
    Dialled again = dial(io, port, fingerprint, seat, true);
    CHECK(again.socket != nullptr);
    CHECK(seat.key == sessionKey);
    const nlohmann::json resumed = greet(again);
    CHECK(resumed["body"]["resumed"] == true);
    CHECK(seat.tickets.size() == kTicketsHeld);
    again.socket->close(websocket::close_code::normal, ignored);
    again.socket.reset();

    Seat forged{randomBytes(kSessionKeyBytes), {randomBytes(kTicketBytes)}};
    Dialled stale = dial(io, port, fingerprint, forged, true);
    CHECK(stale.socket != nullptr);
    CHECK(forged.key != sessionKey);
    const nlohmann::json fresh = greet(stale);
    CHECK(fresh["body"]["resumed"] == false);
    stale.socket->close(websocket::close_code::normal, ignored);
    stale.socket.reset();

    Seat older;
    Dialled ancient = dial(io, port, fingerprint, older, false);
    CHECK(ancient.socket != nullptr);
    const nlohmann::json refusal = greet(ancient, kProtocolVersion + 1);
    CHECK(refusal["type"] == static_cast<int>(FrameType::eError));
    CHECK(refusal["body"]["code"] == "version");
    ancient.socket.reset();

    Seat garbled;
    Dialled nonsense = dial(io, port, fingerprint, garbled, false);
    CHECK(nonsense.socket != nullptr);
    const Bytes garbage = {0x7F, 0x00, 0x00, 0x00, 0x01};
    send(nonsense, garbage);
    const Frame complaint = receive(nonsense);
    CHECK(complaint.type == FrameType::eError);
    CHECK(bodyJson(complaint)["code"] == "bad-frame");
    nonsense.socket.reset();

    Seat twice2;
    Dialled twiceOver = dial(io, port, fingerprint, twice2, false);
    CHECK(twiceOver.socket != nullptr);
    (void)greet(twiceOver);

    std::set<std::string> warm;
    for (const i2p::LocalDestination& destination : router.localDestinations()) {
        warm.insert(destination.host);
    }
    CHECK(warm.size() == gateway.pooled());
    const nlohmann::json ask = {{"kind", "stream"},
        {"published", false}, {"realtime", false}};
    send(twiceOver, encodeJson(FrameType::eEndpointCreate, 6, ask));
    const Frame once = receive(twiceOver);
    CHECK(once.type == FrameType::eOk);
    CHECK(warm.count(bodyJson(once)["host"].get<std::string>()) == 1);
    CHECK(router.localDestinations().size() == gateway.pooled() + 1);
    send(twiceOver, encodeJson(FrameType::eEndpointCreate, 6, ask));
    const Frame repeat = receive(twiceOver);
    CHECK(repeat.type == FrameType::eOk);
    CHECK(bodyJson(repeat)["host"] == bodyJson(once)["host"]);
    const std::size_t pooledBefore = gateway.pooled();
    const nlohmann::json watching = {{"kind", "raw"}, {"published", true}, {"realtime", false},
        {"readerKey", standardToI2pBase64(toBase64(Key::generateX25519().rawPrivate()))}};
    send(twiceOver, encodeJson(FrameType::eEndpointCreate, 16, watching));
    const Frame watcher = receive(twiceOver);
    CHECK(watcher.type == FrameType::eOk);
    CHECK(warm.count(bodyJson(watcher)["host"].get<std::string>()) == 1);
    CHECK(gateway.pooled() == pooledBefore);
    twiceOver.socket->close(websocket::close_code::normal, ignored);
    twiceOver.socket.reset();

    const std::size_t refusedBefore = gateway.refusals();
    Seat askingSeat;
    Dialled asking = dial(io, port, fingerprint, askingSeat, false);
    CHECK(asking.socket != nullptr);
    (void)greet(asking);
    send(asking,
        encodeJson(FrameType::eEndpointCreate, 8,
            {{"kind", "stream"},
                {"published", false}, {"realtime", false}}));
    CHECK(receive(asking).type == FrameType::eOk);
    const nlohmann::json dialAsk = {{"endpoint", 8},
        {"host", "anything.b32.i2p"}, {"deadline", kDialDeadlineSeconds}};
    send(asking, encodeJson(FrameType::eStreamOpen, 10, dialAsk));
    send(asking, encodeJson(FrameType::eStreamOpen, 10, dialAsk));
    const Frame dialled = receive(asking);
    CHECK(dialled.type == FrameType::eStreamReset);
    CHECK(dialled.ref == 10);
    CHECK(gateway.dials() == 1);
    CHECK(gateway.refusals() == refusedBefore);
    {
        constexpr std::uint32_t kTooLongRef = 18;
        const nlohmann::json tooLong = {{"endpoint", 8}, {"host", "anything.b32.i2p"},
            {"deadline", kMaxDialDeadline.count() + 1}};
        send(asking, encodeJson(FrameType::eStreamOpen, kTooLongRef, tooLong));
        const Frame refusedLong = receive(asking);
        CHECK(refusedLong.type == FrameType::eError);
        CHECK(refusedLong.ref == kTooLongRef);
        CHECK(bodyJson(refusedLong)["code"] == "bad-frame");
        CHECK(gateway.dials() == 1);
    }
    {
        const i2p::Keys presence = i2p::Keys::generate();
        const nlohmann::json readers = nlohmann::json::array(
            {standardToI2pBase64(toBase64(Key::generateX25519().rawPublic()))});
        const nlohmann::json withMaster = {{"kind", "raw"}, {"published", true},
            {"keys", presence.privateBase64()}, {"readers", readers}};
        send(asking, encodeJson(FrameType::eEndpointCreate, 12, withMaster));
        const Frame refused = receive(asking);
        CHECK(refused.type == FrameType::eError);
        CHECK(bodyJson(refused)["code"] == "bad-frame");
        const nlohmann::json withDelegation = {{"kind", "raw"}, {"published", true},
            {"keys", presence.issueTransient(1).privateBase64()}, {"readers", readers}};
        send(asking, encodeJson(FrameType::eEndpointCreate, 14, withDelegation));
        const Frame made = receive(asking);
        CHECK(made.type == FrameType::eOk);
        CHECK(bodyJson(made)["host"] == i2p::routingHost(presence.publicBase64()));
    }
    asking.socket->close(websocket::close_code::normal, ignored);
    asking.socket.reset();

    Seat heldSeat;
    Dialled held = dial(io, port, fingerprint, heldSeat, false);
    CHECK(held.socket != nullptr);
    (void)greet(held);
    Seat doomed = heldSeat;
    send(held,
        encodeJson(FrameType::eEndpointCreate, 4,
            {{"kind", "stream"},
                {"published", true}, {"realtime", false}}));
    const Frame made = receive(held);
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

    const Bytes doomedKey = doomed.key;
    Dialled after = dial(io, port, fingerprint, doomed, true);
    CHECK(after.socket != nullptr);
    CHECK(doomed.key != doomedKey);
    const nlohmann::json born = greet(after);
    CHECK(born["body"]["resumed"] == false);
    CHECK(born["body"]["endpoints"].empty());
    after.socket->close(websocket::close_code::normal, ignored);
    after.socket.reset();

    gateway.stop();
    std::filesystem::remove_all(root);
    std::printf("TestGateway ok\n");
    return 0;
}
