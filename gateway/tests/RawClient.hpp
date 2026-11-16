// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>
#include <bazarish/GatewayChannel.hpp>
#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/SecretBytes.hpp>
#include <bazarish/TrafficShape.hpp>

#include "TestUtil.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#include <deque>
#include <memory>
#include <optional>
#include <string>

namespace bazarish::gateway::raw {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = boost::beast::websocket;
using asio::ip::tcp;

struct Seat {
    SecretBytes key;
    std::deque<Bytes> tickets;
};

struct Dialled {
    std::unique_ptr<websocket::stream<tcp::socket>> socket;
    std::shared_ptr<Records> records;
    Seat* seat = nullptr;
};

inline Bytes readRaw(websocket::stream<tcp::socket>& socket)
{
    beast::flat_buffer buffer;
    socket.read(buffer);
    const auto* const begin = static_cast<const unsigned char*>(buffer.data().data());
    return Bytes(begin, begin + buffer.size());
}

inline void writeRaw(websocket::stream<tcp::socket>& socket, const Bytes& message)
{
    socket.write(asio::buffer(message.data(), message.size()));
}

inline Dialled dial(asio::io_context& io, const int port, const std::string& path,
    const std::string& fingerprint, Seat& seat, const bool join)
{
    tcp::socket raw(io);
    raw.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"),
        static_cast<unsigned short>(port)));
    auto stream = std::make_unique<websocket::stream<tcp::socket>>(std::move(raw));
    stream->handshake("127.0.0.1", path);
    stream->binary(true);
    Dialled out;
    const Cover cover(fingerprint);
    const std::optional<SecretBytes> card = cover.open(readRaw(*stream));
    if (!card.has_value()) {
        return out;
    }
    const Key sealing = cardSealingKey(unpadded(card->bytes()), fingerprint);
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

inline void send(Dialled& dialled, const Bytes& frame)
{
    shape::SystemRandom random;
    writeRaw(*dialled.socket, dialled.records->seal(padRecord(frame, 0, random)));
}

inline Frame receive(Dialled& dialled)
{
    while (true) {
        const Bytes record = readRaw(*dialled.socket);
        CHECK(record.size() >= static_cast<std::size_t>(kRecordPadFloor) + kAeadTagBytes);
        const std::optional<Bytes> opened = dialled.records->open(record);
        CHECK(opened.has_value());
        const std::optional<RecordBody> carried = unpadRecord(*opened);
        CHECK(carried.has_value());
        const Frame frame = decode(carried->frame);
        if (frame.type != FrameType::eTickets) {
            return frame;
        }
        const nlohmann::json body = bodyJson(frame);
        for (const nlohmann::json& ticket : body.at("tickets")) {
            dialled.seat->tickets.push_back(fromBase64(ticket.get<std::string>()));
        }
    }
}

}  // namespace bazarish::gateway::raw
