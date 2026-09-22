// Bazarish project (c) 2026
#pragma once

#include <bazarish/GatewayStreamBook.hpp>

#include <bazarish/I2p.hpp>
#include <bazarish/WebSocket.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

namespace bazarish::gateway {

// One destination the gateway operates for a client. The client never sees the
// keys: it says what the destination is for and the gateway mints, builds and
// publishes it.
struct EndpointEntry {
    std::uint32_t id = 0;
    std::shared_ptr<i2p::Endpoint> endpoint;
    // What it is for. The two are exclusive: streams are dialled and accepted,
    // raw datagrams carry a call's media and nothing else.
    bool raw = false;
    bool published = false;
    bool realtime = false;
    std::string host;
    // The socket this endpoint's datagrams ride, when one is attached. A raw
    // endpoint with none has its datagrams dropped: audio that arrives late has
    // already been played past.
    http::SocketPtr socket;
    // Accepting callers, or waiting for datagrams. Both of those block, so both
    // are a thread.
    std::thread worker;
    std::atomic<bool> running{true};
    // What was last told to the client, so a push says something new.
    bool ready = false;
    int inboundTunnels = 0;
    int outboundTunnels = 0;
    int leaseSets = 0;
};

// One stream, and what it owes in both directions.
struct StreamEntry {
    std::uint32_t id = 0;
    std::uint32_t endpoint = 0;
    std::unique_ptr<i2p::Stream> stream;
    StreamBook book;
    // The socket this stream's data rides. With none it rides the main one: a
    // transfer slowed by sharing a queue is better than a transfer stopped.
    http::SocketPtr socket;
    std::thread reader;
    std::atomic<bool> running{true};
};

}  // namespace bazarish::gateway
