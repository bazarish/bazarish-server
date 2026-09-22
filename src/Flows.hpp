// Bazarish project (c) 2026
#pragma once

#include <bazarish/GatewayStreamBook.hpp>

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/WebSocket.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

namespace bazarish::gateway {

class Session;

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
//
// Either it rides I2P, or it is one half of a pair: when both ends of a dial
// are this gateway's own, there is nothing for the network to carry and the two
// clients are joined inside the process. The gateway already knows which
// destination is which - it minted both - so routing their bytes out through
// two tunnel sets and back would be work done to arrive where it started.
struct StreamEntry {
    std::uint32_t id = 0;
    std::uint32_t endpoint = 0;
    // Set for a stream over I2P, null for one half of a local pair.
    std::unique_ptr<i2p::Stream> stream;
    // The other half, and whose session it is.
    std::weak_ptr<StreamEntry> peer;
    std::weak_ptr<Session> peerSession;
    // Bytes meant for THIS side's client that its window has no room for yet.
    // Bounded by the other side's window, because nothing is credited to it
    // until what it sent has left.
    Bytes waiting;
    // The other side has finished sending; this one is told so once what is
    // waiting has actually gone.
    bool endAfterDrain = false;
    StreamBook book;
    // The socket this stream's data rides. With none it rides the main one: a
    // transfer slowed by sharing a queue is better than a transfer stopped.
    http::SocketPtr socket;
    std::thread reader;
    std::atomic<bool> running{true};
};

}  // namespace bazarish::gateway
