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

struct EndpointEntry {
    std::uint32_t id = 0;
    std::shared_ptr<i2p::Endpoint> endpoint;
    bool raw = false;
    bool published = false;
    bool realtime = false;
    std::string host;
    http::SocketPtr socket;
    std::thread worker;
    std::atomic<bool> running{true};
    bool ready = false;
    int inboundTunnels = 0;
    int outboundTunnels = 0;
    int leaseSets = 0;
};

struct StreamEntry {
    std::uint32_t id = 0;
    std::uint32_t endpoint = 0;
    std::unique_ptr<i2p::Stream> stream;
    std::weak_ptr<StreamEntry> peer;
    std::weak_ptr<Session> peerSession;
    Bytes waiting;
    bool endAfterDrain = false;
    StreamBook book;
    http::SocketPtr socket;
    std::thread reader;
    std::atomic<bool> running{true};
};

}  // namespace bazarish::gateway
