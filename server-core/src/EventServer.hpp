// Bazarish project (c) 2026
#pragma once

#include "EventGate.hpp"
#include "Storage.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>

namespace bazarish::server {

// The long-poll face of the messaging server, served on its own asio loop with
// C++20 coroutines: a request that has nothing to report is suspended on the
// event gate instead of holding a thread, so hundreds of clients can keep a
// request open on a handful of threads. Everything else stays on the ordinary
// (thread-per-request) HTTP server; only waiting needs this.
//
// One route: GET /v1/messaging/events?wait=<seconds>&client=<id>. It answers at
// once when the caller has pending items, otherwise when something arrives for
// them, otherwise when the wait runs out - and the answer is the same shape
// either way, so the client's next step never depends on which happened.
class EventServer {
public:
    struct Options {
        std::string host = "127.0.0.1";
        int port = 0;
        // Longest a client may ask to be kept waiting. Anything above is clamped:
        // an idle I2P stream that lives too long is torn down under us.
        int maxWaitSeconds = 30;
        int threads = 2;
    };

    EventServer(Storage& storage, EventGate& gate, Options options);
    ~EventServer();

    EventServer(const EventServer&) = delete;
    EventServer& operator=(const EventServer&) = delete;

    // Binds and starts serving; returns the port actually bound (useful with 0).
    int start();
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::server
