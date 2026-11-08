// Bazarish project (c) 2026
#include "EventGate.hpp"

#include <utility>

#include <boost/asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <thread>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition);            \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

int main()
{
    using namespace bazarish::server;
    boost::asio::io_context io;
    EventGate gate;

    std::atomic<bool> wokenForAlice{false};
    std::atomic<bool> wokenForBob{false};
    gate.wait(io.get_executor(), "alice", std::chrono::seconds(30),
        [&wokenForAlice]() { wokenForAlice = true; });
    gate.wait(io.get_executor(), "bob", std::chrono::seconds(30),
        [&wokenForBob]() { wokenForBob = true; });
    CHECK(gate.waiting() == 2);

    gate.notify("alice");
    io.run_for(std::chrono::milliseconds(200));
    CHECK(wokenForAlice.load());
    CHECK(!wokenForBob.load());
    CHECK(gate.waiting() == 1);

    std::atomic<bool> expired{false};
    gate.wait(io.get_executor(), "carol", std::chrono::seconds(0),
        [&expired]() { expired = true; });
    io.run_for(std::chrono::milliseconds(200));
    CHECK(expired.load());

    gate.notify("nobody");
    io.run_for(std::chrono::milliseconds(50));

    {
        auto gone = std::make_unique<boost::asio::io_context>();
        gate.wait(gone->get_executor(), "dave", std::chrono::seconds(30), []() {});
        CHECK(gate.waiting() == 2);
        gone.reset();
    }
    CHECK(gate.waiting() == 1);
    gate.notify("dave");

    std::atomic<bool> toldEarly{false};
    gate.notify("erin");
    gate.wait(io.get_executor(), "erin", std::chrono::seconds(30),
        [&toldEarly]() { toldEarly = true; });
    io.run_for(std::chrono::milliseconds(200));
    CHECK(toldEarly.load());
    std::printf("ok\n");
    return 0;
}
