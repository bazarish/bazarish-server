// Bazarish project (c) 2026
#include "EventGate.hpp"

#include <utility>

#include <boost/asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
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

    // A waiter is woken by a delivery for its own user, long before its timeout.
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
    CHECK(!wokenForBob.load());   // a delivery for one user wakes only that user
    CHECK(gate.waiting() == 1);

    // A waiter nobody wakes still finishes, so a forgotten client is answered.
    std::atomic<bool> expired{false};
    gate.wait(io.get_executor(), "carol", std::chrono::seconds(0),
        [&expired]() { expired = true; });
    io.run_for(std::chrono::milliseconds(200));
    CHECK(expired.load());

    // Notifying a user nobody waits on is a no-op, not a crash.
    gate.notify("nobody");
    io.run_for(std::chrono::milliseconds(50));
    std::printf("ok\n");
    return 0;
}
