// Bazarish project (c) 2026
#include "EventGate.hpp"
#include "TestUtil.hpp"

#include <utility>

#include <boost/asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <thread>

namespace {

constexpr std::chrono::milliseconds kSettle{200};
constexpr std::chrono::seconds kHeld{2};

// A context that ran out of work stays stopped until it is restarted.
void runFor(boost::asio::io_context& io, const std::chrono::milliseconds span)
{
    io.restart();
    io.run_for(span);
}

}  // namespace

int main()
{
    using namespace bazarish::server;
    boost::asio::io_context io;
    EventGate gate;

    std::atomic<bool> wokenForAlice{false};
    std::atomic<bool> wokenForBob{false};
    gate.wait(io.get_executor(), "alice", "phone", [&wokenForAlice]() { wokenForAlice = true; });
    gate.wait(io.get_executor(), "bob", "phone", [&wokenForBob]() { wokenForBob = true; });
    CHECK(gate.waiting() == 2);

    runFor(io, kHeld);
    CHECK(!wokenForAlice.load());
    CHECK(!wokenForBob.load());
    CHECK(gate.waiting() == 2);

    gate.notify("alice");
    runFor(io, kSettle);
    CHECK(wokenForAlice.load());
    CHECK(!wokenForBob.load());
    CHECK(gate.waiting() == 1);

    std::atomic<bool> laptop{false};
    std::atomic<bool> phoneAgain{false};
    gate.wait(io.get_executor(), "bob", "laptop", [&laptop]() { laptop = true; });
    gate.wait(io.get_executor(), "bob", "phone", [&phoneAgain]() { phoneAgain = true; });
    runFor(io, kSettle);
    CHECK(wokenForBob.load());
    CHECK(!laptop.load());
    CHECK(!phoneAgain.load());
    CHECK(gate.waiting() == 2);
    gate.notify("bob");
    runFor(io, kSettle);
    CHECK(laptop.load());
    CHECK(phoneAgain.load());
    CHECK(gate.waiting() == 0);

    gate.notify("nobody");
    runFor(io, kSettle);

    {
        auto gone = std::make_unique<boost::asio::io_context>();
        gate.wait(gone->get_executor(), "dave", "phone", []() {});
        CHECK(gate.waiting() == 1);
        gone.reset();
    }
    CHECK(gate.waiting() == 0);
    gate.notify("dave");

    std::atomic<bool> toldEarly{false};
    gate.notify("erin");
    gate.wait(io.get_executor(), "erin", "phone", [&toldEarly]() { toldEarly = true; });
    runFor(io, kSettle);
    CHECK(toldEarly.load());
    std::printf("ok\n");
    return 0;
}
