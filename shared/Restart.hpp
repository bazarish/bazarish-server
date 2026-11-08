// Bazarish project (c) 2026
#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace bazarish {

inline constexpr int kRestartExitCode = 90;

class StopGate {
public:
    void wait();
    bool waitFor(std::chrono::nanoseconds timeout);
    void stop();
    bool stopped() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool stopped_ = false;
};

// SIGINT and SIGTERM, taken from every thread started after it, reach onStop on a thread of its
// own: a handler may not touch a mutex or a condition variable.
class SignalWaiter {
public:
    explicit SignalWaiter(std::function<void()> onStop);
    ~SignalWaiter();

    SignalWaiter(const SignalWaiter&) = delete;
    SignalWaiter& operator=(const SignalWaiter&) = delete;

private:
    std::thread thread_;
};

class RestartSwitch {
public:
    explicit RestartSwitch(std::function<void()> stop);
    ~RestartSwitch();

    RestartSwitch(const RestartSwitch&) = delete;
    RestartSwitch& operator=(const RestartSwitch&) = delete;

    void request();

    bool requested() const;

private:
    std::function<void()> stop_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool asked_ = false;
    bool releasing_ = false;
    std::thread waiter_;
};

}  // namespace bazarish
