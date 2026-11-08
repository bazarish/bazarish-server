// Bazarish project (c) 2026
#include "Restart.hpp"

#include <bazarish/Log.hpp>

#include <pthread.h>
#include <signal.h>

#include <cerrno>
#include <chrono>
#include <stdexcept>
#include <utility>

namespace bazarish {

namespace {

constexpr std::chrono::milliseconds kResponseGrace{300};

}  // namespace

void StopGate::wait()
{
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this]() { return stopped_; });
}

bool StopGate::waitFor(const std::chrono::nanoseconds timeout)
{
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, timeout, [this]() { return stopped_; });
}

void StopGate::stop()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
    }
    cv_.notify_all();
}

bool StopGate::stopped() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return stopped_;
}

namespace {

sigset_t blockedStopSignals()
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &set, nullptr) != 0) {
        throw std::runtime_error("the stop signals could not be blocked");
    }
    return set;
}

}  // namespace

SignalWaiter::SignalWaiter(std::function<void()> onStop)
    : thread_([signals = blockedStopSignals(), onStop = std::move(onStop)]() {
        int caught = 0;
        if (sigwait(&signals, &caught) == 0) {
            onStop();
        }
    })
{
}

// A stop that came from inside leaves the waiter in sigwait: a signal of its own ends it.
SignalWaiter::~SignalWaiter()
{
    const int woken = pthread_kill(thread_.native_handle(), SIGTERM);
    if (woken != 0 && woken != ESRCH) {
        log::error("the signal waiter could not be woken: {}", woken);
    }
    thread_.join();
}

RestartSwitch::RestartSwitch(std::function<void()> stop)
    : stop_(std::move(stop))
{
    waiter_ = std::thread([this]() {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this]() { return asked_ || releasing_; });
            if (!asked_) {
                return;
            }
        }
        std::this_thread::sleep_for(kResponseGrace);
        stop_();
    });
}

RestartSwitch::~RestartSwitch()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        releasing_ = true;
    }
    cv_.notify_all();
    if (waiter_.joinable()) {
        waiter_.join();
    }
}

void RestartSwitch::request()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        asked_ = true;
    }
    cv_.notify_all();
}

bool RestartSwitch::requested() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return asked_;
}

}  // namespace bazarish
