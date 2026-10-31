// Bazarish project (c) 2026
#include "Restart.hpp"

#include <chrono>
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
