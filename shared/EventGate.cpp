// Bazarish project (c) 2026
#include "EventGate.hpp"

#include <algorithm>

namespace bazarish::server {

void EventGate::notify(const std::string& user)
{
    std::vector<Waiter> woken;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = waiters_.find(user);
        if (found == waiters_.end()) {
            if (missed_ == Missed::eKept) {
                early_.insert(user);
            }
            return;
        }
        woken.swap(found->second);
        waiters_.erase(found);
    }
    for (const Waiter& held : woken) {
        if (const std::shared_ptr<boost::asio::steady_timer> timer = held.timer.lock()) {
            timer->cancel();
        }
    }
}

void EventGate::wakeWaiting(const std::string& user)
{
    std::vector<Waiter> woken;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = waiters_.find(user);
        if (found == waiters_.end()) {
            return;
        }
        woken.swap(found->second);
        waiters_.erase(found);
    }
    for (const Waiter& held : woken) {
        if (const std::shared_ptr<boost::asio::steady_timer> timer = held.timer.lock()) {
            timer->cancel();
        }
    }
}

void EventGate::release(const std::string& user, const std::string& client)
{
    std::vector<std::shared_ptr<boost::asio::steady_timer>> released;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = waiters_.find(user);
        if (found == waiters_.end()) {
            return;
        }
        std::erase_if(found->second, [&client, &released](const Waiter& waiter) {
            if (waiter.client != client) {
                return false;
            }
            if (const std::shared_ptr<boost::asio::steady_timer> alive = waiter.timer.lock()) {
                released.push_back(alive);
            }
            return true;
        });
        if (found->second.empty()) {
            waiters_.erase(found);
        }
    }
    for (const std::shared_ptr<boost::asio::steady_timer>& timer : released) {
        timer->cancel();
    }
}

void EventGate::forget(
    const std::string& user, const std::shared_ptr<boost::asio::steady_timer>& timer)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = waiters_.find(user);
    if (found == waiters_.end()) {
        return;
    }
    std::erase_if(found->second, [&timer](const Waiter& held) {
        const std::shared_ptr<boost::asio::steady_timer> alive = held.timer.lock();
        return !alive || alive == timer;
    });
    if (found->second.empty()) {
        waiters_.erase(found);
    }
}

std::size_t EventGate::waiting() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::size_t total = 0;
    for (const auto& entry : waiters_) {
        total += static_cast<std::size_t>(std::count_if(entry.second.begin(), entry.second.end(),
            [](const Waiter& held) { return !held.timer.expired(); }));
    }
    return total;
}

}  // namespace bazarish::server
