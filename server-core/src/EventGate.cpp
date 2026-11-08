// Bazarish project (c) 2026
#include "EventGate.hpp"

#include <algorithm>

namespace bazarish::server {

void EventGate::notify(const std::string& user)
{
    std::vector<std::weak_ptr<boost::asio::steady_timer>> woken;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = waiters_.find(user);
        if (found == waiters_.end()) {
            early_.insert(user);
            return;
        }
        woken.swap(found->second);
        waiters_.erase(found);
    }
    for (const std::weak_ptr<boost::asio::steady_timer>& held : woken) {
        if (const std::shared_ptr<boost::asio::steady_timer> timer = held.lock()) {
            timer->cancel();
        }
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
    std::erase_if(found->second, [&timer](const std::weak_ptr<boost::asio::steady_timer>& held) {
        const std::shared_ptr<boost::asio::steady_timer> alive = held.lock();
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
            [](const std::weak_ptr<boost::asio::steady_timer>& held) { return !held.expired(); }));
    }
    return total;
}

}  // namespace bazarish::server
