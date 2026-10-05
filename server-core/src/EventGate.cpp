// Bazarish project (c) 2026
#include "EventGate.hpp"

#include <algorithm>

namespace bazarish::server {

void EventGate::notify(const std::string& user)
{
    std::vector<std::shared_ptr<boost::asio::steady_timer>> woken;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = waiters_.find(user);
        if (found == waiters_.end()) {
            return;
        }
        woken.swap(found->second);
        waiters_.erase(found);
    }
    for (const std::shared_ptr<boost::asio::steady_timer>& timer : woken) {
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
    std::erase(found->second, timer);
    if (found->second.empty()) {
        waiters_.erase(found);
    }
}

std::size_t EventGate::waiting() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::size_t total = 0;
    for (const auto& entry : waiters_) {
        total += entry.second.size();
    }
    return total;
}

}  // namespace bazarish::server
