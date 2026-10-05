// Bazarish project (c) 2026
#include "RateLimiter.hpp"

namespace bazarish {

constexpr std::size_t kSweepAbove = 4096;

RateLimiter::RateLimiter(const std::size_t maxPerWindow, const std::int64_t windowSeconds)
    : maxPerWindow_(maxPerWindow)
    , windowSeconds_(windowSeconds)
{
}

bool RateLimiter::allow(const std::string& caller, const std::int64_t now)
{
    if (caller.empty()) {
        return true;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    if (windows_.size() > kSweepAbove) {
        for (auto at = windows_.begin(); at != windows_.end();) {
            if (now - at->second.start >= windowSeconds_) {
                at = windows_.erase(at);
            } else {
                ++at;
            }
        }
    }
    Window& window = windows_[caller];
    if (now - window.start >= windowSeconds_) {
        window.start = now;
        window.count = 0;
    }
    if (window.count >= maxPerWindow_) {
        return false;
    }
    ++window.count;
    return true;
}

}  // namespace bazarish
