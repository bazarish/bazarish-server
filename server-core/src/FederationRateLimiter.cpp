// Bazarish project (c) 2026
#include "FederationRateLimiter.hpp"

#include <utility>

namespace bazarish::server {

FederationRateLimiter::FederationRateLimiter(
    const std::size_t maxPerWindow, const std::int64_t windowSeconds)
    : maxPerWindow_(maxPerWindow)
    , windowSeconds_(windowSeconds)
{
}

bool FederationRateLimiter::allow(const std::string& peerDest, const std::int64_t now)
{
    if (peerDest.empty()) {
        return true;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    // Opportunistically drop fully-expired windows so a churn of peer
    // destinations cannot grow the map without bound.
    if (windows_.size() > 4096) {
        for (auto it = windows_.begin(); it != windows_.end();) {
            if (now - it->second.start >= windowSeconds_) {
                it = windows_.erase(it);
            } else {
                ++it;
            }
        }
    }
    Window& window = windows_[peerDest];
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

}  // namespace bazarish::server
