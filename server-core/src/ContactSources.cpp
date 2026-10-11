// Bazarish project (c) 2026
#include "ContactSources.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>

namespace bazarish::server {

ContactSources::ContactSources(const std::int64_t memorySeconds)
    : memorySeconds_(memorySeconds)
{
}

bool ContactSources::admit(const std::string& source, const std::int64_t now)
{
    if (source.empty()) {
        return true;
    }
    const std::string key = toHex(sha256(Bytes(source.begin(), source.end())));
    const std::lock_guard<std::mutex> lock(mutex_);
    if (now - sweptAt_ >= kSecondsPerHour) {
        sweep(now);
    }
    const auto found = seen_.find(key);
    if (found != seen_.end() && now - found->second < memorySeconds_) {
        return false;
    }
    seen_[key] = now;
    return true;
}

void ContactSources::sweep(const std::int64_t now)
{
    for (auto at = seen_.begin(); at != seen_.end();) {
        if (now - at->second >= memorySeconds_) {
            at = seen_.erase(at);
        } else {
            ++at;
        }
    }
    sweptAt_ = now;
}

}  // namespace bazarish::server
