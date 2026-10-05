// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish {

class RateLimiter {
public:
    RateLimiter(std::size_t maxPerWindow, std::int64_t windowSeconds);

    bool allow(const std::string& caller, std::int64_t now);

private:
    struct Window {
        std::int64_t start = 0;
        std::size_t count = 0;
    };

    const std::size_t maxPerWindow_;
    const std::int64_t windowSeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, Window> windows_;
};

}  // namespace bazarish
