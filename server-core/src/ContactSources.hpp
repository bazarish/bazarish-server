// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::server {

class ContactSources {
public:
    explicit ContactSources(std::int64_t memorySeconds);

    bool admit(const std::string& source, std::int64_t now);

private:
    void sweep(std::int64_t now);

    const std::int64_t memorySeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> seen_;
    std::int64_t sweptAt_ = 0;
};

}  // namespace bazarish::server
