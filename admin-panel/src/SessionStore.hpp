// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::admin {

class SessionStore {
public:
    explicit SessionStore(std::int64_t ttlSeconds = 3600);

    std::string create(std::int64_t now);

    bool valid(const std::string& token, std::int64_t now);

    void destroy(const std::string& token);

private:
    void pruneLocked(std::int64_t now);

    std::int64_t ttlSeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> tokens_;
};

}  // namespace bazarish::admin
