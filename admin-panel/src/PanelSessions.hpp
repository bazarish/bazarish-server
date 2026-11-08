// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace bazarish::admin {

class PanelSessions {
public:
    explicit PanelSessions(std::int64_t ttlSeconds = 3600);

    std::string create(const std::string& fingerprint, std::int64_t now);

    // The operator a live session belongs to; none for an unknown or expired token.
    std::optional<std::string> holder(const std::string& token, std::int64_t now);

    void destroy(const std::string& token);

private:
    void pruneLocked(std::int64_t now);

    std::int64_t ttlSeconds_;
    std::mutex mutex_;
    struct Held {
        std::string fingerprint;
        std::int64_t expires = 0;
    };
    std::unordered_map<std::string, Held> tokens_;
};

}  // namespace bazarish::admin
