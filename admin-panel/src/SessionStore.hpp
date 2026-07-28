// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::admin {

// In-memory admin sessions. A successful login mints a random opaque token stored
// against an expiry; the cookie carries only the token. Every session belongs to
// the configured admin by construction (login already enforced it), so a valid
// token is sufficient authorization. Single-process, so in-memory state needs no
// external store.
class SessionStore {
public:
    explicit SessionStore(std::int64_t ttlSeconds = 3600);

    // Mints a new session token valid for the configured TTL from now.
    std::string create(std::int64_t now);

    // True if the token is known and unexpired.
    bool valid(const std::string& token, std::int64_t now);

    // Drops a session (logout). No-op if unknown.
    void destroy(const std::string& token);

private:
    void pruneLocked(std::int64_t now);

    std::int64_t ttlSeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> tokens_;  // token -> expiry
};

}  // namespace bazarish::admin
