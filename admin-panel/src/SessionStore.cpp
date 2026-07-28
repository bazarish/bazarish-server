// Bazarish project (c) 2026
#include "SessionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

namespace bazarish::admin {

SessionStore::SessionStore(const std::int64_t ttlSeconds)
    : ttlSeconds_(ttlSeconds)
{
}

void SessionStore::pruneLocked(const std::int64_t now)
{
    for (auto it = tokens_.begin(); it != tokens_.end();) {
        if (it->second <= now) {
            it = tokens_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string SessionStore::create(const std::int64_t now)
{
    // base64url: no '+', '/' or '=' so the token drops into a cookie unencoded.
    const std::string token = toBase64Url(randomBytes(24));
    const std::lock_guard<std::mutex> lock(mutex_);
    pruneLocked(now);
    tokens_[token] = now + ttlSeconds_;
    return token;
}

bool SessionStore::valid(const std::string& token, const std::int64_t now)
{
    if (token.empty()) {
        return false;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto it = tokens_.find(token);
    return it != tokens_.end() && it->second > now;
}

void SessionStore::destroy(const std::string& token)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    tokens_.erase(token);
}

}  // namespace bazarish::admin
