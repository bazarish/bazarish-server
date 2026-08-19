// Bazarish project (c) 2026
#include "SessionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>

namespace bazarish::server {

namespace {
constexpr std::int64_t kSweepIntervalSeconds = 300;
constexpr std::size_t kSessionIdBytes = 16;
}  // namespace

std::string SessionStore::open(const std::string& user, const Bytes& secret, const std::int64_t now,
    std::int64_t* const outExpiresUnix)
{
    const std::string id = toHex(randomBytes(kSessionIdBytes));
    // A random lifetime inside the window: a fixed one would have every client
    // renew on the same schedule, and the point of a short-lived key is that a
    // leaked one is worth little.
    const std::int64_t span
        = auth::kSessionMaxLifetimeSeconds - auth::kSessionMinLifetimeSeconds;
    const std::int64_t jitter
        = span > 0 ? static_cast<std::int64_t>(randomBytes(2)[0] << 8 | randomBytes(1)[0]) % span
                   : 0;
    Session session;
    session.user = user;
    session.key = auth::deriveSessionKey(secret, id);
    session.expiresUnix = now + auth::kSessionMinLifetimeSeconds + jitter;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        sessions_[id] = session;
    }
    if (outExpiresUnix != nullptr) {
        *outExpiresUnix = session.expiresUnix;
    }
    return id;
}

std::optional<SessionStore::Session> SessionStore::find(
    const std::string& id, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (now - lastSweep_ > kSweepIntervalSeconds) {
        lastSweep_ = now;
        std::erase_if(sessions_,
            [now](const auto& entry) { return entry.second.expiresUnix <= now; });
    }
    const auto found = sessions_.find(id);
    if (found == sessions_.end()) {
        return std::nullopt;
    }
    if (found->second.expiresUnix <= now) {
        sessions_.erase(found);
        return std::nullopt;
    }
    return found->second;
}

bool SessionStore::acceptSeq(const std::string& id, const std::uint64_t seq, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = sessions_.find(id);
    if (found == sessions_.end() || found->second.expiresUnix <= now) {
        return false;
    }
    if (seq <= found->second.lastSeq) {
        return false;  // replayed or reordered: neither is acceptable
    }
    found->second.lastSeq = seq;
    return true;
}

void SessionStore::drop(const std::string& id)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    sessions_.erase(id);
}

std::size_t SessionStore::size() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

}  // namespace bazarish::server
