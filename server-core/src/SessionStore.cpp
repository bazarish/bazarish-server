// Bazarish project (c) 2026
#include "SessionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>

#include <climits>
#include <stdexcept>

namespace bazarish::server {

namespace {
constexpr std::int64_t kSweepIntervalSeconds = 300;
constexpr std::size_t kSessionIdChars = 32;
// How far ahead handles are accepted. A client runs two connections at once, so
// requests arrive out of order; this is the width of that reordering, not a
// replay window (the sequence check below is what stops replays).
constexpr std::uint64_t kHandleWindow = 64;
// Bytes drawn for the lifetime jitter. Two: the window is an hour wide and the
// point is that clients do not all renew at once, not unpredictability.
constexpr std::size_t kJitterBytes = 2;
}  // namespace

std::string SessionStore::open(const std::string& user, const Bytes& secret, const std::int64_t now,
    std::int64_t* const outExpiresUnix)
{
    // Derived from the secret, not drawn at random: it fixes the MAC key together
    // with the secret, and both sides have to arrive at the same one without it
    // ever travelling.
    const std::string id = toHex(sha256(secret)).substr(0, kSessionIdChars);
    // A random lifetime inside the window: a fixed one would have every client
    // renew on the same schedule, and the point of a short-lived key is that a
    // leaked one is worth little.
    const std::int64_t span
        = auth::kSessionMaxLifetimeSeconds - auth::kSessionMinLifetimeSeconds;
    const Bytes draw = randomBytes(kJitterBytes);
    const std::int64_t jitter
        = span > 0 ? static_cast<std::int64_t>(draw[0] << CHAR_BIT | draw[1]) % span : 0;
    Session session;
    session.id = id;
    session.user = user;
    session.key = auth::deriveSessionKey(secret, id);
    session.secret = secret;
    session.expiresUnix = now + auth::kSessionMinLifetimeSeconds + jitter;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = sessions_.find(id);
        if (found != sessions_.end() && found->second.expiresUnix > now) {
            // Opening twice on one secret is the same session, not a new one.
            // Overwriting it put lastSeq back to zero, and this session's own
            // spent sequence numbers became usable again.
            if (found->second.user != user) {
                throw std::runtime_error("this session secret is already another account's");
            }
            if (outExpiresUnix != nullptr) {
                *outExpiresUnix = found->second.expiresUnix;
            }
            return id;
        }
        if (found != sessions_.end()) {
            forgetHandlesLocked(found->second);  // lapsed: its handles go with it
        }
        sessions_[id] = session;
        indexHandlesLocked(session);
    }
    if (outExpiresUnix != nullptr) {
        *outExpiresUnix = session.expiresUnix;
    }
    return id;
}

void SessionStore::indexHandlesLocked(const Session& session)
{
    for (std::uint64_t seq = session.lastSeq + 1; seq <= session.lastSeq + kHandleWindow; ++seq) {
        handles_[auth::sessionHandle(session.secret, seq)] = session.id;
    }
}

void SessionStore::forgetHandlesLocked(const Session& session)
{
    for (std::uint64_t seq = session.lastSeq + 1; seq <= session.lastSeq + kHandleWindow; ++seq) {
        handles_.erase(auth::sessionHandle(session.secret, seq));
    }
}

std::optional<SessionStore::Session> SessionStore::findByHandle(
    const std::string& handle, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (now - lastSweep_ > kSweepIntervalSeconds) {
        lastSweep_ = now;
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (it->second.expiresUnix <= now) {
                forgetHandlesLocked(it->second);
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }
    const auto handle_ = handles_.find(handle);
    if (handle_ == handles_.end()) {
        return std::nullopt;
    }
    const auto found = sessions_.find(handle_->second);
    if (found == sessions_.end()) {
        handles_.erase(handle_);
        return std::nullopt;
    }
    if (found->second.expiresUnix <= now) {
        forgetHandlesLocked(found->second);
        sessions_.erase(found);
        return std::nullopt;
    }
    return found->second;
}

bool SessionStore::acceptSeq(
    const std::string& handle, const std::uint64_t seq, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto handle_ = handles_.find(handle);
    if (handle_ == handles_.end()) {
        return false;
    }
    const auto found = sessions_.find(handle_->second);
    if (found == sessions_.end() || found->second.expiresUnix <= now) {
        return false;
    }
    if (seq <= found->second.lastSeq) {
        return false;  // replayed: this sequence has already been spent
    }
    // Retire the handles up to here and index the next window, so the set the
    // server accepts moves with the client.
    forgetHandlesLocked(found->second);
    found->second.lastSeq = seq;
    indexHandlesLocked(found->second);
    return true;
}

void SessionStore::setTunnelKey(const std::string& id, const Bytes& tunnelKey)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = sessions_.find(id);
    if (found != sessions_.end()) {
        found->second.tunnelKey = tunnelKey;
    }
}

void SessionStore::drop(const std::string& id)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = sessions_.find(id);
    if (found == sessions_.end()) {
        return;
    }
    forgetHandlesLocked(found->second);
    sessions_.erase(found);
}

std::size_t SessionStore::size() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

}  // namespace bazarish::server
