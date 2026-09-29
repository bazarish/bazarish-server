// Bazarish project (c) 2026
#include "Sessions.hpp"

#include <utility>

namespace bazarish::gateway {

namespace {

// A client re-sends only what was in flight when a socket died, which is a
// handful of requests. Keeping the last few answers is enough to make every
// such repeat idempotent, and bounding them is what keeps a long session from
// remembering a day of traffic.
constexpr std::size_t kAnswersRemembered = 64;

}  // namespace

Session::Session(std::string cookie, const std::int64_t now)
    : cookie_(std::move(cookie))
    , ids_(/*odd=*/true)
    , aloneSince_(now)
{
}

void Session::addSocket()
{
    ++sockets_;
}

void Session::removeSocket(const std::int64_t now)
{
    if (sockets_ == 0) {
        return;
    }
    --sockets_;
    if (sockets_ == 0) {
        aloneSince_ = now;
    }
}

bool Session::expired(const std::int64_t now, const std::int64_t ttlSeconds) const
{
    if (sockets_ > 0) {
        return false;
    }
    return now - aloneSince_ >= ttlSeconds;
}

void Session::remember(const std::uint32_t ref, Bytes answer)
{
    if (answers_.find(ref) != answers_.end()) {
        return;
    }
    answers_.emplace(ref, std::move(answer));
    answerOrder_.push_back(ref);
    while (answerOrder_.size() > kAnswersRemembered) {
        answers_.erase(answerOrder_.front());
        answerOrder_.pop_front();
    }
}

const Bytes* Session::answered(const std::uint32_t ref) const
{
    const auto found = answers_.find(ref);
    return found == answers_.end() ? nullptr : &found->second;
}

SessionStore::SessionStore(const std::int64_t ttlSeconds)
    : ttlSeconds_(ttlSeconds)
{
}

std::shared_ptr<Session> SessionStore::open(const std::int64_t now)
{
    const std::string cookie = toBase64Url(randomBytes(kSessionCookieBytes));
    std::shared_ptr<Session> session = std::make_shared<Session>(cookie, now);
    sessions_.emplace(cookie, session);
    return session;
}

std::shared_ptr<Session> SessionStore::find(
    const std::string& cookie, const std::int64_t now) const
{
    const auto found = sessions_.find(cookie);
    if (found == sessions_.end()) {
        return nullptr;
    }
    // A session past its term is gone even if nothing has swept it yet: the
    // sweep is housekeeping, not the rule.
    if (found->second->expired(now, ttlSeconds_)) {
        return nullptr;
    }
    return found->second;
}

void SessionStore::close(const std::string& cookie)
{
    sessions_.erase(cookie);
}

std::vector<std::shared_ptr<Session>> SessionStore::drain()
{
    std::vector<std::shared_ptr<Session>> gone;
    for (auto& [cookie, session] : sessions_) {
        (void)cookie;
        gone.push_back(session);
    }
    sessions_.clear();
    return gone;
}

std::vector<std::shared_ptr<Session>> SessionStore::sweep(const std::int64_t now)
{
    std::vector<std::shared_ptr<Session>> gone;
    for (auto at = sessions_.begin(); at != sessions_.end();) {
        if (at->second->expired(now, ttlSeconds_)) {
            gone.push_back(at->second);
            at = sessions_.erase(at);
        } else {
            ++at;
        }
    }
    return gone;
}

}  // namespace bazarish::gateway
