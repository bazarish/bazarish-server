// Bazarish project (c) 2026
#include "Sessions.hpp"

#include <utility>

namespace bazarish::gateway {

namespace {

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

std::optional<Bytes> Session::answered(const std::uint32_t ref) const
{
    const auto found = answers_.find(ref);
    if (found == answers_.end()) {
        return std::nullopt;
    }
    return found->second;
}

std::vector<Bytes> Session::issueTickets(const std::size_t count)
{
    std::vector<Bytes> issued;
    for (std::size_t i = 0; i < count; ++i) {
        issued.push_back(randomBytes(kTicketBytes));
        tickets.insert(std::string(issued.back().begin(), issued.back().end()));
    }
    return issued;
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

std::shared_ptr<Session> SessionStore::holding(const Bytes& ticket, const std::int64_t now) const
{
    for (const auto& [cookie, session] : sessions_) {
        (void)cookie;
        if (session->tickets.count(std::string(ticket.begin(), ticket.end())) > 0
            && !session->expired(now, ttlSeconds_)) {
            return session;
        }
    }
    return nullptr;
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

std::vector<std::shared_ptr<Session>> SessionStore::all() const
{
    std::vector<std::shared_ptr<Session>> open;
    for (const auto& [cookie, session] : sessions_) {
        (void)cookie;
        open.push_back(session);
    }
    return open;
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
