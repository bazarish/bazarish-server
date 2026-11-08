// Bazarish project (c) 2026
#include "LoginMailbox.hpp"

#include <LoginRelay.hpp>

#include <bazarish/Hmac.hpp>

#include <iterator>
#include <stdexcept>

namespace bazarish::service {

LoginMailbox::LoginMailbox(const std::int64_t windowSeconds)
    : windowSeconds_(windowSeconds)
{
}

bool LoginMailbox::expect(
    const std::string& challenge, const std::string& token, const std::int64_t now)
{
    if (token.empty()) {
        throw std::invalid_argument("an awaited login needs the token of its browser");
    }
    const std::string nonce = loginrelay::nonceOf(challenge);
    const std::lock_guard<std::mutex> lock(mutex_);
    pruneLocked(now);
    if (awaited_.size() >= kMaxAwaitedLogins) {
        return false;
    }
    awaited_[nonce] = Awaited{token, challenge, {}, now};
    return true;
}

std::string LoginMailbox::challengeOf(const std::string& nonce, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    pruneLocked(now);
    const auto found = awaited_.find(nonce);
    return found == awaited_.end() ? std::string() : found->second.challenge;
}

bool LoginMailbox::deliver(const std::string& nonce, const std::string& challenge,
    const std::string& blob, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    pruneLocked(now);
    const auto found = awaited_.find(nonce);
    if (found == awaited_.end() || found->second.challenge != challenge
        || !found->second.blob.empty()) {
        return false;
    }
    found->second.blob = blob;
    return true;
}

LoginMailbox::Claim LoginMailbox::claim(
    const std::string& nonce, const std::string& token, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    pruneLocked(now);
    const auto found = awaited_.find(nonce);
    if (found == awaited_.end() || token.empty()
        || !constantTimeEqual(token, found->second.token)) {
        return {};
    }
    if (found->second.blob.empty()) {
        return Claim{State::eWaiting, {}, {}};
    }
    Claim signedIn{State::eSigned, found->second.challenge, found->second.blob};
    awaited_.erase(found);
    return signedIn;
}

void LoginMailbox::pruneLocked(const std::int64_t now)
{
    for (auto at = awaited_.begin(); at != awaited_.end();) {
        at = now - at->second.since > windowSeconds_ ? awaited_.erase(at) : std::next(at);
    }
}

}  // namespace bazarish::service
