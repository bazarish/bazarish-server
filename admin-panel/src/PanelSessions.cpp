// Bazarish project (c) 2026
#include "PanelSessions.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

namespace bazarish::admin {

namespace {
constexpr std::size_t kSessionTokenBytes = 24;
}  // namespace

PanelSessions::PanelSessions(const std::int64_t ttlSeconds)
    : ttlSeconds_(ttlSeconds)
{
}

void PanelSessions::pruneLocked(const std::int64_t now)
{
    for (auto it = tokens_.begin(); it != tokens_.end();) {
        if (it->second.expires <= now) {
            it = tokens_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string PanelSessions::create(const std::string& fingerprint, const std::int64_t now)
{
    const std::string token = toBase64Url(randomBytes(kSessionTokenBytes));
    const std::lock_guard<std::mutex> lock(mutex_);
    pruneLocked(now);
    tokens_[token] = Held{fingerprint, now + ttlSeconds_};
    return token;
}

std::optional<std::string> PanelSessions::holder(const std::string& token, const std::int64_t now)
{
    if (token.empty()) {
        return std::nullopt;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto it = tokens_.find(token);
    if (it == tokens_.end() || it->second.expires <= now) {
        return std::nullopt;
    }
    return it->second.fingerprint;
}

void PanelSessions::destroy(const std::string& token)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    tokens_.erase(token);
}

}  // namespace bazarish::admin
