// Bazarish project (c) 2026
#include "AdminAuth.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace bazarish::admin {

namespace {

constexpr std::size_t kChallengeSecretBytes = 16;

}  // namespace

AdminAuth::AdminAuth(std::shared_ptr<PanelSettings> settings)
    : settings_(std::move(settings))
    , challenges_(toHex(randomBytes(kChallengeSecretBytes)), settings_->get().consumer)
{
}

service::LoginChallenge& AdminAuth::challenges()
{
    const service::LoginConsumer wanted = settings_->get().consumer;
    if (wanted != challenges_.consumer()) {
        challenges_.setConsumer(wanted);
    }
    return challenges_;
}

std::string AdminAuth::issueChallenge(const std::int64_t now)
{
    return challenges().issue(now);
}

std::string AdminAuth::verify(
    const std::string& challenge, const std::string& blob, const std::int64_t now)
{
    return challenges().verify(challenge, blob, now);
}

std::string AdminAuth::login(
    const std::string& challenge, const std::string& blob, const std::int64_t now)
{
    const std::string fingerprint = verify(challenge, blob, now);
    const std::vector<std::string> admins = settings_->get().admins;
    if (std::find(admins.begin(), admins.end(), fingerprint) == admins.end()) {
        throw std::runtime_error("login: not a configured admin identity");
    }
    return fingerprint;
}

}  // namespace bazarish::admin
