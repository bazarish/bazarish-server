// Bazarish project (c) 2026
#include "AdminAuth.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace bazarish::admin {

namespace {

// The per-run secret that binds this panel's challenges to itself.
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
    // Single use is what defeats replay: a login blob captured from any other
    // verifier carries a challenge this panel never minted, so it is rejected
    // here even though its signature is valid. The store consumes the nonce only
    // after the signature checks out, so a bad blob cannot burn a good challenge.
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
