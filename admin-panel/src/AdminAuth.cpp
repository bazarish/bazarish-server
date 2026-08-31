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

AdminAuth::AdminAuth(service::LoginConsumer consumer, std::vector<std::string> adminFingerprints)
    : challenges_(toHex(randomBytes(kChallengeSecretBytes)), std::move(consumer))
    , adminFingerprints_(std::move(adminFingerprints))
{
}

std::string AdminAuth::issueChallenge(const std::int64_t now)
{
    return challenges_.issue(now);
}

std::string AdminAuth::login(
    const std::string& challenge, const std::string& blob, const std::int64_t now)
{
    // Single use is what defeats replay: a login blob captured from any other
    // verifier carries a challenge this panel never minted, so it is rejected
    // here even though its signature is valid. The store consumes the nonce only
    // after the signature checks out, so a bad blob cannot burn a good challenge.
    const std::string fingerprint = challenges_.verify(challenge, blob, now);
    if (std::find(adminFingerprints_.begin(), adminFingerprints_.end(), fingerprint)
        == adminFingerprints_.end()) {
        throw std::runtime_error("login: not a configured admin identity");
    }
    return fingerprint;
}

}  // namespace bazarish::admin
