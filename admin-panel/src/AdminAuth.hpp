// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>

namespace bazarish::admin {

// Wire contract for the login blob. The challenge is signed as the body of a
// canonical request under this fixed method and path, so the panel can verify it
// with the standard request-auth primitive and the client's existing
// `sign-login` command signs exactly this. These two constants define that
// contract and must stay identical to what the client signs.
inline constexpr const char* kLoginMethod = "BZ-LOGIN";
inline constexpr const char* kLoginPath = "/portal/login";

// Verifies a signed login blob over the given challenge and returns the signer's
// hybrid fingerprint. The blob is base64(JSON {k,t,c,p}) carrying the four
// request-auth headers. Throws on any signature, key-type or freshness failure.
// This checks only the signature; it does not enforce single-use or the admin
// identity (the caller does).
std::string verifyLoginBlob(
    const std::string& blob, std::int64_t now, const std::string& challenge);

// Mints single-use login challenges and consumes them exactly once. A challenge
// is base64(JSON {nonce, ts, aud}); the store remembers every issued nonce until
// it is consumed or ages out of the freshness window. Consuming an unknown or
// already-used challenge fails, which is what defeats replay of a captured login
// blob (see AdminAuth::login).
class ChallengeStore {
public:
    explicit ChallengeStore(std::string audience);

    // Issues a fresh challenge for the user to sign with their client.
    std::string issue(std::int64_t now);

    // Returns true if the challenge is one this store issued, carries the right
    // audience, is within the freshness window, and has not been consumed before;
    // consumes it on success. Never throws.
    bool consume(const std::string& challenge, std::int64_t now);

private:
    void pruneLocked(std::int64_t now);

    std::string audience_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> issued_;  // nonce -> issue timestamp
};

// The panel login policy: a challenge it issued, a valid signature over it, and a
// signer that matches one of the configured admin identities.
class AdminAuth {
public:
    AdminAuth(std::string audience, std::vector<std::string> adminFingerprints);

    std::string issueChallenge(std::int64_t now);

    // Completes a login. Verifies the blob's signature over the challenge,
    // requires the signer to be a configured admin, then consumes the challenge
    // (single-use). Returns the admin fingerprint on success; throws otherwise.
    std::string login(const std::string& challenge, const std::string& blob, std::int64_t now);

private:
    ChallengeStore challenges_;
    std::vector<std::string> adminFingerprints_;
};

}  // namespace bazarish::admin
