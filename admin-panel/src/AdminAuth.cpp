// Bazarish project (c) 2026
#include "AdminAuth.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <utility>

namespace bazarish::admin {

std::string verifyLoginBlob(
    const std::string& blob, const std::int64_t now, const std::string& challenge)
{
    const Bytes raw = fromBase64(blob);
    const nlohmann::json parsed = nlohmann::json::parse(raw.begin(), raw.end());
    auth::Headers headers;
    headers[auth::kHeaderKeys] = parsed.at("k").get<std::string>();
    headers[auth::kHeaderTimestamp] = parsed.at("t").get<std::string>();
    headers[auth::kHeaderSignatureClassical] = parsed.at("c").get<std::string>();
    headers[auth::kHeaderSignaturePq] = parsed.at("p").get<std::string>();
    return auth::verifyRequest(
        headers, now, kLoginMethod, kLoginPath, Bytes(challenge.begin(), challenge.end()));
}

ChallengeStore::ChallengeStore(std::string audience)
    : audience_(std::move(audience))
{
}

void ChallengeStore::pruneLocked(const std::int64_t now)
{
    const std::int64_t cutoff = now - auth::kAuthFreshnessWindowSeconds;
    for (auto it = issued_.begin(); it != issued_.end();) {
        if (it->second < cutoff) {
            it = issued_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string ChallengeStore::issue(const std::int64_t now)
{
    const std::string nonce = toHex(randomBytes(16));
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        pruneLocked(now);
        issued_.emplace(nonce, now);
    }
    const nlohmann::json envelope = {
        {"nonce", nonce},
        {"ts", now},
        {"aud", audience_},
    };
    const std::string text = envelope.dump();
    return toBase64(Bytes(text.begin(), text.end()));
}

bool ChallengeStore::consume(const std::string& challenge, const std::int64_t now)
{
    std::string nonce;
    std::int64_t ts = 0;
    std::string aud;
    try {
        const Bytes raw = fromBase64(challenge);
        const nlohmann::json envelope = nlohmann::json::parse(raw.begin(), raw.end());
        nonce = envelope.at("nonce").get<std::string>();
        ts = envelope.at("ts").get<std::int64_t>();
        aud = envelope.at("aud").get<std::string>();
    } catch (const std::exception&) {
        return false;
    }
    if (aud != audience_) {
        return false;
    }
    if (ts < now - auth::kAuthFreshnessWindowSeconds
        || ts > now + auth::kAuthFreshnessWindowSeconds) {
        return false;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    pruneLocked(now);
    // erase returns 1 only if the nonce was issued and not yet consumed.
    return issued_.erase(nonce) == 1;
}

AdminAuth::AdminAuth(std::string audience, std::string adminFingerprint)
    : challenges_(std::move(audience))
    , adminFingerprint_(std::move(adminFingerprint))
{
}

std::string AdminAuth::issueChallenge(const std::int64_t now)
{
    return challenges_.issue(now);
}

std::string AdminAuth::login(
    const std::string& challenge, const std::string& blob, const std::int64_t now)
{
    // Verify the signature before consuming the challenge, so a failed attempt
    // (bad blob) does not burn a valid challenge.
    const std::string fingerprint = verifyLoginBlob(blob, now, challenge);
    if (fingerprint != adminFingerprint_) {
        throw std::runtime_error("login: not the configured admin identity");
    }
    // The single-use consume is what defeats replay: a login blob captured from
    // any other verifier carries a challenge this panel never issued, so it is
    // rejected here even though its signature is valid.
    if (!challenges_.consume(challenge, now)) {
        throw std::runtime_error("login: unknown or already-used challenge");
    }
    return fingerprint;
}

}  // namespace bazarish::admin
