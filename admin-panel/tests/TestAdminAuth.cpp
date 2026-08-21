// Bazarish project (c) 2026
#include "AdminAuth.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#define CHECK_THROWS(expression)                                                      \
    do {                                                                             \
        bool thrown = false;                                                         \
        try {                                                                        \
            (void)(expression);                                                      \
        } catch (const std::exception&) {                                            \
            thrown = true;                                                           \
        }                                                                            \
        if (!thrown) {                                                               \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d: %s did not throw\n", \
                __FILE__, __LINE__, #expression);                                    \
            std::exit(1);                                                            \
        }                                                                            \
    } while (false)

using namespace bazarish;
using namespace bazarish::admin;

namespace {

constexpr std::int64_t kNow = 1780000000;

// Produces the login blob the client's `sign-login` would emit: the four
// request-auth headers over the challenge, packed as base64(JSON {k,t,c,p}).
std::string forgeBlob(const Identity& identity, const std::string& challenge, std::int64_t ts)
{
    const auth::Headers headers = auth::signRequest(
        identity, ts, kLoginMethod, kLoginPath, Bytes(challenge.begin(), challenge.end()));
    const nlohmann::json blob = {
        {"k", headers.at(auth::kHeaderKeys)},
        {"t", headers.at(auth::kHeaderTimestamp)},
        {"c", headers.at(auth::kHeaderSignatureClassical)},
        {"p", headers.at(auth::kHeaderSignaturePq)},
    };
    const std::string text = blob.dump();
    return toBase64(Bytes(text.begin(), text.end()));
}

std::string makeChallenge(const std::string& nonce, std::int64_t ts, const std::string& aud)
{
    const nlohmann::json envelope = {{"nonce", nonce}, {"ts", ts}, {"aud", aud}};
    const std::string text = envelope.dump();
    return toBase64(Bytes(text.begin(), text.end()));
}

}  // namespace

int main()
{
    const Identity admin = Identity::generate();

    // ChallengeStore: single-use, audience- and freshness-bound.
    {
        ChallengeStore store("aud-x");
        const std::string challenge = store.issue(kNow);
        CHECK(store.consume(challenge, kNow));         // accepted once
        CHECK(!store.consume(challenge, kNow));        // replay rejected
        CHECK(!store.consume("not-base64", kNow));     // garbage rejected
        // A well-formed but never-issued challenge is rejected.
        CHECK(!store.consume(makeChallenge("ffff", kNow, "aud-x"), kNow));
        // Wrong audience rejected even if otherwise valid-looking.
        const std::string fresh = store.issue(kNow);
        CHECK(!store.consume(makeChallenge("ffff", kNow, "other"), kNow));
        // Stale (outside the freshness window) rejected.
        const std::string stale = store.issue(kNow);
        CHECK(!store.consume(stale, kNow + auth::kAuthFreshnessWindowSeconds + 1));
    }

    // Full login: a panel-issued challenge, signed by the configured admin.
    {
        AdminAuth auth("bazarish-admin-panel", {admin.fingerprint()});
        const std::string challenge = auth.issueChallenge(kNow);
        const std::string blob = forgeBlob(admin, challenge, kNow);
        CHECK(auth.login(challenge, blob, kNow) == admin.fingerprint());
        // The same challenge + blob cannot be reused (single-use defeats replay).
        CHECK_THROWS(auth.login(challenge, blob, kNow));
    }

    // A panel with two operators takes either of them.
    {
        const Identity second = Identity::generate();
        AdminAuth auth("bazarish-admin-panel", {admin.fingerprint(), second.fingerprint()});
        const std::string challenge = auth.issueChallenge(kNow);
        CHECK(auth.login(challenge, forgeBlob(second, challenge, kNow), kNow)
            == second.fingerprint());
    }

    // A valid signature from a non-admin identity is rejected.
    {
        AdminAuth auth("bazarish-admin-panel", {admin.fingerprint()});
        const Identity stranger = Identity::generate();
        const std::string challenge = auth.issueChallenge(kNow);
        const std::string blob = forgeBlob(stranger, challenge, kNow);
        CHECK_THROWS(auth.login(challenge, blob, kNow));
    }

    // A blob signed too long ago fails the freshness check.
    {
        AdminAuth auth("bazarish-admin-panel", {admin.fingerprint()});
        const std::string challenge = auth.issueChallenge(kNow);
        const std::string blob = forgeBlob(admin, challenge, kNow);
        CHECK_THROWS(
            auth.login(challenge, blob, kNow + auth::kAuthFreshnessWindowSeconds + 1));
    }

    // The replay-defense crux: a validly-signed blob over a challenge this panel
    // never issued (e.g. captured from another verifier) is rejected, because the
    // challenge is not in the issued set.
    {
        AdminAuth auth("bazarish-admin-panel", {admin.fingerprint()});
        const std::string foreign = makeChallenge("deadbeef", kNow, "bazarish-admin-panel");
        const std::string blob = forgeBlob(admin, foreign, kNow);
        CHECK_THROWS(auth.login(foreign, blob, kNow));
    }

    std::printf("TestAdminAuth: all checks passed\n");
    return 0;
}
