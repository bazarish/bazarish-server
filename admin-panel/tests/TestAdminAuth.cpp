// Bazarish project (c) 2026
#include "AdminAuth.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/LoginChallenge.hpp>
#include <bazarish/Portal.hpp>

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

// The login blob the client's `sign-login` emits, over this challenge.
std::string forgeBlob(const Identity& identity, const std::string& challenge, std::int64_t ts)
{
    return service::signLoginBlob(identity, ts, challenge);
}

service::LoginConsumer panelConsumer()
{
    return service::LoginConsumer{"Bazarish admin panel", "http://127.0.0.1:8460", "Administrator"};
}

// A challenge nobody here issued, wearing this panel's name: what a captured
// login blob from another verifier looks like from the inside.
std::string foreignChallenge(const service::LoginConsumer& consumer, std::int64_t ts)
{
    service::LoginChallenge elsewhere("another-portal-secret", consumer);
    return elsewhere.issue(ts);
}

}  // namespace

int main()
{
    const Identity admin = Identity::generate();

    // The challenge names this panel, in the words the operator is shown before
    // signing - that is the whole reason it is not an opaque string.
    {
        AdminAuth auth(panelConsumer(), {admin.fingerprint()});
        const service::LoginConsumer named
            = service::readLoginConsumer(auth.issueChallenge(kNow));
        CHECK(named.name == panelConsumer().name);
        CHECK(named.place == panelConsumer().place);
        CHECK(named.role == panelConsumer().role);
    }

    // Full login: a panel-issued challenge, signed by the configured admin.
    {
        AdminAuth auth(panelConsumer(), {admin.fingerprint()});
        const std::string challenge = auth.issueChallenge(kNow);
        const std::string blob = forgeBlob(admin, challenge, kNow);
        CHECK(auth.login(challenge, blob, kNow) == admin.fingerprint());
        // The same challenge + blob cannot be reused (single-use defeats replay).
        CHECK_THROWS(auth.login(challenge, blob, kNow));
    }

    // A panel with two operators takes either of them.
    {
        const Identity second = Identity::generate();
        AdminAuth auth(panelConsumer(), {admin.fingerprint(), second.fingerprint()});
        const std::string challenge = auth.issueChallenge(kNow);
        CHECK(auth.login(challenge, forgeBlob(second, challenge, kNow), kNow)
            == second.fingerprint());
    }

    // A valid signature from a non-admin identity is rejected.
    {
        AdminAuth auth(panelConsumer(), {admin.fingerprint()});
        const Identity stranger = Identity::generate();
        const std::string challenge = auth.issueChallenge(kNow);
        const std::string blob = forgeBlob(stranger, challenge, kNow);
        CHECK_THROWS(auth.login(challenge, blob, kNow));
    }

    // A blob signed too long ago fails the freshness check.
    {
        AdminAuth auth(panelConsumer(), {admin.fingerprint()});
        const std::string challenge = auth.issueChallenge(kNow);
        const std::string blob = forgeBlob(admin, challenge, kNow);
        CHECK_THROWS(
            auth.login(challenge, blob, kNow + auth::kAuthFreshnessWindowSeconds + 1));
    }

    // The replay-defense crux: a validly-signed blob over a challenge this panel
    // never issued (captured from another verifier) is rejected, however right
    // the label on it looks.
    {
        AdminAuth auth(panelConsumer(), {admin.fingerprint()});
        const std::string foreign = foreignChallenge(panelConsumer(), kNow);
        const std::string blob = forgeBlob(admin, foreign, kNow);
        CHECK_THROWS(auth.login(foreign, blob, kNow));
    }

    // A challenge naming another place does not open this panel either: the
    // label is checked before anything else, so the words the operator read are
    // the words the panel agreed to.
    {
        AdminAuth auth(panelConsumer(), {admin.fingerprint()});
        service::LoginConsumer somewhereElse = panelConsumer();
        somewhereElse.place = "http://192.0.2.10:8460";
        service::LoginChallenge other("another-portal-secret", somewhereElse);
        const std::string challenge = other.issue(kNow);
        CHECK_THROWS(auth.login(challenge, forgeBlob(admin, challenge, kNow), kNow));
    }

    std::printf("TestAdminAuth: all checks passed\n");
    return 0;
}
