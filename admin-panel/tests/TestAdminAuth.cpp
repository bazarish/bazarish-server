// Bazarish project (c) 2026
#include "AdminAuth.hpp"

#include <filesystem>
#include <memory>

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

std::string forgeBlob(const Identity& identity, const std::string& challenge, std::int64_t ts)
{
    return service::signLoginBlob(identity, ts, challenge);
}

service::LoginConsumer panelConsumer()
{
    return service::LoginConsumer{"Bazarish admin panel", "http://127.0.0.1:8460", "Administrator"};
}

std::string foreignChallenge(const service::LoginConsumer& consumer, std::int64_t ts)
{
    service::LoginChallenge elsewhere("another-portal-secret", consumer);
    return elsewhere.issue(ts);
}

std::shared_ptr<PanelSettings> panelWith(std::vector<std::string> admins)
{
    Config config;
    config.consumer = panelConsumer();
    config.admins = std::move(admins);
    return std::make_shared<PanelSettings>(std::filesystem::path(), std::move(config));
}

}  // namespace

int main()
{
    const Identity admin = Identity::generate();

    {
        AdminAuth auth(panelWith({admin.fingerprint()}));
        const service::LoginConsumer named
            = service::readLoginConsumer(auth.issueChallenge(kNow));
        CHECK(named.name == panelConsumer().name);
        CHECK(named.place == panelConsumer().place);
        CHECK(named.role == panelConsumer().role);
    }

    {
        AdminAuth auth(panelWith({admin.fingerprint()}));
        const std::string challenge = auth.issueChallenge(kNow);
        const std::string blob = forgeBlob(admin, challenge, kNow);
        CHECK(auth.login(challenge, blob, kNow) == admin.fingerprint());
        CHECK_THROWS(auth.login(challenge, blob, kNow));
    }

    {
        const Identity second = Identity::generate();
        AdminAuth auth(panelWith({admin.fingerprint(), second.fingerprint()}));
        const std::string challenge = auth.issueChallenge(kNow);
        CHECK(auth.login(challenge, forgeBlob(second, challenge, kNow), kNow)
            == second.fingerprint());
    }

    {
        AdminAuth auth(panelWith({admin.fingerprint()}));
        const Identity stranger = Identity::generate();
        const std::string challenge = auth.issueChallenge(kNow);
        const std::string blob = forgeBlob(stranger, challenge, kNow);
        CHECK_THROWS(auth.login(challenge, blob, kNow));
    }

    {
        AdminAuth auth(panelWith({admin.fingerprint()}));
        const std::string challenge = auth.issueChallenge(kNow);
        const std::string blob = forgeBlob(admin, challenge, kNow);
        CHECK_THROWS(
            auth.login(challenge, blob, kNow + auth::kAuthFreshnessWindowSeconds + 1));
    }

    {
        AdminAuth auth(panelWith({admin.fingerprint()}));
        const std::string foreign = foreignChallenge(panelConsumer(), kNow);
        const std::string blob = forgeBlob(admin, foreign, kNow);
        CHECK_THROWS(auth.login(foreign, blob, kNow));
    }

    {
        AdminAuth auth(panelWith({admin.fingerprint()}));
        service::LoginConsumer somewhereElse = panelConsumer();
        somewhereElse.place = "http://192.0.2.10:8460";
        service::LoginChallenge other("another-portal-secret", somewhereElse);
        const std::string challenge = other.issue(kNow);
        CHECK_THROWS(auth.login(challenge, forgeBlob(admin, challenge, kNow), kNow));
    }

    std::printf("TestAdminAuth: all checks passed\n");
    return 0;
}
