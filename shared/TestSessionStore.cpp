// Bazarish project (c) 2026
#include "SessionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Crypto.hpp>

#include <cstdio>
#include <string>

#define CHECK(condition)                                                                \
    do {                                                                                \
        if (!(condition)) {                                                             \
            std::printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            return 1;                                                                   \
        }                                                                               \
    } while (false)

using namespace bazarish;
using namespace bazarish::server;

namespace {

constexpr std::int64_t kNow = 1780000000;
constexpr std::uint64_t kHandleWindow = 64;

const std::string kUser = std::string(52, 'a');

}  // namespace

int main()
{
    const Bytes secret = randomBytes(32);

    {
        SessionStore sessions;
        std::int64_t expires = 0;
        const std::string id = sessions.open(kUser, secret, kNow, expires);
        CHECK(!id.empty());
        CHECK(sessions.size() == 1);
        CHECK(id == toHex(sha256(secret)).substr(0, 32));
        CHECK(expires >= kNow + auth::kSessionMinLifetimeSeconds);
        CHECK(expires <= kNow + auth::kSessionMaxLifetimeSeconds);

        for (const std::uint64_t seq : {std::uint64_t{1}, kHandleWindow / 2, kHandleWindow}) {
            const std::optional<SessionStore::Session> found
                = sessions.findByHandle(auth::sessionHandle(secret, seq), kNow);
            CHECK(found.has_value());
            CHECK(found->user == kUser);
            CHECK(found->key == auth::deriveSessionKey(secret, id));
        }
        CHECK(!sessions.findByHandle(auth::sessionHandle(secret, kHandleWindow + 1), kNow)
                   .has_value());
        CHECK(!sessions.findByHandle(auth::sessionHandle(randomBytes(32), 1), kNow).has_value());
        CHECK(!sessions.findByHandle("not-a-handle", kNow).has_value());
    }

    {
        SessionStore sessions;
        std::int64_t expires = 0;
        (void)sessions.open(kUser, secret, kNow, expires);

        const std::string handle5 = auth::sessionHandle(secret, 5);
        CHECK(sessions.acceptSeq(handle5, 5, kNow));
        CHECK(!sessions.acceptSeq(auth::sessionHandle(secret, 5), 5, kNow));
        CHECK(!sessions.acceptSeq(auth::sessionHandle(secret, 3), 3, kNow));
        CHECK(!sessions.findByHandle(handle5, kNow).has_value());
        CHECK(!sessions.findByHandle(auth::sessionHandle(secret, 1), kNow).has_value());
        CHECK(sessions.findByHandle(auth::sessionHandle(secret, 6), kNow).has_value());
        CHECK(sessions.findByHandle(auth::sessionHandle(secret, 5 + kHandleWindow), kNow)
                  .has_value());
        CHECK(!sessions.findByHandle(auth::sessionHandle(secret, 5 + kHandleWindow + 1), kNow)
                   .has_value());
        CHECK(sessions.acceptSeq(auth::sessionHandle(secret, 40), 40, kNow));
        CHECK(!sessions.acceptSeq(auth::sessionHandle(secret, 39), 39, kNow));
        CHECK(!sessions.acceptSeq("not-a-handle", 99, kNow));
    }

    {
        SessionStore sessions;
        std::int64_t expires = 0;
        (void)sessions.open(kUser, secret, kNow, expires);
        const std::string handle = auth::sessionHandle(secret, 1);
        CHECK(sessions.findByHandle(handle, expires - 1).has_value());
        CHECK(!sessions.findByHandle(handle, expires).has_value());
        CHECK(!sessions.acceptSeq(handle, 1, expires));
        CHECK(sessions.size() == 0);
    }

    {
        SessionStore sessions;
        const Bytes other = randomBytes(32);
        std::int64_t expires = 0;
        const std::string first = sessions.open(kUser, secret, kNow, expires);
        const std::string second = sessions.open(kUser, other, kNow, expires);
        CHECK(first != second);
        CHECK(sessions.size() == 2);
        CHECK(sessions.acceptSeq(auth::sessionHandle(secret, 9), 9, kNow));
        CHECK(sessions.acceptSeq(auth::sessionHandle(other, 1), 1, kNow));
        CHECK(sessions.findByHandle(auth::sessionHandle(other, 2), kNow)->id == second);
    }

    std::printf("TestSessionStore passed\n");
    return 0;
}
