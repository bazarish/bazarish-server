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
// The width of the reordering a client's two connections produce, and so the
// number of handles the store publishes ahead of where a session stands. Matches
// kHandleWindow in the store itself; a test that guessed differently would pass
// while proving nothing.
constexpr std::uint64_t kHandleWindow = 64;

const std::string kUser = std::string(52, 'a');

}  // namespace

int main()
{
    const Bytes secret = randomBytes(32);

    // A session is found by any handle inside the window ahead of it, and by
    // nothing else: the handles are what a request carries, and only the holder
    // of the secret can produce one.
    {
        SessionStore sessions;
        std::int64_t expires = 0;
        const std::string id = sessions.open(kUser, secret, kNow, &expires);
        CHECK(!id.empty());
        CHECK(sessions.size() == 1);
        // Derived from the secret, so both sides arrive at it without it
        // travelling.
        CHECK(id == toHex(sha256(secret)).substr(0, 32));
        // The lifetime is inside the window, and drawn rather than fixed.
        CHECK(expires >= kNow + auth::kSessionMinLifetimeSeconds);
        CHECK(expires <= kNow + auth::kSessionMaxLifetimeSeconds);

        for (const std::uint64_t seq : {std::uint64_t{1}, kHandleWindow / 2, kHandleWindow}) {
            const std::optional<SessionStore::Session> found
                = sessions.findByHandle(auth::sessionHandle(secret, seq), kNow);
            CHECK(found.has_value());
            CHECK(found->user == kUser);
            CHECK(found->key == auth::deriveSessionKey(secret, id));
        }
        // Beyond the window, and under another secret: neither is this session.
        CHECK(!sessions.findByHandle(auth::sessionHandle(secret, kHandleWindow + 1), kNow)
                   .has_value());
        CHECK(!sessions.findByHandle(auth::sessionHandle(randomBytes(32), 1), kNow).has_value());
        CHECK(!sessions.findByHandle("not-a-handle", kNow).has_value());
    }

    // The sequence is the replay check: strictly increasing, and the window
    // moves with it rather than staying where the session opened.
    {
        SessionStore sessions;
        std::int64_t expires = 0;
        (void)sessions.open(kUser, secret, kNow, &expires);

        const std::string handle5 = auth::sessionHandle(secret, 5);
        CHECK(sessions.acceptSeq(handle5, 5, kNow));
        // The same counter again is the replay this exists to stop, and so is
        // anything below it - a captured request cannot be re-presented.
        CHECK(!sessions.acceptSeq(auth::sessionHandle(secret, 5), 5, kNow));
        CHECK(!sessions.acceptSeq(auth::sessionHandle(secret, 3), 3, kNow));
        // Spent handles are retired: what the store accepts has moved on.
        CHECK(!sessions.findByHandle(handle5, kNow).has_value());
        CHECK(!sessions.findByHandle(auth::sessionHandle(secret, 1), kNow).has_value());
        // And the next window is indexed from where the session now stands.
        CHECK(sessions.findByHandle(auth::sessionHandle(secret, 6), kNow).has_value());
        CHECK(sessions.findByHandle(auth::sessionHandle(secret, 5 + kHandleWindow), kNow)
                  .has_value());
        CHECK(!sessions.findByHandle(auth::sessionHandle(secret, 5 + kHandleWindow + 1), kNow)
                   .has_value());
        // A jump forward inside the window is fine: two connections overtake each
        // other all the time.
        CHECK(sessions.acceptSeq(auth::sessionHandle(secret, 40), 40, kNow));
        CHECK(!sessions.acceptSeq(auth::sessionHandle(secret, 39), 39, kNow));
        // A handle that belongs to no session accepts nothing.
        CHECK(!sessions.acceptSeq("not-a-handle", 99, kNow));
    }

    // A session is over when its term is: it is neither found nor accepted
    // afterwards, and it stops occupying the store.
    {
        SessionStore sessions;
        std::int64_t expires = 0;
        (void)sessions.open(kUser, secret, kNow, &expires);
        const std::string handle = auth::sessionHandle(secret, 1);
        CHECK(sessions.findByHandle(handle, expires - 1).has_value());
        CHECK(!sessions.findByHandle(handle, expires).has_value());
        CHECK(!sessions.acceptSeq(handle, 1, expires));
        CHECK(sessions.size() == 0);
    }

    // Two sessions of one account - a client keeps one for its requests and one
    // for the poll it parks - do not see each other's handles or counters.
    {
        SessionStore sessions;
        const Bytes other = randomBytes(32);
        std::int64_t expires = 0;
        const std::string first = sessions.open(kUser, secret, kNow, &expires);
        const std::string second = sessions.open(kUser, other, kNow, &expires);
        CHECK(first != second);
        CHECK(sessions.size() == 2);
        CHECK(sessions.acceptSeq(auth::sessionHandle(secret, 9), 9, kNow));
        // The other session is untouched by that: its own counter still stands.
        CHECK(sessions.acceptSeq(auth::sessionHandle(other, 1), 1, kNow));
        CHECK(sessions.findByHandle(auth::sessionHandle(other, 2), kNow)->id == second);

        // Dropping one leaves the other, and takes its handles with it.
        sessions.drop(first);
        CHECK(sessions.size() == 1);
        CHECK(!sessions.findByHandle(auth::sessionHandle(secret, 10), kNow).has_value());
        CHECK(sessions.findByHandle(auth::sessionHandle(other, 2), kNow).has_value());
    }

    std::printf("TestSessionStore passed\n");
    return 0;
}
