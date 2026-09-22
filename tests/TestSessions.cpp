// Bazarish project (c) 2026
#include "Sessions.hpp"

#include "TestUtil.hpp"

#include <set>
#include <string>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr std::int64_t kTtl = kSessionTtl.count();
constexpr std::int64_t kStart = 1000000;

}  // namespace

int main()
{
    SessionStore store(kTtl);

    // Every session gets a cookie of its own, and it names that session.
    const std::shared_ptr<Session> first = store.open(kStart);
    const std::shared_ptr<Session> second = store.open(kStart);
    CHECK(first->cookie() != second->cookie());
    CHECK(!first->cookie().empty());
    CHECK(store.size() == 2);
    CHECK(store.find(first->cookie(), kStart) == first);
    // A cookie that names nothing is not an error, it is nothing.
    CHECK(store.find("not-a-cookie", kStart) == nullptr);

    // While a socket is attached the session does not expire, however long it
    // has been. The clock starts when the last one drops.
    first->addSocket();
    CHECK(first->sockets() == 1);
    CHECK(!first->expired(kStart + 10 * kTtl, kTtl));
    first->addSocket();
    first->removeSocket(kStart + 1);
    CHECK(first->sockets() == 1);
    CHECK(!first->expired(kStart + 10 * kTtl, kTtl));
    first->removeSocket(kStart + 2);
    CHECK(first->sockets() == 0);
    CHECK(!first->expired(kStart + 2 + kTtl - 1, kTtl));
    CHECK(first->expired(kStart + 2 + kTtl, kTtl));

    // A session past its term is gone before anything sweeps it: the sweep is
    // housekeeping, not the rule.
    CHECK(store.find(first->cookie(), kStart + 2 + kTtl) == nullptr);
    CHECK(store.size() == 2);

    // The sweep names what it dropped and leaves what is still standing.
    second->addSocket();
    const std::vector<std::shared_ptr<Session>> gone = store.sweep(kStart + 2 + kTtl);
    CHECK(gone.size() == 1);
    CHECK(gone.front() == first);
    CHECK(store.size() == 1);
    CHECK(store.find(second->cookie(), kStart + 2 + kTtl) == second);

    // Sockets are bounded: a client cannot open as many as it likes.
    CHECK(!second->full());
    while (second->sockets() < kMaxSocketsPerSession) {
        second->addSocket();
    }
    CHECK(second->full());

    // Removing a socket that is not there does not underflow into a session
    // that can never expire.
    Session lonely("cookie", kStart);
    lonely.removeSocket(kStart);
    CHECK(lonely.sockets() == 0);
    CHECK(lonely.expired(kStart + kTtl, kTtl));

    // The gateway allocates the odd half of the space, and never twice.
    std::set<std::uint32_t> issued;
    for (int i = 0; i < 50; ++i) {
        const std::uint32_t id = second->ids().next();
        CHECK(id % 2 == 1);
        CHECK(issued.insert(id).second);
    }

    // A request re-sent after a socket died gets the answer it already earned,
    // not a second endpoint.
    const Bytes answer = {0x03, 0x00, 0x00, 0x00, 0x04};
    CHECK(second->answered(4) == nullptr);
    second->remember(4, answer);
    CHECK(second->answered(4) != nullptr);
    CHECK(*second->answered(4) == answer);
    // Remembering the same reference twice keeps the first answer: the second
    // attempt at an operation that already happened is not a new outcome.
    second->remember(4, Bytes{0xFF});
    CHECK(*second->answered(4) == answer);

    // The record is bounded, and what falls out of it is the oldest.
    for (std::uint32_t ref = 100; ref < 300; ++ref) {
        second->remember(ref, Bytes{static_cast<unsigned char>(ref & 0xFF)});
    }
    CHECK(second->answered(4) == nullptr);
    CHECK(second->answered(299) != nullptr);

    // Closing forgets a session whether or not it had expired.
    store.close(second->cookie());
    CHECK(store.size() == 0);
    CHECK(store.find(second->cookie(), kStart) == nullptr);

    std::printf("TestSessions ok\n");
    return 0;
}
