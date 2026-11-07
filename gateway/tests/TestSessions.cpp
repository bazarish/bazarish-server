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

    const std::shared_ptr<Session> first = store.open(kStart);
    const std::shared_ptr<Session> second = store.open(kStart);
    CHECK(first->cookie() != second->cookie());
    CHECK(!first->cookie().empty());
    CHECK(store.size() == 2);
    const std::vector<Bytes> tickets = first->issueTickets(kTicketsHeld);
    CHECK(tickets.size() == kTicketsHeld);
    CHECK(store.holding(tickets.front(), kStart) == first);
    CHECK(store.holding(randomBytes(kTicketBytes), kStart) == nullptr);

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

    CHECK(store.holding(tickets.back(), kStart + 2 + kTtl) == nullptr);
    CHECK(store.size() == 2);

    second->addSocket();
    const std::vector<std::shared_ptr<Session>> gone = store.sweep(kStart + 2 + kTtl);
    CHECK(gone.size() == 1);
    CHECK(gone.front() == first);
    CHECK(store.size() == 1);
    const std::vector<Bytes> secondTickets = second->issueTickets(1);
    CHECK(store.holding(secondTickets.front(), kStart + 2 + kTtl) == second);

    CHECK(!second->full());
    while (second->sockets() < kMaxSocketsPerSession) {
        second->addSocket();
    }
    CHECK(second->full());

    Session lonely("cookie", kStart);
    lonely.removeSocket(kStart);
    CHECK(lonely.sockets() == 0);
    CHECK(lonely.expired(kStart + kTtl, kTtl));

    std::set<std::uint32_t> issued;
    for (int i = 0; i < 50; ++i) {
        const std::uint32_t id = second->ids().next();
        CHECK(id % 2 == 1);
        CHECK(issued.insert(id).second);
    }

    const Bytes answer = {0x03, 0x00, 0x00, 0x00, 0x04};
    CHECK(!second->answered(4).has_value());
    second->remember(4, answer);
    CHECK(second->answered(4).has_value());
    CHECK(*second->answered(4) == answer);
    second->remember(4, Bytes{0xFF});
    CHECK(*second->answered(4) == answer);

    for (std::uint32_t ref = 100; ref < 300; ++ref) {
        second->remember(ref, Bytes{static_cast<unsigned char>(ref & 0xFF)});
    }
    CHECK(!second->answered(4).has_value());
    CHECK(second->answered(299).has_value());

    store.close(second->cookie());
    CHECK(store.size() == 0);
    CHECK(store.holding(secondTickets.front(), kStart) == nullptr);

    std::printf("TestSessions ok\n");
    return 0;
}
