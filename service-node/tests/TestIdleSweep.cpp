// Bazarish project (c) 2026
#include "GrantStore.hpp"
#include "IdleSweep.hpp"
#include "OperatorPush.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::service;

namespace {

constexpr std::int64_t kIdleDays = 180;
constexpr std::int64_t kRegisteredAt = 1'800'000'000;
constexpr std::int64_t kLapsedDelegationDay = 10;
constexpr std::int64_t kActiveDelegationDay = 30;
constexpr std::int64_t kPendingRegistrationDay = 100;
constexpr std::int64_t kSweepDay = kIdleDays + 20;

SubscriptionStore::Account account(const std::string& user, const std::int64_t delegatedAt)
{
    SubscriptionStore::Account record;
    record.user = user;
    record.registeredAt = kRegisteredAt;
    record.delegatedAt = delegatedAt;
    return record;
}

std::int64_t days(const std::int64_t count)
{
    return count * kSecondsPerDay;
}

}  // namespace

int main()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-sweep-" + toHex(randomBytes(8)));
    const Identity node = Identity::generate();
    const OperatorPush noServer(OperatorPush::Dial{}, node, OperatorPush::kPromptAttempts);

    const std::string active = Identity::generate().fingerprint();
    const std::string lapsed = Identity::generate().fingerprint();
    const std::string neverDelegated = Identity::generate().fingerprint();
    const std::string pending = Identity::generate().fingerprint();
    const std::int64_t now = kRegisteredAt + days(kSweepDay);

    {
        SubscriptionStore store(root);
        GrantStore grants(root);
        store.putAccount(account(active, kRegisteredAt + days(kActiveDelegationDay)));
        store.putAccount(account(lapsed, kRegisteredAt + days(kLapsedDelegationDay)));
        store.putAccount(account(neverDelegated, 0));
        grants.recordRegistration(pending, kRegisteredAt + days(kPendingRegistrationDay), false);

        CHECK(idleSince(store.getAccount(active), grants, active)
            == kRegisteredAt + days(kActiveDelegationDay));
        CHECK(idleSince(store.getAccount(neverDelegated), grants, neverDelegated)
            == kRegisteredAt);
        CHECK(idleSince(store.getAccount(pending), grants, pending)
            == kRegisteredAt + days(kPendingRegistrationDay));

        sweepIdleAccounts(store, grants, noServer, 0, now);
        CHECK(store.allAccounts().size() == 3);

        sweepIdleAccounts(store, grants, noServer, kIdleDays, now);
        CHECK(store.getAccount(active).has_value());
        CHECK(!store.getAccount(lapsed).has_value());
        CHECK(!store.getAccount(neverDelegated).has_value());
        CHECK(grants.peekApproval(pending).has_value());

        sweepIdleAccounts(store, grants, noServer, kIdleDays,
            kRegisteredAt + days(kActiveDelegationDay + kIdleDays) + 1);
        CHECK(!store.getAccount(active).has_value());
        CHECK(grants.peekApproval(pending).has_value());

        sweepIdleAccounts(store, grants, noServer, kIdleDays,
            kRegisteredAt + days(kPendingRegistrationDay + kIdleDays) + 1);
        CHECK(!grants.peekApproval(pending).has_value());
    }

    fs::remove_all(root);
    std::printf("TestIdleSweep: all checks passed\n");
    return 0;
}
