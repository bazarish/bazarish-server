// Bazarish project (c) 2026
#include "IdleSweep.hpp"
#include "AccountRemoval.hpp"

#include <bazarish/Clock.hpp>
#include <bazarish/Log.hpp>

#include <set>

namespace bazarish::service {

std::int64_t idleSince(const std::optional<SubscriptionStore::Account>& account,
    GrantStore& grants, const std::string& user)
{
    if (account.has_value() && account->delegatedAt != 0) {
        return account->delegatedAt;
    }
    if (account.has_value() && account->registeredAt != 0) {
        return account->registeredAt;
    }
    if (const std::optional<GrantStore::Approval> approval = grants.peekApproval(user);
        approval.has_value()) {
        return approval->requestedAt;
    }
    if (const std::optional<GrantStore::SubscriptionGrant> grant = grants.peekSubscription(user);
        grant.has_value()) {
        return grant->grantedAt;
    }
    return 0;
}

void sweepIdleAccounts(SubscriptionStore& store, GrantStore& grants, const OperatorPush& push,
    const std::int64_t idleDays, const std::int64_t now, const StopGate& stopping, UserLocks& locks)
{
    if (idleDays <= 0) {
        return;
    }
    const std::int64_t idleSeconds = idleDays * kSecondsPerDay;
    std::set<std::string> users;
    for (const std::string& user : grants.allUsers()) {
        users.insert(user);
    }
    for (const SubscriptionStore::Account& account : store.allAccounts()) {
        users.insert(account.user);
    }
    for (const std::string& user : users) {
        if (stopping.stopped()) {
            return;
        }
        const UserLocks::Held held = locks.hold(user);
        const std::int64_t since = idleSince(store.getAccount(user), grants, user);
        if (since == 0 || since + idleSeconds > now) {
            continue;
        }
        removeAccount(user, store, grants,
            [&push](const std::string& gone) {
                return push.publish(gone, std::string(), 0, {}).has_value();
            },
            [&push](const std::string& gone) { return push.forgetMailbox(gone); });
        log::info("swept idle account {}", log::redact(user));
    }
}

}  // namespace bazarish::service
