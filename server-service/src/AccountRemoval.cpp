// Bazarish project (c) 2026
#include "AccountRemoval.hpp"

namespace bazarish::service {

void removeAccount(
    const std::string& user, SubscriptionStore& store, GrantStore& grants, PushQueue& pushes)
{
    pushes.record(user, {.forget = true});
    store.deleteAccount(user);
    grants.erase(user);
    pushes.deliver(user);
}

}  // namespace bazarish::service
