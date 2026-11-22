// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "PushQueue.hpp"
#include "SubscriptionStore.hpp"

#include <string>

namespace bazarish::service {

// The caller holds the account's lock.
void removeAccount(
    const std::string& user, SubscriptionStore& store, GrantStore& grants, PushQueue& pushes);

}  // namespace bazarish::service
