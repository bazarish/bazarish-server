// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "SubscriptionStore.hpp"

#include <functional>
#include <string>

namespace bazarish::service {

// Takes an account off its messaging server - the address, then the mailbox - and then off this
// node. The caller holds the account's lock.
void removeAccount(const std::string& user, SubscriptionStore& store, GrantStore& grants,
    const std::function<bool(const std::string&)>& takeDownAddress,
    const std::function<bool(const std::string&)>& forgetMailbox);

}  // namespace bazarish::service
