// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "OperatorPush.hpp"
#include "SubscriptionStore.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace bazarish::service {

std::int64_t idleSince(const std::optional<SubscriptionStore::Account>& account,
    GrantStore& grants, const std::string& user);

void sweepIdleAccounts(SubscriptionStore& store, GrantStore& grants, const OperatorPush& push,
    std::int64_t idleDays, std::int64_t now);

}  // namespace bazarish::service
