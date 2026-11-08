// Bazarish project (c) 2026
#include "AccountRemoval.hpp"

#include <bazarish/Log.hpp>

namespace bazarish::service {

void removeAccount(const std::string& user, SubscriptionStore& store, GrantStore& grants,
    const std::function<bool(const std::string&)>& takeDownAddress,
    const std::function<bool(const std::string&)>& forgetMailbox)
{
    if (!takeDownAddress(user)) {
        log::warn("destination of {} was not taken down: the messaging server refused it",
            log::redact(user));
    }
    if (!forgetMailbox(user)) {
        log::warn("mailbox of {} was not dropped: the messaging server refused it",
            log::redact(user));
    }
    store.deleteAccount(user);
    grants.erase(user);
}

}  // namespace bazarish::service
