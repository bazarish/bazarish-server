// Bazarish project (c) 2026
#include "UserLocks.hpp"

#include <utility>

namespace bazarish::service {

UserLocks::Held::Held(std::shared_ptr<std::mutex> mutex)
    : mutex_(std::move(mutex))
    , lock_(*mutex_)
{
}

UserLocks::Held UserLocks::hold(const std::string& user)
{
    std::shared_ptr<std::mutex> mutex;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        std::erase_if(locks_, [](const auto& entry) { return entry.second.expired(); });
        std::weak_ptr<std::mutex>& held = locks_[user];
        mutex = held.lock();
        if (!mutex) {
            mutex = std::make_shared<std::mutex>();
            held = mutex;
        }
    }
    return Held(std::move(mutex));
}

long UserLocks::holders(const std::string& user)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = locks_.find(user);
    return found == locks_.end() ? 0 : found->second.use_count();
}

}  // namespace bazarish::service
