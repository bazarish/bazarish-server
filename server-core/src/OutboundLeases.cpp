// Bazarish project (c) 2026
#include "OutboundLeases.hpp"

#include <bazarish/Log.hpp>

namespace bazarish::server {

namespace {

// How often expired terms are swept. Well inside a term, so a destination is let
// go close to when it should be rather than at the next delivery.
constexpr std::chrono::seconds kSweepInterval{30};

}  // namespace

OutboundLeases::OutboundLeases(WarmDestPool& pool, Options options)
    : pool_(pool)
    , options_(options)
{
}

OutboundLeases::~OutboundLeases()
{
    stop();
    if (sweeper_.joinable()) {
        sweeper_.join();
    }
}

void OutboundLeases::start()
{
    if (running_.exchange(true)) {
        return;
    }
    sweeper_ = std::thread([this]() { sweeperLoop(); });
}

void OutboundLeases::stop()
{
    running_ = false;
    cv_.notify_all();
}

void OutboundLeases::dropExpired(const std::chrono::steady_clock::time_point now)
{
    for (auto it = leases_.begin(); it != leases_.end();) {
        if (it->second.expiresAt <= now) {
            // Unconditionally: a destination that served a user is not handed to
            // anyone else and is not kept because it was quiet.
            it = leases_.erase(it);
        } else {
            ++it;
        }
    }
}

std::shared_ptr<bazarish::i2p::Endpoint> OutboundLeases::forPair(
    const std::string& user, const std::string& toDest)
{
    // The pair is the key: one address serves one sender writing to one recipient.
    const std::string key = user + "|" + toDest;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        dropExpired(now);
        const auto found = leases_.find(key);
        if (found != leases_.end()) {
            return found->second.endpoint;
        }
    }
    // Taken outside the lock: acquiring wakes the pool's warmer, and holding this
    // lock across it would queue every other user behind one refill.
    std::shared_ptr<bazarish::i2p::Endpoint> fresh = pool_.acquire();
    if (!fresh) {
        return nullptr;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    const auto found = leases_.find(key);
    if (found != leases_.end() && found->second.expiresAt > now) {
        return found->second.endpoint;  // another delivery got there first
    }
    leases_[key] = Lease{fresh, now + options_.term};
    return fresh;
}

OutboundLeases::Stats OutboundLeases::stats() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    Stats s;
    s.live = leases_.size();
    return s;
}

void OutboundLeases::sweeperLoop()
{
    while (running_.load()) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (cv_.wait_for(lock, kSweepInterval, [this]() { return !running_.load(); })) {
                return;
            }
            dropExpired(std::chrono::steady_clock::now());
        }
    }
}

}  // namespace bazarish::server
