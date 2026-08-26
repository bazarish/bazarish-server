// Bazarish project (c) 2026
#include "WarmDestPool.hpp"

#include <bazarish/Log.hpp>

#include <algorithm>
#include <vector>

namespace bazarish::server {

WarmDestPool::WarmDestPool(bazarish::i2p::Router& router, Options options)
    : router_(router)
    , options_(options)
    , target_(std::clamp(options.startSize, options.minSize, options.maxSize))
    , lastAcquire_(std::chrono::steady_clock::now())
    , windowStartedAt_(std::chrono::steady_clock::now())
{
}

WarmDestPool::~WarmDestPool()
{
    stop();
    if (warmer_.joinable()) {
        warmer_.join();
    }
}

void WarmDestPool::start()
{
    if (running_.exchange(true)) {
        return;
    }
    warmer_ = std::thread([this]() { warmerLoop(); });
}

void WarmDestPool::stop()
{
    running_ = false;
    cv_.notify_all();
}

std::shared_ptr<bazarish::i2p::Endpoint> WarmDestPool::acquire()
{
    std::shared_ptr<bazarish::i2p::Endpoint> dest;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        lastAcquire_ = std::chrono::steady_clock::now();
        if (ready_.empty()) {
            ++misses_;
            sawMiss_ = true;  // a starved acquire pushes the target size up next tick
        } else {
            dest = std::move(ready_.front());
            ready_.pop_front();
            ++hits_;
        }
        // Demand is answered as it appears, not at the end of the window: once half
        // the pool has gone in one window the target doubles on the spot and the
        // warmer starts building, rather than letting the rest of the window run out
        // against a pool that is already short.
        ++takenInWindow_;
        if (takenInWindow_ * 2 >= target_ && target_ < options_.maxSize) {
            target_ = std::min(options_.maxSize, target_ * 2);
            takenInWindow_ = 0;
            windowStartedAt_ = lastAcquire_;
        }
    }
    cv_.notify_all();  // wake the warmer to refill (and re-evaluate the target)
    return dest;
}

WarmDestPool::Stats WarmDestPool::stats() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    Stats s;
    s.ready = ready_.size();
    s.target = target_;
    s.hits = hits_;
    s.misses = misses_;
    return s;
}

void WarmDestPool::warmerLoop()
{
    // Destinations still warming, owned by this loop until ready or abandoned.
    std::vector<Building> building;

    while (running_.load()) {
        std::size_t toCreate = 0;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            // Adapt the target: a starved acquire since the last tick grows it toward
            // maxSize; a stretch with no acquires decays it one step toward minSize
            // (and any warm dests beyond the new target are dropped to free the
            // router's tunnels - they were never used, so anonymity is unaffected).
            sawMiss_ = false;
            const auto now = std::chrono::steady_clock::now();
            if (now - windowStartedAt_ >= options_.demandWindow) {
                if (takenInWindow_ == 0 && target_ > options_.minSize) {
                    // A whole window with nobody asking: step the target down and let
                    // the surplus go. They were never used, so dropping them costs
                    // nothing but the tunnels they were holding.
                    target_ = target_ > options_.minSize + options_.shrinkStep
                        ? target_ - options_.shrinkStep
                        : options_.minSize;
                    while (ready_.size() > target_) {
                        ready_.pop_front();
                    }
                }
                takenInWindow_ = 0;
                windowStartedAt_ = now;
            }
            const std::size_t have = ready_.size() + building.size();
            toCreate = target_ > have ? target_ - have : 0;
        }

        // Create the shortfall (createEndpoint returns at once; the tunnels build in
        // the background, which is what waiting on ready() below tracks). A single-use
        // outbound dest stays UNPUBLISHED - the reply rides the stream's inline
        // leaseset, like the blob endpoint - so it never touches the netDb.
        for (std::size_t i = 0; i < toCreate && running_.load(); ++i) {
            try {
                auto endpoint = router_.createEndpoint(bazarish::i2p::EndpointConfig{
                    bazarish::i2p::Keys::generate(), bazarish::i2p::LeaseSetKind::eEncrypted,
                    options_.privacy, options_.tunnelQuantity, /*published=*/false});
                if (endpoint) {
                    building.push_back({std::move(endpoint), std::chrono::steady_clock::now()});
                }
            } catch (const std::exception& error) {
                bazarish::log::warn("warm-pool: createEndpoint failed: {}", error.what());
            }
        }

        // Promote any dest whose tunnels are up; abandon one that never warmed.
        const auto now = std::chrono::steady_clock::now();
        for (auto it = building.begin(); it != building.end();) {
            if (it->endpoint && it->endpoint->ready()) {
                std::size_t warm = 0;
                std::size_t tgt = 0;
                {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    ready_.push_back(std::move(it->endpoint));
                    warm = ready_.size();
                    tgt = target_;
                }
                bazarish::log::info("warm-pool: dest ready ({} warm, target {})", warm, tgt);
                it = building.erase(it);
            } else if (now - it->startedAt > options_.buildTimeout) {
                // Best-effort: a dest that could not build tunnels in time (e.g. a
                // firewalled router with no peers) is dropped; the loop retries.
                bazarish::log::warn("warm-pool: abandoning a dest that never warmed");
                it = building.erase(it);
            } else {
                ++it;
            }
        }

        // Sleep until the next tick (woken early by an acquire). A short tick keeps
        // ready() polling responsive while still building in the background.
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(building.empty() ? 1000 : 300),
            [this]() { return !running_.load(); });
    }
}

}  // namespace bazarish::server
