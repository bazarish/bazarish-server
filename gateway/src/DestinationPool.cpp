// Bazarish project (c) 2026
#include "DestinationPool.hpp"

#include <utility>

namespace bazarish::gateway {

DestinationPool::DestinationPool(
    i2p::Router& router, i2p::EndpointConfig shape, const std::size_t depth)
    : router_(router)
    , shape_(std::move(shape))
{
    for (std::size_t made = 0; made < depth; ++made) {
        held_.push_back(router_.createEndpoint(shape_));
    }
}

DestinationPool::~DestinationPool()
{
    stop();
}

bool DestinationPool::fits(const i2p::EndpointConfig& wanted) const
{
    return wanted.traffic == shape_.traffic && wanted.published == shape_.published
        && wanted.realtime == shape_.realtime && wanted.privacy == shape_.privacy
        && wanted.tunnelQuantity == shape_.tunnelQuantity && !wanted.keys.has_value()
        && wanted.leaseSetReaders.empty() && wanted.leaseSetReaderKey.empty();
}

std::shared_ptr<i2p::Endpoint> DestinationPool::take()
{
    std::shared_ptr<i2p::Endpoint> replacement = router_.createEndpoint(shape_);
    const std::lock_guard<std::mutex> lock(mutex_);
    held_.push_back(std::move(replacement));
    std::shared_ptr<i2p::Endpoint> oldest = std::move(held_.front());
    held_.pop_front();
    return oldest;
}

std::size_t DestinationPool::held() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return held_.size();
}

void DestinationPool::stop()
{
    std::deque<std::shared_ptr<i2p::Endpoint>> dropped;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        dropped.swap(held_);
    }
    for (const std::shared_ptr<i2p::Endpoint>& endpoint : dropped) {
        endpoint->stop();
    }
}

}  // namespace bazarish::gateway
