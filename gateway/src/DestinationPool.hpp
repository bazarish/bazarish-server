// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>

namespace bazarish::gateway {

class DestinationPool {
public:
    // A watching pool serves only requests that bring a reader key, and gives the key when taken.
    enum class Use { eGeneral, eWatching };
    DestinationPool(i2p::Router& router, i2p::EndpointConfig shape, std::size_t depth,
        Use use = Use::eGeneral);
    ~DestinationPool();
    DestinationPool(const DestinationPool&) = delete;
    DestinationPool& operator=(const DestinationPool&) = delete;

    bool fits(const i2p::EndpointConfig& wanted) const;
    std::shared_ptr<i2p::Endpoint> take(const i2p::EndpointConfig& wanted);
    std::size_t held() const;
    void stop();

private:
    i2p::Router& router_;
    const i2p::EndpointConfig shape_;
    const Use use_;
    mutable std::mutex mutex_;
    std::deque<std::shared_ptr<i2p::Endpoint>> held_;
};

}  // namespace bazarish::gateway
