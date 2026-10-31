// Bazarish project (c) 2026
#pragma once

#include "ContactSources.hpp"
#include "Storage.hpp"

#include <RateLimiter.hpp>

#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>

#include <cstdint>
#include <functional>
#include <string>

namespace bazarish::server {

inline constexpr std::int64_t kContactSourceMemorySeconds = kSecondsPerDay;
inline constexpr std::size_t kMailPerPassPerMinute = 120;

struct DeliveryEngineOptions {
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
    std::function<void(const std::string& user)> onDelivered;
};

class DeliveryEngine {
public:
    DeliveryEngine(Storage& storage, DeliveryEngineOptions options);

    struct Outcome {
        bool delivered = false;
        std::string errorCode;
        std::string errorMessage;
        std::string deliveryId;
    };

    Outcome deliver(const Bytes& sealed, const Bytes& payload, std::int64_t now,
        const Key& sealingKey, const std::string& owner, const std::string& peer);

private:
    Storage& storage_;
    const DeliveryEngineOptions options_;
    ContactSources contactSources_;
    RateLimiter mailPerPass_;
};

}  // namespace bazarish::server
