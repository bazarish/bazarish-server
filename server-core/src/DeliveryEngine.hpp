// Bazarish project (c) 2026
#pragma once

#include "Storage.hpp"

#include <bazarish/Crypto.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace bazarish::server {

struct DeliveryEngineOptions {
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
    std::function<void(const std::string& user)> onDelivered;
};

class DeliveryEngine {
public:
    DeliveryEngine(Storage& storage, std::string serverFingerprint,
        std::shared_ptr<const Key> sealingKey, DeliveryEngineOptions options);

    struct Outcome {
        bool delivered = false;
        std::string errorCode;
        std::string errorMessage;
        std::string deliveryId;
    };

    Outcome deliver(const Bytes& sealed, const Bytes& payload, std::int64_t now,
        const Key& sealingKey, const std::string& owner = {});

    const std::string& serverFingerprint() const;
    const Key& sealingKey() const;

private:
    Storage& storage_;
    const std::string serverFingerprint_;
    const std::shared_ptr<const Key> sealingKey_;
    const DeliveryEngineOptions options_;
};

}  // namespace bazarish::server
