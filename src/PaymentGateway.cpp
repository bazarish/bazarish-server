// Bazarish project (c) 2026
#include "PaymentGateway.hpp"

#include "MockPaymentGateway.hpp"
#include "MoneroPaymentGateway.hpp"

#include <mutex>
#include <stdexcept>

namespace bazarish::service {

const char* toString(const PaymentState state)
{
    switch (state) {
        case PaymentState::kPending:
            return "pending";
        case PaymentState::kPaid:
            return "paid";
        case PaymentState::kConfirmed:
            return "confirmed";
        case PaymentState::kExpired:
            return "expired";
        case PaymentState::kFailed:
            return "failed";
    }
    return "unknown";
}

std::string paramOr(const std::map<std::string, std::string>& params, const std::string& key,
    const std::string& fallback)
{
    const auto it = params.find(key);
    return it != params.end() ? it->second : fallback;
}

std::string requireParam(const std::map<std::string, std::string>& params, const std::string& key)
{
    const auto it = params.find(key);
    if (it == params.end() || it->second.empty()) {
        throw std::runtime_error("payment gateway missing required parameter: " + key);
    }
    return it->second;
}

namespace {

std::mutex& registryMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::map<std::string, PaymentGatewayFactory>& registry()
{
    static std::map<std::string, PaymentGatewayFactory> entries;
    return entries;
}

// Registers the built-in backends exactly once. Built-ins are added through the
// registry (not a hard-coded switch) so a deployment can override any of them by
// registering the same type name before the first makePaymentGateway call.
// Caller must hold registryMutex().
void ensureBuiltins()
{
    static const bool kRegistered = []() {
        registry()["mock"] = makeMockPaymentGateway;
        registry()["monerod"] = makeMoneroPaymentGateway;
        return true;
    }();
    (void)kRegistered;
}

}  // namespace

void registerPaymentGateway(const std::string& type, PaymentGatewayFactory factory)
{
    const std::lock_guard<std::mutex> lock(registryMutex());
    ensureBuiltins();
    registry()[type] = std::move(factory);
}

std::unique_ptr<PaymentGateway> makePaymentGateway(const PaymentGatewayConfig& config)
{
    const std::lock_guard<std::mutex> lock(registryMutex());
    ensureBuiltins();
    const auto it = registry().find(config.type);
    if (it == registry().end()) {
        throw std::runtime_error("unknown payment gateway type: " + config.type);
    }
    return it->second(config.params);
}

}  // namespace bazarish::service
