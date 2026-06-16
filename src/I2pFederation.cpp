// Bazarish project (c) 2026
#include "I2pFederation.hpp"

#include "Federation.hpp"

#include <ctime>
#include <stdexcept>
#include <utility>

namespace bazarish::server {

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace

I2pFederation::I2pFederation(SamSession& session, DeliveryEngine& engine, Resolver resolve,
    FederationRateLimiter* const limiter)
    : session_(session)
    , engine_(engine)
    , resolve_(std::move(resolve))
    , limiter_(limiter)
    , running_(false)
{
}

I2pFederation::~I2pFederation()
{
    stop();
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }
}

void I2pFederation::start()
{
    running_ = true;
    acceptThread_ = std::thread([this]() { acceptLoop(); });
}

void I2pFederation::stop()
{
    running_ = false;
}

void I2pFederation::acceptLoop()
{
    while (running_) {
        try {
            std::string peer;
            SamStream stream = session_.accept(peer);
            federationServeOnce(stream, engine_, nowSeconds(), peer, limiter_);
        } catch (const std::exception&) {
            // A failed accept/serve (peer reset, timeout, malformed
            // request) must not take the loop down; the next inbound
            // connection gets a fresh accept.
        }
    }
}

RemoteDeliveryResult I2pFederation::deliver(
    const std::string& toServer, const Bytes& sealed, const Bytes& payload)
{
    RemoteDeliveryResult result;
    const std::optional<std::string> destination = resolve_(toServer);
    if (!destination.has_value()) {
        // No known route to this server: the caller keeps the message
        // locally, exactly like an unreachable server.
        result.reachable = false;
        return result;
    }
    try {
        SamStream stream = session_.connect(destination.value());
        const FederationDeliverResult delivered
            = federationSendDeliver(stream, sealed, payload);
        result.reachable = true;
        result.delivered = delivered.delivered;
        result.errorCode = delivered.errorCode;
        result.errorMessage = delivered.errorMessage;
    } catch (const std::exception&) {
        result.reachable = false;
    }
    return result;
}

RemoteDeliverFn I2pFederation::asRemoteDeliverFn()
{
    return [this](const std::string& toServer, const Bytes& sealed, const Bytes& payload) {
        return deliver(toServer, sealed, payload);
    };
}

}  // namespace bazarish::server
