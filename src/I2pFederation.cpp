// Bazarish project (c) 2026
#include "I2pFederation.hpp"

#include "Federation.hpp"

#include <ctime>
#include <stdexcept>

namespace bazarish::server {

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace

I2pFederation::I2pFederation(
    SamSession& session, DeliveryEngine& engine, FederationRateLimiter* const limiter)
    : session_(session)
    , engine_(engine)
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
            federationServeOnce(stream, engine_, nowSeconds(), peer, limiter_, nullptr, getCard_);
        } catch (const std::exception&) {
            // A failed accept/serve (peer reset, timeout, malformed
            // request) must not take the loop down; the next inbound
            // connection gets a fresh accept.
        }
    }
}

RemoteDeliveryResult I2pFederation::deliver(
    const std::string& toDest, const Bytes& sealed, const Bytes& payload)
{
    RemoteDeliveryResult result;
    // Routing is by destination: toDest is the recipient's I2P destination, so
    // dial it directly — no server-fingerprint resolution. An unreachable
    // destination (e.g. its leaseset has not published yet) leaves the message
    // on the caller for retry.
    try {
        SamStream stream = session_.connect(toDest);
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
    return [this](const std::string& toDest, const Bytes& sealed, const Bytes& payload) {
        return deliver(toDest, sealed, payload);
    };
}

void I2pFederation::setGetCard(GetCardFn getCard)
{
    getCard_ = std::move(getCard);
}

RemoteFetchResult I2pFederation::fetchOverI2p(
    const std::string& toDest, const std::string& op, const Bytes& sealed)
{
    RemoteFetchResult result;
    // Routing is by destination: dial toDest directly and relay the opaque
    // sealed fetch. An unreachable destination leaves the lookup to the caller
    // (the client retries, like a first delivery).
    try {
        SamStream stream = session_.connect(toDest);
        const FederationFetchResult fetched = federationSendFetch(stream, op, sealed);
        result.reachable = true;
        result.ok = fetched.ok;
        result.sealed = fetched.sealed;
        result.errorCode = fetched.errorCode;
        result.errorMessage = fetched.errorMessage;
    } catch (const std::exception&) {
        result.reachable = false;
    }
    return result;
}

RemoteFetchFn I2pFederation::asRemoteFetchFn()
{
    return [this](const std::string& toDest, const std::string& op, const Bytes& sealed) {
        return fetchOverI2p(toDest, op, sealed);
    };
}

}  // namespace bazarish::server
