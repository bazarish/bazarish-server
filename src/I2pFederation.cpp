// Bazarish project (c) 2026
#include "I2pFederation.hpp"

#include "Federation.hpp"

#include <array>
#include <chrono>
#include <ctime>
#include <stdexcept>

namespace bazarish::server {

namespace {

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace

RemoteDeliveryResult federationDeliver(bazarish::i2p::Endpoint& from, const std::string& toDest,
    const Bytes& sealed, const Bytes& payload)
{
    RemoteDeliveryResult result;
    // Routing is by destination: dial the recipient's serving dest directly, FROM
    // the sender's serving endpoint. An unreachable destination (e.g. its leaseset
    // has not published yet) leaves the message on the caller for retry.
    try {
        auto stream = from.connect(toDest, std::chrono::seconds(60));
        if (!stream) {
            result.reachable = false;
            return result;
        }
        const FederationDeliverResult delivered = federationSendDeliver(*stream, sealed, payload);
        result.reachable = true;
        result.delivered = delivered.delivered;
        result.errorCode = delivered.errorCode;
        result.errorMessage = delivered.errorMessage;
    } catch (const std::exception&) {
        result.reachable = false;
    }
    return result;
}

void federationSendAck(bazarish::i2p::Endpoint& from, const std::string& toDest,
    const std::string& messageId, const Bytes& signerPublicDer, const Bytes& signature)
{
    try {
        auto stream = from.connect(toDest, std::chrono::seconds(30));
        if (!stream) {
            return;
        }
        detail::writeFederationHeaderLine(
            *stream, buildFederationDeliveredAck(messageId, signerPublicDer, signature));
        // The receiver sends no reply; keep the stream open until it has read the
        // ack and closed (drain to EOF) so the single line is actually flushed.
        std::array<char, 64> buffer;
        while (stream->readSome(buffer.data(), buffer.size()) > 0) {
        }
    } catch (const std::exception&) {
    }
}

I2pFederation::I2pFederation(
    bazarish::i2p::Endpoint& endpoint, DeliveryEngine& engine, FederationRateLimiter* const limiter)
    : endpoint_(endpoint)
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
        std::string peer;
        auto stream = endpoint_.accept(peer, std::chrono::seconds(30));
        if (!stream) {
            continue;  // accept timeout / stop: re-check running
        }
        try {
            // The home endpoint serves discovery (op "card") only - never user
            // deliveries or acks, which live entirely on per-user serving dests.
            federationServeOnce(*stream, engine_, nowSeconds(), peer, limiter_, nullptr, getCard_);
        } catch (const std::exception&) {
            // A failed serve (peer reset, malformed request) must not take the
            // loop down; the next inbound connection gets a fresh accept.
        }
    }
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
        auto stream = endpoint_.connect(toDest, std::chrono::seconds(60));
        if (!stream) {
            result.reachable = false;
            return result;
        }
        const FederationFetchResult fetched = federationSendFetch(*stream, op, sealed);
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
