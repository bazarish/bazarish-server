// Bazarish project (c) 2026
#include "I2pFederation.hpp"

#include "Federation.hpp"
#include "WarmDestPool.hpp"

#include <bazarish/Log.hpp>

#include <algorithm>
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
    const Bytes& sealed, const Bytes& payload, const FederationPhaseFn& onPhase)
{
    RemoteDeliveryResult result;
    const auto phase = [&onPhase](const char* p) {
        if (onPhase) {
            onPhase(p);
        }
    };
    // Routing is by destination: dial the recipient's serving dest directly, FROM
    // the sender's serving endpoint. An unreachable destination (e.g. its leaseset
    // has not published yet) leaves the message on the caller for retry.
    //
    // DIAGNOSTIC (temporary): the delivery dials FROM the sender's serving (pool /
    // per-user) dest, whose tunnel state differs from the home dest used for card
    // fetch. Log the outcome so a stuck contact-request delivery is visible.
    const auto t0 = std::chrono::steady_clock::now();
    const auto elapsedMs = [t0]() -> long long {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0)
            .count();
    };
    const std::string dest12 = toDest.substr(0, std::min<std::size_t>(12, toDest.size()));
    bazarish::log::warn("fed-deliver dialing {}...", dest12);
    phase("dialing");  // building the tunnel + dialing the recipient's leaseset
    try {
        auto stream = from.connect(toDest, std::chrono::seconds(60));
        if (!stream) {
            bazarish::log::warn(
                "fed-deliver {} UNREACHABLE after {} ms (connect null - sender dest no tunnels?)",
                dest12, elapsedMs());
            result.reachable = false;
            return result;
        }
        phase("sending");  // tunnel up; pushing the sealed envelope
        const FederationDeliverResult delivered = federationSendDeliver(*stream, sealed, payload);
        phase("awaiting-ack");
        result.reachable = true;
        result.delivered = delivered.delivered;
        result.errorCode = delivered.errorCode;
        result.errorMessage = delivered.errorMessage;
        bazarish::log::warn("fed-deliver {} done in {} ms (delivered={}, err='{}')", dest12,
            elapsedMs(), delivered.delivered, delivered.errorCode);
    } catch (const std::exception& error) {
        bazarish::log::warn(
            "fed-deliver {} EXCEPTION after {} ms: {}", dest12, elapsedMs(), error.what());
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

void I2pFederation::setWarmPool(WarmDestPool* pool)
{
    warmPool_ = pool;
}

RemoteFetchResult I2pFederation::fetchOverI2p(
    const std::string& toDest, const std::string& op, const Bytes& sealed)
{
    RemoteFetchResult result;
    // Routing is by destination: dial toDest directly and relay the opaque
    // sealed fetch. An unreachable destination leaves the lookup to the caller
    // (the client retries, like a first delivery).
    //
    // Dial FROM a warm single-use transient dest when the pool has one, so the
    // lookup is anonymous (a fresh one-time dest per fetch, never reused, dropped
    // right after) and fast (its tunnels are already built). The dest lives only for
    // this call - it is released when `oneTime` goes out of scope below. When the
    // pool is empty (or absent) we fall back to the standing home endpoint.
    std::shared_ptr<bazarish::i2p::Endpoint> oneTime = warmPool_ ? warmPool_->acquire() : nullptr;
    bazarish::i2p::Endpoint& dialer = oneTime ? *oneTime : endpoint_;
    //
    // DIAGNOSTIC (temporary): time the i2p dial to the target dest and log where a
    // co-located loopback fetch stalls (leaseset lookup / tunnel build / connect).
    const auto t0 = std::chrono::steady_clock::now();
    const auto elapsedMs = [t0]() -> long long {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0)
            .count();
    };
    const std::string dest12 = toDest.substr(0, std::min<std::size_t>(12, toDest.size()));
    bazarish::log::warn(
        "fed-fetch[{}] dialing {} (from {})...", op, dest12, oneTime ? "warm one-time dest" : "home");
    try {
        auto stream = dialer.connect(toDest, std::chrono::seconds(60));
        if (!stream) {
            bazarish::log::warn(
                "fed-fetch[{}] {} UNREACHABLE after {} ms (connect returned null)", op, dest12,
                elapsedMs());
            result.reachable = false;
            return result;
        }
        bazarish::log::warn(
            "fed-fetch[{}] {} connected in {} ms; sending fetch", op, dest12, elapsedMs());
        const FederationFetchResult fetched = federationSendFetch(*stream, op, sealed);
        result.reachable = true;
        result.ok = fetched.ok;
        result.sealed = fetched.sealed;
        result.errorCode = fetched.errorCode;
        result.errorMessage = fetched.errorMessage;
        bazarish::log::warn("fed-fetch[{}] {} done in {} ms (ok={}, err='{}')", op, dest12,
            elapsedMs(), fetched.ok, fetched.errorCode);
    } catch (const std::exception& error) {
        bazarish::log::warn(
            "fed-fetch[{}] {} EXCEPTION after {} ms: {}", op, dest12, elapsedMs(), error.what());
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
