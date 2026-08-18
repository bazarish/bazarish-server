// Bazarish project (c) 2026
#include "I2pFederation.hpp"

#include <bazarish/Log.hpp>

#include "Federation.hpp"
#include "WarmDestPool.hpp"

#include <array>
#include <chrono>
#include <ctime>
#include <stdexcept>

namespace bazarish::server {

namespace {

// How long a freshly built one-time destination may take to publish before a
// discovery fetch gives up (the warm pool normally hides this entirely).
constexpr int kOneTimeDestReadySeconds = 120;
// How long to wait for the target destination to answer a dial.
constexpr int kFetchDialSeconds = 60;

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
    phase("dialing");  // building the tunnel + dialing the recipient's leaseset
    try {
        auto stream = from.connect(toDest, std::chrono::seconds(60));
        if (!stream) {
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
    } catch (const std::exception& error) {
        // The sender falls back to its own retry; losing the ack silently would
        // leave a delivery looking undelivered with nothing to explain it.
        bazarish::log::warn("delivered-ack not sent: {}", error.what());
    }
}

I2pFetch::I2pFetch(bazarish::i2p::Router& router, WarmDestPool* pool)
    : router_(router)
    , warmPool_(pool)
{
}

RemoteFetchResult I2pFetch::fetchOverI2p(
    const std::string& toDest, const std::string& op, const Bytes& sealed)
{
    RemoteFetchResult result;
    // Routing is by destination: dial toDest directly and relay the opaque
    // sealed fetch. An unreachable destination leaves the lookup to the caller
    // (the client retries, like a first delivery).
    //
    // Always from a single-use transient destination - the server has no address
    // of its own to dial from. A warm one costs nothing; without one, build it
    // here and pay the tunnel wait the pool exists to avoid.
    std::shared_ptr<bazarish::i2p::Endpoint> oneTime = warmPool_ ? warmPool_->acquire() : nullptr;
    if (!oneTime) {
        try {
            oneTime = router_.createEndpoint(bazarish::i2p::EndpointConfig{
                bazarish::i2p::Keys::generate(), bazarish::i2p::LeaseSetKind::eEncrypted,
                bazarish::i2p::Privacy::eMax, bazarish::i2p::kDefaultTunnelQuantity, false});
            if (!oneTime->waitReady(std::chrono::seconds(kOneTimeDestReadySeconds))) {
                result.reachable = false;
                return result;
            }
        } catch (const std::exception&) {
            result.reachable = false;
            return result;
        }
    }
    try {
        auto stream = oneTime->connect(toDest, std::chrono::seconds(kFetchDialSeconds));
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

RemoteFetchFn I2pFetch::asRemoteFetchFn()
{
    return [this](const std::string& toDest, const std::string& op, const Bytes& sealed) {
        return fetchOverI2p(toDest, op, sealed);
    };
}

}  // namespace bazarish::server
