// Bazarish project (c) 2026
#include "I2pFederation.hpp"

#include <bazarish/Errors.hpp>
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
