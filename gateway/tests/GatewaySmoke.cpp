// Bazarish project (c) 2026
#include "GatewayAddress.hpp"

#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>

using namespace bazarish;

namespace {

constexpr std::chrono::seconds kReadyWait{180};
constexpr std::chrono::seconds kStatusWait{2};
constexpr std::chrono::milliseconds kStatusPoll{100};

bool routedByGateway(const i2p::Router& router, const i2p::Endpoint& endpoint)
{
    const auto until = std::chrono::steady_clock::now() + kStatusWait;
    while (std::chrono::steady_clock::now() < until) {
        for (const i2p::LocalDestination& destination : router.localDestinations()) {
            if (destination.host == endpoint.routingHost() && destination.localRoute) {
                return true;
            }
        }
        std::this_thread::sleep_for(kStatusPoll);
    }
    return false;
}

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc != 2) {
        std::printf("usage: gateway_smoke https://host[:port]/<path>#<token>\n");
        return 2;
    }
    const std::optional<client::GatewayAddress> address
        = client::GatewayAddress::parse(argv[1]);
    if (!address.has_value()) {
        std::printf("[smoke] that is not a gateway address\n");
        return 1;
    }
    std::printf("[smoke] %s:%d, path %s\n", address->host.c_str(), address->port,
        address->path.c_str());

    const client::GatewayCheck reached = client::checkGateway(address.value(), std::string());
    if (!reached.ok) {
        std::printf("[smoke] not reachable: %s\n", reached.error.c_str());
        return 1;
    }
    std::printf("[smoke] answers a decoy; its key is %s\n", reached.pin.c_str());

    i2p::RouterConfig config;
    config.backend = i2p::Backend::eGateway;
    config.gatewayHost = address->host;
    config.gatewayPort = address->port;
    config.gatewayPath = address->path;
    config.gatewayToken = address->token;
    config.gatewayTls = address->tls;
    config.gatewayPin = reached.pin;
    i2p::Router router(config);
    router.start();
    std::printf("[smoke] session open, counters %s\n",
        router.capabilities().routerCounters ? "answered" : "refused");

    i2p::EndpointConfig endpointConfig;
    endpointConfig.privacy = i2p::Privacy::eMinimal;
    endpointConfig.published = true;
    const std::shared_ptr<i2p::Endpoint> mine = router.createEndpoint(endpointConfig);
    std::printf("[smoke] the gateway minted %s\n", mine->routingHost().c_str());

    const bool ready = mine->waitReady(kReadyWait);
    std::printf("[smoke] %s after %s\n", ready ? "it has tunnels" : "still no tunnels",
        ready ? "the wait" : "three minutes");
    std::printf("[smoke] the gateway's router knows %d routers, %d floodfills\n",
        router.knownRouters(), router.floodfills());

    i2p::EndpointConfig lookupConfig;
    lookupConfig.published = false;
    const auto askedAt = std::chrono::steady_clock::now();
    const std::shared_ptr<i2p::Endpoint> lookup = router.createEndpoint(lookupConfig);
    const bool warm = lookup->waitReady(kReadyWait);
    const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - askedAt);
    std::printf("[smoke] an unpublished stream destination %s after %lld ms\n",
        warm ? "had tunnels" : "still had none", static_cast<long long>(waited.count()));
    lookup->stop();

    const auto media = [&router]() {
        i2p::EndpointConfig config;
        config.privacy = i2p::Privacy::eMinimal;
        config.published = true;
        config.traffic = i2p::Traffic::eRaw;
        config.realtime = true;
        config.label = "Call media";
        return router.createEndpoint(config);
    };
    const std::shared_ptr<i2p::Endpoint> caller = media();
    const std::shared_ptr<i2p::Endpoint> callee = media();
    const std::string audio = "twenty milliseconds of nothing";
    constexpr int kBurst = 20;
    constexpr std::chrono::milliseconds kBurstGap{50};
    const auto carries = [&audio](i2p::Endpoint& from, i2p::Endpoint& to) {
        for (int frame = 0; frame < kBurst; ++frame) {
            from.sendRawDatagram(to.routingHost(), audio.data(), audio.size());
            if (to.receiveRawDatagram(kBurstGap).size() == audio.size()) {
                return true;
            }
        }
        return false;
    };
    const bool heard = carries(*caller, *callee);
    const bool answered = carries(*callee, *caller);
    std::printf("[smoke] media both ways: %s\n",
        heard && answered ? "heard" : (heard ? "one way only" : "nothing arrived"));
    std::printf("[smoke] media routed by the gateway itself: %s\n",
        routedByGateway(router, *caller) && routedByGateway(router, *callee) ? "yes" : "no");

    caller->stop();
    callee->stop();
    mine->stop();
    router.stop();
    const bool ok = ready && heard && answered;
    std::printf("[smoke] %s\n",
        ok ? "ok" : (ready ? "tunnels, but the media leg did not carry" : "no tunnels"));
    return ok ? 0 : 1;
}
