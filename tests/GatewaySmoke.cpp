// Bazarish project (c) 2026
#include "GatewayAddress.hpp"

#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>

using namespace bazarish;

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

    const bool ready = mine->waitReady(std::chrono::seconds(180));
    std::printf("[smoke] %s after %s\n", ready ? "it has tunnels" : "still no tunnels",
        ready ? "the wait" : "three minutes");
    std::printf("[smoke] the gateway's router knows %d routers, %d floodfills\n",
        router.knownRouters(), router.floodfills());

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

    caller->stop();
    callee->stop();
    mine->stop();
    router.stop();
    const bool ok = ready && heard && answered;
    std::printf("[smoke] %s\n",
        ok ? "ok" : (ready ? "tunnels, but the media leg did not carry" : "no tunnels"));
    return ok ? 0 : 1;
}
