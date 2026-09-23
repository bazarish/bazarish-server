// Bazarish project (c) 2026
// A live check against a real gateway, not part of ctest: it needs one running
// and reachable. Takes the address an operator hands out.
//
//   gateway_smoke https://host[:port]/<path>#<token>
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

    i2p::EndpointConfig endpointConfig{router.generateKeys()};
    endpointConfig.privacy = i2p::Privacy::eMinimal;
    endpointConfig.published = true;
    const std::shared_ptr<i2p::Endpoint> mine = router.createEndpoint(endpointConfig);
    std::printf("[smoke] the gateway minted %s\n", mine->routingHost().c_str());

    // Tunnels are the gateway's router's work, so this is the one thing worth
    // waiting for: it says the borrowed router is really on the network.
    const bool ready = mine->waitReady(std::chrono::seconds(180));
    std::printf("[smoke] %s after %s\n", ready ? "it has tunnels" : "still no tunnels",
        ready ? "the wait" : "three minutes");
    std::printf("[smoke] the gateway's router knows %d routers, %d floodfills\n",
        router.knownRouters(), router.floodfills());

    mine->stop();
    router.stop();
    std::printf("[smoke] %s\n", ready ? "ok" : "reachable, but its router has no tunnels yet");
    return ready ? 0 : 1;
}
