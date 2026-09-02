// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::facade {

// Serves the facade's API on I2P destinations of its own - the address clients
// are meant to use, and the only I2P address the server side publishes at all
// (federation runs on the users' own destinations, never a shared one).
//
// It parses no HTTP: an accepted stream is pumped verbatim to the facade's own
// local listener, so there is exactly one HTTP implementation and the secret
// base path, routing and streaming rules apply unchanged. The destination keys
// are persisted, because their b33 travels in the server descriptor and must
// survive a restart.
class I2pFront {
public:
    struct Options {
        // Where the destination keys live (one file per destination).
        std::filesystem::path stateDir;
        // The facade's own HTTP listener, which every stream is pumped to.
        std::string localHost = "127.0.0.1";
        int localPort = 0;
        // How many destinations to publish. More addresses let an operator hand
        // different clients different entry points; one is plenty to start.
        std::size_t destinations = 1;
        bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
        int tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity;
    };

    explicit I2pFront(Options options);
    ~I2pFront();

    I2pFront(const I2pFront&) = delete;
    I2pFront& operator=(const I2pFront&) = delete;

    // Brings the destinations up and starts accepting. Tunnels build in the
    // background, so this returns as soon as the addresses are known: the
    // routing hosts (".b32.i2p"), in creation order.
    std::vector<std::string> start();
    void stop();

private:
    void acceptLoop(const std::shared_ptr<bazarish::i2p::Endpoint>& endpoint);

    const Options options_;
    std::unique_ptr<bazarish::i2p::Router> router_;
    std::vector<std::shared_ptr<bazarish::i2p::Endpoint>> endpoints_;
    std::vector<std::thread> acceptThreads_;
    std::atomic<bool> running_{false};
    // Relays in flight. Each is a thread of its own, held for as long as the
    // client keeps its connection: unbounded, a burst of clients is a burst of
    // threads, and a facade that cannot make one dies where it stands.
    std::atomic<std::size_t> relays_{0};
};

}  // namespace bazarish::facade
