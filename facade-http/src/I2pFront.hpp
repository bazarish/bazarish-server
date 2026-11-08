// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace bazarish::facade {

class I2pFront {
public:
    struct Options {
        std::filesystem::path stateDir;
        std::string localHost = "127.0.0.1";
        int localPort = 0;
        bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
        int tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity;
    };

    I2pFront(Options options, bazarish::i2p::Keys keys);
    ~I2pFront();

    I2pFront(const I2pFront&) = delete;
    I2pFront& operator=(const I2pFront&) = delete;

    void start();
    void stop();

private:
    struct Relay {
        std::thread thread;
        std::shared_ptr<bazarish::i2p::Stream> stream;
        int fd = -1;
        std::shared_ptr<std::atomic<bool>> finished;
    };

    void acceptLoop();
    // Joins the relays that are done, or all of them, cutting the rest short first.
    std::size_t reapRelays(bool all);

    const Options options_;
    const bazarish::i2p::Keys keys_;
    std::unique_ptr<bazarish::i2p::Router> router_;
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint_;
    std::thread acceptThread_;
    std::thread readyThread_;
    std::atomic<bool> running_{false};
    std::mutex relaysMutex_;
    std::list<Relay> relays_;
};

}  // namespace bazarish::facade
