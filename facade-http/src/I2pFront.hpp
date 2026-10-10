// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <memory>
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

    explicit I2pFront(Options options);
    ~I2pFront();

    I2pFront(const I2pFront&) = delete;
    I2pFront& operator=(const I2pFront&) = delete;

    std::string start();
    void stop();

private:
    void acceptLoop();

    const Options options_;
    std::unique_ptr<bazarish::i2p::Router> router_;
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint_;
    std::thread acceptThread_;
    std::thread readyThread_;
    std::atomic<bool> running_{false};
    std::atomic<std::size_t> relays_{0};
};

}  // namespace bazarish::facade
