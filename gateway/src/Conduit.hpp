// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>

namespace bazarish::gateway {

class Conduit {
public:
    virtual ~Conduit() = default;

    virtual std::size_t readSome(void* buffer, std::size_t size) = 0;
    virtual void writeAll(const void* data, std::size_t size) = 0;
    virtual void close() = 0;
};

struct DirectRoute {
    std::string dest;
    std::string host;
    int port = 0;
    std::string pin;
};

std::unique_ptr<Conduit> overI2p(std::unique_ptr<i2p::Stream> stream);
std::unique_ptr<Conduit> overTls(const DirectRoute& route, std::chrono::seconds deadline);

}  // namespace bazarish::gateway
