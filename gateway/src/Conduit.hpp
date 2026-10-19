// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>
#include <bazarish/Tls.hpp>

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

struct ServerLink {
    std::string host;
    int port = 0;
    std::string pin;

    friend bool operator==(const ServerLink&, const ServerLink&) = default;
};

std::unique_ptr<Conduit> overI2p(std::unique_ptr<i2p::Stream> stream);
std::unique_ptr<Conduit> overTls(const DirectRoute& route, std::chrono::seconds deadline);
std::unique_ptr<Conduit> overServer(const ServerLink& server, const tls::Credential& own,
    const std::string& to, const std::string& from, std::chrono::seconds deadline);

}  // namespace bazarish::gateway
