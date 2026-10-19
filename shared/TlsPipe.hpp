// Bazarish project (c) 2026
#pragma once

#include <bazarish/Tls.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>

namespace bazarish::server {

// A byte stream over TLS between two services of one operator, each pinning the other's key.
class TlsPipe {
public:
    static std::unique_ptr<TlsPipe> dial(const std::string& host, int port,
        const std::string& pin, std::chrono::seconds deadline,
        const tls::Credential* own = nullptr);
    static std::unique_ptr<TlsPipe> serve(int protocolFamily, int socket,
        const tls::Credential& own, std::chrono::seconds deadline);

    ~TlsPipe();
    TlsPipe(const TlsPipe&) = delete;
    TlsPipe& operator=(const TlsPipe&) = delete;

    const std::string& peerPin() const;

    std::size_t readSome(void* buffer, std::size_t size);
    std::string readLine(std::size_t maxBytes);
    void writeAll(const void* data, std::size_t size);
    void close();
    void closeAfter(std::chrono::seconds wait);
    void keepOpen();
    void whenEnded(std::function<void()> ended);

private:
    struct Impl;
    explicit TlsPipe(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::server
