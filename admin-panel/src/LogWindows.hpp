// Bazarish project (c) 2026
#pragma once

#include "Config.hpp"

#include <bazarish/Tls.hpp>
#include <bazarish/WebSocket.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace bazarish {
class Identity;
}

namespace bazarish::admin {

inline constexpr std::size_t kMaxLogWindows = 8;

struct LogWindow {
    ServiceEntry service;
    std::string path;
    std::uint64_t after = 0;
    std::string instance;
    std::function<bool()> live;
};

void refuseLogWindow(http::Socket& socket, const std::string& message);

class LogWindows {
public:
    LogWindows(const Identity& identity, tls::Credential credential);

    LogWindows(const LogWindows&) = delete;
    LogWindows& operator=(const LogWindows&) = delete;

    void open(const boost::asio::any_io_executor& executor, const http::SocketPtr& socket,
        LogWindow window);
    std::size_t count() const;

private:
    const Identity& identity_;
    const tls::Credential credential_;
    const std::shared_ptr<std::atomic<std::size_t>> open_;
};

}  // namespace bazarish::admin
