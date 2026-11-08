// Bazarish project (c) 2026
#pragma once

#include <bazarish/Log.hpp>

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <thread>

namespace bazarish::facade {

inline constexpr std::size_t kPumpBufferBytes = 32 * 1024;
inline constexpr int kDrainMillis = 60000;
inline constexpr int kDrainPollMillis = 50;

// The fd stays the caller's to close, so a stop from outside can shut it while this runs.
template <typename Stream>
void relay(Stream& stream, const int fd)
{
    std::size_t fromClient = 0;
    std::size_t toClient = 0;
    std::atomic<bool> clientClosed{false};
    std::thread inbound([&stream, fd, &fromClient, &clientClosed]() {
        std::array<char, kPumpBufferBytes> buffer{};
        bool open = true;
        while (open) {
            const std::size_t read = stream.readSome(buffer.data(), buffer.size());
            if (read == 0) {
                break;
            }
            fromClient += read;
            std::size_t written = 0;
            while (written < read) {
                const ssize_t n
                    = ::send(fd, buffer.data() + written, read - written, MSG_NOSIGNAL);
                if (n <= 0) {
                    open = false;
                    break;
                }
                written += static_cast<std::size_t>(n);
            }
        }
        clientClosed = true;
        ::shutdown(fd, SHUT_WR);
    });

    std::array<char, kPumpBufferBytes> buffer{};
    while (true) {
        const ssize_t n = ::read(fd, buffer.data(), buffer.size());
        if (n <= 0) {
            break;
        }
        try {
            stream.writeAll(buffer.data(), static_cast<std::size_t>(n));
            toClient += static_cast<std::size_t>(n);
        } catch (const std::exception& error) {
            bazarish::log::debug("i2p relay: write to client failed: {}", error.what());
            break;
        }
    }
    for (int waited = 0; !clientClosed && waited < kDrainMillis; waited += kDrainPollMillis) {
        std::this_thread::sleep_for(std::chrono::milliseconds(kDrainPollMillis));
    }
    stream.close();
    ::shutdown(fd, SHUT_RD);
    inbound.join();
    bazarish::log::debug("i2p relay done: {} bytes in, {} bytes out", fromClient, toClient);
}

}  // namespace bazarish::facade
