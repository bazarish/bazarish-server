// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/Log.hpp>

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <exception>
#include <mutex>
#include <thread>

namespace bazarish::facade {

inline constexpr std::size_t kPumpBufferBytes = 32 * 1024;
inline constexpr std::chrono::seconds kDrainFor{60};

// The fd stays the caller's to close, so a stop from outside can shut it while this runs.
template <typename Stream>
void relay(Stream& stream, const int fd)
{
    std::size_t fromClient = 0;
    std::size_t toClient = 0;
    std::mutex closing;
    std::condition_variable closed;
    bool clientClosed = false;
    std::thread inbound([&stream, fd, &fromClient, &closing, &closed, &clientClosed]() {
        std::array<unsigned char, kPumpBufferBytes> buffer{};
        bool open = true;
        while (open) {
            const std::size_t read = stream.readSome(buffer);
            if (read == 0) {
                break;
            }
            fromClient += read;
            std::size_t written = 0;
            while (written < read) {
                const ssize_t n
                    = ::send(fd, &buffer[written], read - written, MSG_NOSIGNAL);
                if (n <= 0) {
                    open = false;
                    break;
                }
                written += static_cast<std::size_t>(n);
            }
        }
        ::shutdown(fd, SHUT_WR);
        {
            const std::lock_guard<std::mutex> lock(closing);
            clientClosed = true;
        }
        closed.notify_one();
    });

    std::array<unsigned char, kPumpBufferBytes> buffer{};
    while (true) {
        const ssize_t n = ::read(fd, buffer.data(), buffer.size());
        if (n <= 0) {
            break;
        }
        try {
            stream.writeAll(ByteView(buffer).first(static_cast<std::size_t>(n)));
            toClient += static_cast<std::size_t>(n);
        } catch (const std::exception& error) {
            bazarish::log::debug("i2p relay: write to client failed: {}", error.what());
            break;
        }
    }
    {
        std::unique_lock<std::mutex> lock(closing);
        closed.wait_for(lock, kDrainFor, [&clientClosed]() { return clientClosed; });
    }
    stream.close();
    ::shutdown(fd, SHUT_RD);
    inbound.join();
    bazarish::log::debug("i2p relay done: {} bytes in, {} bytes out", fromClient, toClient);
}

}  // namespace bazarish::facade
