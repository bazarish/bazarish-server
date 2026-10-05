// Bazarish project (c) 2026
#pragma once

#include "TestUtil.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace bazarish::gateway {

namespace {

constexpr std::size_t kRelayBufferBytes = 16384;
constexpr int kRelayBacklog = 16;

class Relay {
public:
    explicit Relay(const int to)
        : to_(to)
    {
        listen_ = ::socket(AF_INET, SOCK_STREAM, 0);
        CHECK(listen_ >= 0);
        const int one = 1;
        const int reusable
            = ::setsockopt(listen_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = ::inet_addr("127.0.0.1");
        const int bound = ::bind(listen_, reinterpret_cast<sockaddr*>(&address), sizeof address);
        socklen_t length = sizeof address;
        const int named = ::getsockname(listen_, reinterpret_cast<sockaddr*>(&address), &length);
        const int listening = ::listen(listen_, kRelayBacklog);
        CHECK(reusable == 0);
        CHECK(bound == 0);
        CHECK(named == 0);
        CHECK(listening == 0);
        port_ = ntohs(address.sin_port);
        accepter_ = std::thread([this]() { accepting(); });
    }

    ~Relay()
    {
        running_.store(false);
        ::shutdown(listen_, SHUT_RDWR);
        ::close(listen_);
        if (accepter_.joinable()) {
            accepter_.join();
        }
        cutAll();
        for (std::thread& pump : pumps_) {
            if (pump.joinable()) {
                pump.join();
            }
        }
    }

    Relay(const Relay&) = delete;
    Relay& operator=(const Relay&) = delete;

    int port() const { return port_; }

    std::size_t connections() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return pairs_.size();
    }

    void hold(const bool refusing) { refusing_.store(refusing); }

    void stall(const bool holding) { stalling_.store(holding); }

    void cut(const std::size_t which)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        CHECK(which < pairs_.size());
        ::shutdown(pairs_[which].first, SHUT_RDWR);
        ::shutdown(pairs_[which].second, SHUT_RDWR);
    }

private:
    void cutAll()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [in, out] : pairs_) {
            ::shutdown(in, SHUT_RDWR);
            ::shutdown(out, SHUT_RDWR);
        }
    }

    void accepting()
    {
        while (running_.load()) {
            const int in = ::accept(listen_, nullptr, nullptr);
            if (in < 0) {
                return;
            }
            if (refusing_.load()) {
                ::close(in);
                continue;
            }
            const int out = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = ::inet_addr("127.0.0.1");
            address.sin_port = htons(static_cast<std::uint16_t>(to_));
            if (out < 0
                || ::connect(out, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0) {
                ::close(in);
                ::close(out);
                continue;
            }
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                pairs_.emplace_back(in, out);
            }
            pumps_.emplace_back([this, in, out]() { pump(in, out, false); });
            pumps_.emplace_back([this, in, out]() { pump(out, in, true); });
        }
    }

    void pump(const int from, const int to, const bool stallable)
    {
        std::vector<char> buffer(kRelayBufferBytes);
        for (;;) {
            const ssize_t got = ::recv(from, buffer.data(), buffer.size(), 0);
            if (got <= 0) {
                ::shutdown(to, SHUT_RDWR);
                return;
            }
            while (stallable && stalling_.load() && running_.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            ssize_t sent = 0;
            while (sent < got) {
                const ssize_t wrote = ::send(to, buffer.data() + sent,
                    static_cast<std::size_t>(got - sent), MSG_NOSIGNAL);
                if (wrote <= 0) {
                    ::shutdown(from, SHUT_RDWR);
                    return;
                }
                sent += wrote;
            }
        }
    }

    int to_;
    int listen_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::atomic<bool> refusing_{false};
    std::atomic<bool> stalling_{false};
    std::thread accepter_;
    std::vector<std::thread> pumps_;
    mutable std::mutex mutex_;
    std::vector<std::pair<int, int>> pairs_;
};

}  // namespace

}  // namespace bazarish::gateway
