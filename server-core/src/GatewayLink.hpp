// Bazarish project (c) 2026
#pragma once

#include <TlsPipe.hpp>

#include <bazarish/Tls.hpp>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {

class GatewayLink {
public:
    using Listed = std::function<std::vector<std::string>()>;
    using Serve = std::function<bool(const std::string& to, const std::string& from, TlsPipe&)>;

    GatewayLink(tls::Credential own, std::vector<std::string> gateways, Listed listed,
        Serve serve);
    ~GatewayLink();
    GatewayLink(const GatewayLink&) = delete;
    GatewayLink& operator=(const GatewayLink&) = delete;

    int start(const std::string& host, int port);
    void stop();
    void setGateways(std::vector<std::string> gateways);
    void servedChanged();

private:
    struct Impl;
    struct Handler {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    void accept();
    void handle(int family, int socket);
    void watch(const std::shared_ptr<TlsPipe>& pipe);
    bool admitted(const std::string& pin) const;
    void reap(bool all);

    const tls::Credential own_;
    const Listed listed_;
    const Serve serve_;
    std::unique_ptr<Impl> impl_;
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::vector<std::string> gateways_;
    std::uint64_t version_ = 1;
    std::list<std::weak_ptr<TlsPipe>> open_;
    std::list<Handler> handlers_;
    std::atomic<bool> running_{false};
    std::thread loop_;
};

}  // namespace bazarish::server
