// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "Federation.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>
#include <Restart.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {

class PerUserDestinations {
public:
    PerUserDestinations(bazarish::i2p::Router* router, DeliveryEngine& engine,
        std::filesystem::path stateDir, bazarish::i2p::Privacy privacy,
        int tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity,
        RateLimiter* limiter = nullptr);
    ~PerUserDestinations();

    PerUserDestinations(const PerUserDestinations&) = delete;
    PerUserDestinations& operator=(const PerUserDestinations&) = delete;

    void provision(const std::string& userFp, const std::string& transientB64,
        std::int64_t expiresUnix);

    void revoke(const std::string& userFp);

    void reloadPersisted(std::int64_t now);

    std::size_t sweepExpired(std::int64_t now);

    void setGetCard(GetCardFn getCard);
    std::shared_ptr<bazarish::i2p::Endpoint> endpointForDest(const std::string& dest) const;

    std::size_t size() const;

    struct Assignment {
        std::string dest;
        std::shared_ptr<Key> sealingKey;
        std::string state = "none";
    };
    Assignment assignmentFor(const std::string& userFp, std::int64_t now) const;

    std::string prepareServingKey(const std::string& userFp);
    bool commitServingKey(const std::string& userFp);

private:
    struct Destination {
        std::atomic<bool> running{true};
        // Several: one accepted stream must not hold up the next.
        std::vector<std::thread> workers;
        std::string transientB64;
        std::int64_t expiresUnix = 0;
        std::shared_ptr<Key> sealingKey;
        std::shared_ptr<Key> pendingSealingKey;
        std::shared_ptr<Key> signingKey;
        std::string dest;
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
    };

    void bringUp(const std::string& userFp, const std::string& transientB64,
        std::int64_t expiresUnix, const std::string& sealingKeyPem,
        const std::string& signingKeyPem);
    // Takes the destination out of service and hands its threads to reapRetired.
    void teardownLocked(const std::string& userFp);
    void reapRetired();
    void serveLoop(Destination* destination, const std::string& userFp);
    void startWatchdog();
    void watchStream(const std::shared_ptr<bazarish::i2p::Stream>& stream);
    void unwatchStream(const bazarish::i2p::Stream* stream);
    void startSweeper();
    std::filesystem::path pathFor(const std::string& userFp) const;
    std::filesystem::path destsDir() const;

    bazarish::i2p::Router* const router_;
    DeliveryEngine& engine_;
    const std::filesystem::path stateDir_;
    const bazarish::i2p::Privacy privacy_;
    const int tunnelQuantity_;
    RateLimiter* const limiter_;
    GetCardFn getCard_;
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Destination>> dests_;
    std::thread sweeper_;
    std::thread watchdog_;
    std::mutex retiringMutex_;
    std::vector<std::unique_ptr<Destination>> retiring_;
    std::mutex watchMutex_;
    std::vector<std::pair<std::weak_ptr<bazarish::i2p::Stream>,
        std::chrono::steady_clock::time_point>>
        watched_;
    bazarish::StopGate stopGate_;
};

}  // namespace bazarish::server
