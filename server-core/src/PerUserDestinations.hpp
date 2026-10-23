// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "Federation.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>
#include <Restart.hpp>
#include <TlsPipe.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {

// A destination goes down this long before its delegation ends: from the first second of the day
// it has no key for, the lease set its router builds cannot be signed and brings the router down.
inline constexpr std::int64_t kLapseLeadSeconds = 60;

class PerUserDestinations {
public:
    PerUserDestinations(bazarish::i2p::Router* router, DeliveryEngine& engine,
        std::filesystem::path stateDir, bazarish::i2p::Privacy privacy,
        int tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity);
    ~PerUserDestinations();

    PerUserDestinations(const PerUserDestinations&) = delete;
    PerUserDestinations& operator=(const PerUserDestinations&) = delete;

    struct Assignment {
        std::string dest;
        std::shared_ptr<Key> sealingKey;
        std::string state = "none";
    };

    Assignment provision(const std::string& userFp, const std::string& transientB64,
        std::int64_t expiresUnix);

    // Stops serving the address and keeps its keys, which change only with the address.
    void takeOffline(const std::string& userFp);
    // The account is gone: its address record and keys go with it.
    void forget(const std::string& userFp);

    void reloadPersisted(std::int64_t now);

    std::size_t sweepExpired(std::int64_t now);
    std::chrono::seconds nextSweepIn(std::int64_t now) const;

    void setGetCard(GetCardFn getCard);
    void setServedChanged(std::function<void()> changed);
    std::vector<std::string> served() const;
    bool serveDirect(const std::string& to, const std::string& from, TlsPipe& pipe);
    std::shared_ptr<bazarish::i2p::Endpoint> endpointForDest(const std::string& dest) const;

    std::size_t size() const;

    Assignment assignmentFor(const std::string& userFp, std::int64_t now) const;
    std::int64_t heldUntil(const std::string& userFp) const;


private:
    struct Destination {
        std::atomic<bool> running{true};
        // Several: one accepted stream must not hold up the next.
        std::vector<std::thread> workers;
        std::string transientB64;
        std::int64_t expiresUnix = 0;
        std::shared_ptr<Key> sealingKey;
        std::shared_ptr<Key> signingKey;
        std::string dest;
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
    };

    void bringUp(const std::string& userFp, const std::string& transientB64,
        std::int64_t expiresUnix, const std::string& sealingKeyPem,
        const std::string& signingKeyPem);
    void teardownLocked(const std::string& userFp);
    void reapRetired();
    static Assignment assignedLocked(const Destination& destination, std::int64_t now);
    void announceServed() const;
    void reloadLocked(std::int64_t now);
    void serveLoop(Destination* destination, const std::string& userFp);
    void startWatchdog();
    void watchStream(const std::shared_ptr<bazarish::i2p::Stream>& stream);
    void unwatchStream(const bazarish::i2p::Stream* stream);
    void startSweeper();
    std::chrono::seconds nextSweepInLocked(std::int64_t now) const;
    std::filesystem::path pathFor(const std::string& userFp) const;
    std::filesystem::path destsDir() const;

    bazarish::i2p::Router* const router_;
    DeliveryEngine& engine_;
    const std::filesystem::path stateDir_;
    const bazarish::i2p::Privacy privacy_;
    const int tunnelQuantity_;
    GetCardFn getCard_;
    std::function<void()> servedChanged_;
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Destination>> dests_;
    std::thread sweeper_;
    std::condition_variable sweepDue_;
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
