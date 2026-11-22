// Bazarish project (c) 2026
#pragma once

#include "DeliveryEngine.hpp"
#include "Federation.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/I2p.hpp>
#include <Restart.hpp>
#include <TlsPipe.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::server {

class PerUserDestinations {
public:
    // Without a router it only keeps the records.
    PerUserDestinations(std::optional<std::reference_wrapper<bazarish::i2p::Router>> router,
        DeliveryEngine& engine,
        std::filesystem::path stateDir, bazarish::i2p::Privacy privacy, GetCardFn getCard,
        std::function<void()> servedChanged);
    ~PerUserDestinations();

    PerUserDestinations(const PerUserDestinations&) = delete;
    PerUserDestinations& operator=(const PerUserDestinations&) = delete;

    struct Assignment {
        std::string dest;
        std::shared_ptr<Key> sealingKey;
        std::string state = "none";
        std::int64_t transientExpires = 0;
    };

    Assignment provision(const std::string& userFp, const std::string& transientB64,
        std::int64_t expiresUnix, const std::string& sealingKeyPem,
        const std::string& signingKeyPem);

    void forget(const std::string& userFp);

    void reloadPersisted(std::int64_t now);

    std::size_t sweepExpired(std::int64_t now);
    std::chrono::seconds nextSweepIn(std::int64_t now) const;

    std::vector<std::string> served() const;

    // i2pd ends a lease before this, so an exchange that has not finished is not going to.
    static constexpr int kServeDeadlineSeconds = 45;

    struct DirectTarget {
        std::string owner;
        std::shared_ptr<Key> sealing;
        std::shared_ptr<Key> signing;
    };
    std::optional<DirectTarget> directTargetFor(const std::string& to) const;

    // A destination this server service serves, answered without the frame leaving the host.
    template <class Pipe>
    bool serveDirect(const std::string& to, const std::string& from, Pipe& pipe)
    {
        const std::optional<DirectTarget> target = directTargetFor(to);
        if (!target.has_value()) {
            return false;
        }
        pipe.closeAfter(std::chrono::seconds(kServeDeadlineSeconds));
        federationServeOnce(pipe, engine_, nowSeconds(), from, *target->sealing, target->owner,
            getCard_, ackSignerFor(target->signing));
        return true;
    }

    std::size_t size() const;

    Assignment assignmentFor(const std::string& userFp, std::int64_t now) const;
    std::int64_t heldUntil(const std::string& userFp) const;

    // Told whenever what assignmentFor answers for a user may have changed.
    void watchUsers(std::function<void(const std::string& user)> changed);

private:
    struct Destination {
        std::atomic<bool> running{true};
        std::vector<std::thread> workers;
        std::string transientB64;
        std::int64_t expiresUnix = 0;
        std::shared_ptr<Key> sealingKey;
        std::shared_ptr<Key> signingKey;
        std::string dest;
        std::shared_ptr<bazarish::i2p::Endpoint> endpoint;
        std::atomic<bool> wasReady{false};
        std::unique_ptr<bazarish::i2p::EndpointWatch> readyWatch;
    };

    static SignAckFn ackSignerFor(std::shared_ptr<Key> signingKey);
    void bringUp(const std::string& userFp, const std::string& transientB64,
        std::int64_t expiresUnix, const std::string& sealingKeyPem,
        const std::string& signingKeyPem);
    void teardownLocked(const std::string& userFp);
    void reapRetired();
    static Assignment assignedLocked(const Destination& destination, std::int64_t now);
    void announceServed() const;
    void tellUser(const std::string& userFp) const;
    void reloadLocked(std::int64_t now);
    void serveLoop(Destination& destination, const std::string& userFp);
    void startWatchdog();
    void watchStream(const std::shared_ptr<bazarish::i2p::Stream>& stream);
    void unwatchStream(const std::shared_ptr<bazarish::i2p::Stream>& stream);
    void startSweeper();
    std::chrono::seconds nextSweepInLocked(std::int64_t now) const;
    std::filesystem::path pathFor(const std::string& userFp) const;
    std::filesystem::path destsDir() const;

    const std::optional<std::reference_wrapper<bazarish::i2p::Router>> router_;
    DeliveryEngine& engine_;
    const std::filesystem::path stateDir_;
    const bazarish::i2p::Privacy privacy_;
    const GetCardFn getCard_;
    const std::function<void()> servedChanged_;
    mutable std::mutex userWatchMutex_;
    std::function<void(const std::string& user)> userChanged_;
    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Destination>> dests_;
    std::thread sweeper_;
    std::condition_variable sweepDue_;
    std::thread watchdog_;
    std::mutex retiringMutex_;
    std::vector<std::shared_ptr<Destination>> retiring_;
    std::mutex watchMutex_;
    std::vector<std::pair<std::weak_ptr<bazarish::i2p::Stream>,
        std::chrono::steady_clock::time_point>>
        watched_;
    bazarish::StopGate stopGate_;
};

}  // namespace bazarish::server
