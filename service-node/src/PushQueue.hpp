// Bazarish project (c) 2026
#pragma once

#include "OperatorPush.hpp"
#include "SubscriptionStore.hpp"
#include "UserLocks.hpp"

#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::service {

// Values stay in the account record, so a delivery always carries the latest one.
class PushQueue {
public:
    struct Unsent {
        bool quota = false;
        bool card = false;
        bool addressDown = false;

        bool any() const { return quota || card || addressDown; }
    };

    struct Delivery {
        std::function<PushOutcome(const std::string& user, std::uint64_t quotaBytes)> quota;
        std::function<PushOutcome(const std::string& user)> card;
        std::function<PushOutcome(const std::string& user)> takeDownAddress;
    };

    PushQueue(const std::filesystem::path& root, SubscriptionStore& store, UserLocks& locks,
        Delivery delivery);
    ~PushQueue();

    PushQueue(const PushQueue&) = delete;
    PushQueue& operator=(const PushQueue&) = delete;

    // These four are called with the account's lock held.
    void record(const std::string& user, Unsent changed);
    void settled(const std::string& user, Unsent confirmed);
    Unsent deliver(const std::string& user);
    Unsent unsent(const std::string& user) const;

    void serverReached();

private:
    struct Attempt {
        Unsent left;
        bool delivered = false;
        bool unreachable = false;
    };

    std::filesystem::path unsentPath(const std::string& user) const;
    void write(const std::string& user, Unsent left);
    std::vector<std::string> unsentUsers() const;
    Attempt attempt(const std::string& user);
    void drain();
    void run();

    std::filesystem::path root_;
    SubscriptionStore& store_;
    UserLocks& locks_;
    const Delivery delivery_;
    std::mutex mutex_;
    std::condition_variable wake_;
    bool reached_ = false;
    bool stopping_ = false;
    std::thread worker_;
};

}  // namespace bazarish::service
