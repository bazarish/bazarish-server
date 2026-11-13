// Bazarish project (c) 2026
#pragma once

#include "Federation.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Devices.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace bazarish::server {

struct NodeAddress {
    std::string host;
    int port = 0;
    bool tls = true;
    std::string pin;
};

class NodeCards {
public:
    static constexpr std::chrono::seconds kTimeout{5};
    static constexpr std::int64_t kCacheSeconds = 60;

    NodeCards(NodeAddress node, std::shared_ptr<const Identity> identity);

    std::optional<HeldCard> card(const std::string& user);
    // The devices the account's card lists, and its newest revocation list.
    std::optional<DeviceBook> devices(const std::string& user);
    void forget(const std::string& user);

private:
    struct Held {
        std::int64_t fetchedAt = 0;
        HeldCard card;
        DeviceBook devices;
    };

    std::optional<Held> held(const std::string& user);

    NodeAddress node_;
    std::shared_ptr<const Identity> identity_;
    std::mutex mutex_;
    std::map<std::string, Held> cached_;
};

}  // namespace bazarish::server
