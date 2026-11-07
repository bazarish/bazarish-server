// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

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

    std::optional<Bytes> card(const std::string& user);
    void forget(const std::string& user);

private:
    NodeAddress node_;
    std::shared_ptr<const Identity> identity_;
    std::mutex mutex_;
    std::map<std::string, std::pair<std::int64_t, Bytes>> cached_;
};

}  // namespace bazarish::server
