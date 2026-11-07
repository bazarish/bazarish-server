// Bazarish project (c) 2026
#pragma once

#include "Flows.hpp"
#include <bazarish/GatewayChannel.hpp>
#include <bazarish/GatewayProtocol.hpp>

#include <bazarish/Bytes.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace bazarish::gateway {

class Session {
public:
    Session(std::string cookie, std::int64_t now);

    const std::string& cookie() const { return cookie_; }
    Ids& ids() { return ids_; }

    void addSocket();
    void removeSocket(std::int64_t now);
    std::size_t sockets() const { return sockets_; }
    bool full() const { return sockets_ >= kMaxSocketsPerSession; }

    bool expired(std::int64_t now, std::int64_t ttlSeconds) const;

    void remember(std::uint32_t ref, Bytes answer);
    std::optional<Bytes> answered(std::uint32_t ref) const;

    http::SocketPtr control;
    std::chrono::steady_clock::time_point replayDue{};
    std::map<std::uint32_t, std::shared_ptr<EndpointEntry>> endpoints;
    std::map<std::uint32_t, std::shared_ptr<StreamEntry>> streams;
    std::set<std::uint32_t> dialling;
    bool retired = false;
    Bytes key;
    std::set<std::string> tickets;

    std::vector<Bytes> issueTickets(std::size_t count);

private:
    std::string cookie_;
    Ids ids_;
    std::size_t sockets_ = 0;
    std::int64_t aloneSince_ = 0;
    std::map<std::uint32_t, Bytes> answers_;
    std::deque<std::uint32_t> answerOrder_;
};

class SessionStore {
public:
    explicit SessionStore(std::int64_t ttlSeconds = kSessionTtl.count());

    std::shared_ptr<Session> open(std::int64_t now);
    // The live session a ticket was issued by; the ticket itself stays until it is spent.
    std::shared_ptr<Session> holding(const Bytes& ticket, std::int64_t now) const;
    void close(const std::string& cookie);

    std::vector<std::shared_ptr<Session>> sweep(std::int64_t now);
    std::vector<std::shared_ptr<Session>> drain();
    std::vector<std::shared_ptr<Session>> all() const;

    std::size_t size() const { return sessions_.size(); }

private:
    std::int64_t ttlSeconds_;
    std::map<std::string, std::shared_ptr<Session>> sessions_;
};

}  // namespace bazarish::gateway
