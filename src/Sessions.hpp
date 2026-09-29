// Bazarish project (c) 2026
#pragma once

#include "Flows.hpp"
#include <bazarish/GatewayProtocol.hpp>

#include <bazarish/Bytes.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace bazarish::gateway {

// A socket is not a session. A session is what holds the destinations, and it
// outlives the socket that opened it, because the connection this is written
// for is a phone's - and because the client drops its own control socket on
// purpose, so that a watcher sees a host being fetched from rather than one
// connection that lives for hours.
class Session {
public:
    Session(std::string cookie, std::int64_t now);

    const std::string& cookie() const { return cookie_; }
    // Identifiers the gateway allocates. It allocates only for an inbound
    // stream, and takes the odd half of the space so the two sides never
    // collide without asking each other.
    Ids& ids() { return ids_; }

    void addSocket();
    void removeSocket(std::int64_t now);
    std::size_t sockets() const { return sockets_; }
    bool full() const { return sockets_ >= kMaxSocketsPerSession; }

    // While any socket is attached the session does not expire; the clock
    // starts when the last one drops.
    bool expired(std::int64_t now, std::int64_t ttlSeconds) const;

    // A request the client sent and never saw answered is re-sent on the next
    // control socket with the same reference. Identifiers are never reused, so
    // the reference is an idempotency key that costs nothing to have, and the
    // repeat gets the answer it already earned rather than a second endpoint.
    void remember(std::uint32_t ref, Bytes answer);
    const Bytes* answered(std::uint32_t ref) const;

    // What this session holds. The gateway drives them; the session owns them,
    // so that everything a session has goes when the session does.
    // The socket carrying this session's control. Everything with no socket of
    // its own rides it.
    http::SocketPtr control;
    // A control socket that has just said hello, until the client has told it
    // what it received. Nothing new may go out on it before the bytes it is
    // owed: a stream whose replay arrives after newer data is a corrupted
    // stream. Zero once the resume is in, or once the grace has run out for a
    // client that had nothing to resume.
    std::chrono::steady_clock::time_point replayDue{};
    std::map<std::uint32_t, std::shared_ptr<EndpointEntry>> endpoints;
    std::map<std::uint32_t, std::shared_ptr<StreamEntry>> streams;
    // Dials this session has running. A client re-sends a request its socket
    // died under, with the same reference; until the dial answers there is
    // nothing yet to answer the repeat from, and starting a second dial would
    // put two streams behind one identifier.
    std::set<std::uint32_t> dialling;

private:
    std::string cookie_;
    Ids ids_;
    std::size_t sockets_ = 0;
    // Meaningless while a socket is attached; set when the last one drops.
    std::int64_t aloneSince_ = 0;
    std::map<std::uint32_t, Bytes> answers_;
    std::deque<std::uint32_t> answerOrder_;
};

// Every live session, by the cookie that names it.
class SessionStore {
public:
    explicit SessionStore(std::int64_t ttlSeconds = kSessionTtl.count());

    // A new session with a cookie of its own, from the system's random source.
    std::shared_ptr<Session> open(std::int64_t now);
    // The session a cookie names, or nothing. A cookie that names nothing is
    // not an error: the caller opens a fresh session and says so, and the
    // client treats it as a router that restarted.
    std::shared_ptr<Session> find(const std::string& cookie, std::int64_t now) const;
    void close(const std::string& cookie);

    // Drops every session whose last socket dropped longer ago than the term,
    // and hands them back: what they hold has to be stopped, and only the
    // caller knows how.
    std::vector<std::shared_ptr<Session>> sweep(std::int64_t now);
    // The same, for all of them at once: what a daemon on its way out has to
    // stop before it takes away the lock they are held under.
    std::vector<std::shared_ptr<Session>> drain();

    std::size_t size() const { return sessions_.size(); }

private:
    std::int64_t ttlSeconds_;
    std::map<std::string, std::shared_ptr<Session>> sessions_;
};

}  // namespace bazarish::gateway
