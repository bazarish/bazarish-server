// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace bazarish::server {

// The sessions clients authenticate requests with instead of presenting a
// hybrid signature every time. In memory only: a session is a short-lived
// convenience, and losing them on restart costs each client one signed request.
class SessionStore {
public:
    struct Session {
        std::string user;
        Bytes key;
        std::int64_t expiresUnix = 0;
        std::uint64_t lastSeq = 0;
    };

    // Issues a session for `user` from the secret the client sealed to us,
    // expiring at a random point inside the configured window. Returns the id.
    std::string open(const std::string& user, const Bytes& secret, std::int64_t now,
        std::int64_t* outExpiresUnix);

    // The session, if it exists and has not expired. Expired ones are dropped as
    // they are looked up, so an idle server does not keep them forever.
    std::optional<Session> find(const std::string& id, std::int64_t now);

    // Records that this session used `seq`, rejecting anything not strictly
    // higher than what it used before - that is the replay check, and it costs
    // one integer per session rather than a hash per request.
    bool acceptSeq(const std::string& id, std::uint64_t seq, std::int64_t now);

    void drop(const std::string& id);
    std::size_t size() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, Session> sessions_;
    std::int64_t lastSweep_ = 0;
};

}  // namespace bazarish::server
