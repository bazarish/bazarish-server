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
        std::string id;
        std::string user;
        Bytes key;
        Bytes secret;  // the handles are derived from it
        // What the frames of this tunnel are encrypted under. Derived from the
        // same secret as `key` with a different label, so holding one of them is
        // not holding the other.
        Bytes tunnelKey;
        std::int64_t expiresUnix = 0;
        std::uint64_t lastSeq = 0;
    };

    // Issues a session for `user` from the secret the client sealed to us,
    // expiring at a random point inside the configured window. Returns the id,
    // which stays here: what travels is a different handle per request.
    std::string open(const std::string& user, const Bytes& secret, std::int64_t now,
        std::int64_t* outExpiresUnix);

    // The session a request handle belongs to, if any is still live. Expired
    // sessions are dropped as they are looked up.
    std::optional<Session> findByHandle(const std::string& handle, std::int64_t now);

    // Records the key this session's tunnel frames are encrypted under.
    void setTunnelKey(const std::string& id, const Bytes& tunnelKey);

    // Records that this session used `seq`, rejecting anything not strictly
    // higher than it used before - the replay check, one integer per session
    // rather than a hash per request - and re-indexes the handles it will accept
    // next.
    bool acceptSeq(const std::string& handle, std::uint64_t seq, std::int64_t now);

    std::size_t size() const;

private:
    // Handles a session will accept next, so requests that overtake each other
    // still land: a client keeps two connections and they do not take turns.
    void indexHandlesLocked(const Session& session);
    void forgetHandlesLocked(const Session& session);

    mutable std::mutex mutex_;
    std::map<std::string, Session> sessions_;      // id -> session
    std::map<std::string, std::string> handles_;   // handle -> id
    std::int64_t lastSweep_ = 0;
};

}  // namespace bazarish::server
