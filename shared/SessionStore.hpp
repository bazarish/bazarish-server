// Bazarish project (c) 2026
#pragma once

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/SecretBytes.hpp>

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace bazarish::server {

class SessionStore {
public:
    struct Session {
        std::string id;
        auth::DeviceCaller caller;
        SecretBytes key;
        SecretBytes secret;
        SecretBytes tunnelKey;
        std::int64_t expiresUnix = 0;
        std::uint64_t lastSeq = 0;
    };

    std::string open(const auth::DeviceCaller& caller, const SecretBytes& secret, std::int64_t now,
        std::int64_t& outExpiresUnix);

    std::optional<Session> findByHandle(const std::string& handle, std::int64_t now);

    void setTunnelKey(const std::string& id, const SecretBytes& tunnelKey);

    bool acceptSeq(const std::string& handle, std::uint64_t seq, std::int64_t now);

    std::size_t size() const;

private:
    void indexHandlesLocked(const Session& session);
    void forgetHandlesLocked(const Session& session);

    mutable std::mutex mutex_;
    std::map<std::string, Session> sessions_;
    std::map<std::string, std::string> handles_;
    std::int64_t lastSweep_ = 0;
};

}  // namespace bazarish::server
