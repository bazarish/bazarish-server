// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>

namespace bazarish::server {

// The messaging server's configuration while it runs, and the writer that puts it
// back in the file it was read from.
//
// Only the log level and libi2pd's own logging take effect at once; everything
// else is read at start, so a change to it is written for the next one and the
// operator is told so.
class ServerSettings {
public:
    struct Values {
        // How much the server says, and whether libi2pd's own lines join it.
        // Both apply the moment they are set.
        std::string logLevel;
        bool i2pLog = false;
        // The I2P side: how private the tunnels are and how many of them carry
        // one destination. A public server's inbound federation runs a full pool;
        // an operator on a thin uplink lowers it.
        std::string i2pPrivacy;
        int i2pTunnelQuantity = 0;
        // Inbound deliveries accepted from one peer destination per minute.
        std::size_t federationRateLimit = 0;
        // How long mail nobody ever acknowledged is kept before the sweep takes
        // it. 0 keeps it forever.
        std::int64_t mailboxRetentionDays = 0;
        // Where this server answers, and the service node it reports to.
        std::string listenHost;
        int listenPort = 0;
        std::string serviceNodeUrl;
    };

    ServerSettings(std::filesystem::path configPath, Values initial);

    Values get() const;

    // Applies the values and writes them to the config file. Throws when the
    // file cannot be written: an operator must not be told a change stuck when
    // it would vanish at the next restart.
    void set(const Values& values);

private:
    void persist(const Values& values) const;

    std::filesystem::path configPath_;
    mutable std::mutex mutex_;
    Values values_;
};

}  // namespace bazarish::server
