// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>

namespace bazarish::server {

class ServerSettings {
public:
    struct Values {
        // How much the server says, and whether libi2pd's own lines join it.
        std::string logLevel;
        bool i2pLog = false;
        std::string i2pPrivacy;
        int i2pTunnelQuantity = 0;
        std::string listenHost;
        int listenPort = 0;
        std::string serviceNodeUrl;
    };

    ServerSettings(std::filesystem::path configPath, Values initial);

    Values get() const;

    void set(const Values& values);

private:
    void persist(const Values& values) const;

    std::filesystem::path configPath_;
    mutable std::mutex mutex_;
    Values values_;
};

}  // namespace bazarish::server
