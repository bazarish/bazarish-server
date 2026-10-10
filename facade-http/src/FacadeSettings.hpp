// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <mutex>
#include <string>

namespace bazarish::facade {

class FacadeSettings {
public:
    struct Values {
        std::string logLevel;
        std::string messagingHost;
        int messagingPort = 0;
        std::string listenHost;
        int listenPort = 0;
        std::string opsHost;
        int opsPort = 0;
        std::string directHost;
        int directPort = 0;
        std::string i2pPrivacy;
        int i2pTunnelQuantity = 0;
    };

    FacadeSettings(std::filesystem::path configPath, Values initial);

    Values get() const;

    void set(const Values& values);

private:
    void persist(const Values& values) const;

    std::filesystem::path configPath_;
    mutable std::mutex mutex_;
    Values values_;
};

}  // namespace bazarish::facade
