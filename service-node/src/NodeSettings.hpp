// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::service {

class NodeSettings {
public:
    struct Values {
        bool requireApproval = false;
        std::string registrationMessage;
        std::string portalMessage;
        LoginConsumer loginConsumer;
        std::vector<std::string> facades;
        std::vector<std::string> reseeds;
        std::vector<std::string> portalLinks;
        std::string logLevel;
        std::string listenHost;
        int listenPort = 0;
        std::string portalListenHost;
        int portalListenPort = 0;
        std::string messagingHost;
        int messagingPort = 0;
        std::uint64_t defaultQuotaBytes = 0;
        std::int64_t idleDeleteDays = 0;
    };

    NodeSettings(std::filesystem::path configPath, Values initial);

    Values get() const;

    void set(const Values& values);

private:
    void persist(const Values& values) const;

    std::filesystem::path configPath_;
    mutable std::mutex mutex_;
    Values values_;
};

}  // namespace bazarish::service
