// Bazarish project (c) 2026
#pragma once

#include <SettingsFile.hpp>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace bazarish::server {

struct ServerSettingsValues {
    std::string logLevel;
    std::string i2pLogLevel;
    std::string i2pPrivacy;
    std::string listenHost;
    int listenPort = 0;
    std::string serviceNodeUrl;
    std::string gatewayListenHost;
    int gatewayListenPort = 0;
    std::vector<std::string> gateways;
};

class ServerSettings : public SettingsFile<ServerSettingsValues> {
public:
    using Values = ServerSettingsValues;

    ServerSettings(std::filesystem::path configPath, Values initial);
};

}  // namespace bazarish::server
