// Bazarish project (c) 2026
#pragma once

#include <SettingsFile.hpp>

#include <filesystem>
#include <string>

namespace bazarish::facade {

struct FacadeSettingsValues {
    std::string logLevel;
    std::string messagingHost;
    int messagingPort = 0;
    std::string serviceNodeHost;
    int serviceNodePort = 0;
    std::string listenHost;
    int listenPort = 0;
    std::string opsHost;
    int opsPort = 0;
    std::string directHost;
    int directPort = 0;
    std::string i2pPrivacy;
    std::string i2pLogLevel;
    int i2pTunnelQuantity = 0;
};

class FacadeSettings : public server::SettingsFile<FacadeSettingsValues> {
public:
    using Values = FacadeSettingsValues;

    FacadeSettings(std::filesystem::path configPath, Values initial);
};

}  // namespace bazarish::facade
