// Bazarish project (c) 2026
#include "ServerSettings.hpp"

#include <bazarish/ConfigFile.hpp>

#include <utility>

namespace bazarish::server {

namespace {

namespace fs = std::filesystem;

const char* const kLogLevelKey = "logLevel";
const char* const kI2pKey = "i2p";
const char* const kI2pLogLevelKey = "logLevel";
const char* const kI2pPrivacyKey = "privacy";
const char* const kListenKey = "listen";
const char* const kHostKey = "host";
const char* const kPortKey = "port";
const char* const kServiceNodeKey = "serviceNode";
const char* const kUrlKey = "url";
const char* const kGatewayListenKey = "gatewayListen";
const char* const kGatewaysKey = "gateways";

void persistServerSettings(
    ConfigFile& file, const ServerSettingsValues& values, const ServerSettingsValues& before)
{
    setIfChanged(file, {kLogLevelKey}, values.logLevel, before.logLevel);
    setIfChanged(file, {kI2pKey, kI2pLogLevelKey}, values.i2pLogLevel, before.i2pLogLevel);
    setIfChanged(file, {kI2pKey, kI2pPrivacyKey}, values.i2pPrivacy, before.i2pPrivacy);
    setIfChanged(file, {kListenKey, kHostKey}, values.listenHost, before.listenHost);
    setIfChanged(file, {kListenKey, kPortKey}, values.listenPort, before.listenPort);
    setIfChanged(
        file, {kServiceNodeKey, kUrlKey}, values.serviceNodeUrl, before.serviceNodeUrl);
    if (!values.gatewayListenHost.empty()) {
        setIfChanged(file, {kGatewayListenKey, kHostKey}, values.gatewayListenHost,
            before.gatewayListenHost);
        setIfChanged(file, {kGatewayListenKey, kPortKey}, values.gatewayListenPort,
            before.gatewayListenPort);
    }
    setIfChanged(file, {kGatewaysKey}, values.gateways, before.gateways);
}

}  // namespace

ServerSettings::ServerSettings(fs::path configPath, Values initial)
    : SettingsFile(std::move(configPath), std::move(initial), persistServerSettings)
{
}

}  // namespace bazarish::server
