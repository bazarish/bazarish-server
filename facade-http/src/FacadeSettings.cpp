// Bazarish project (c) 2026
#include "FacadeSettings.hpp"

#include <bazarish/ConfigFile.hpp>

#include <utility>

namespace bazarish::facade {

namespace {

namespace fs = std::filesystem;

const char* const kLogLevelKey = "logLevel";
const char* const kMessagingKey = "messaging";
const char* const kServiceNodeKey = "serviceNode";
const char* const kListenKey = "listen";
const char* const kOpsListenKey = "opsListen";
const char* const kDirectListenKey = "directListen";
const char* const kHostKey = "host";
const char* const kPortKey = "port";
const char* const kI2pKey = "i2p";
const char* const kI2pPrivacyKey = "privacy";
const char* const kI2pTunnelsKey = "tunnelQuantity";
const char* const kI2pLogLevelKey = "logLevel";

void persistFacadeSettings(
    ConfigFile& file, const FacadeSettingsValues& values, const FacadeSettingsValues& before)
{
    setIfChanged(file, {kLogLevelKey}, values.logLevel, before.logLevel);
    setIfChanged(file, {kMessagingKey, kHostKey}, values.messagingHost, before.messagingHost);
    setIfChanged(file, {kMessagingKey, kPortKey}, values.messagingPort, before.messagingPort);
    setIfChanged(
        file, {kServiceNodeKey, kHostKey}, values.serviceNodeHost, before.serviceNodeHost);
    setIfChanged(
        file, {kServiceNodeKey, kPortKey}, values.serviceNodePort, before.serviceNodePort);
    setIfChanged(file, {kListenKey, kHostKey}, values.listenHost, before.listenHost);
    setIfChanged(file, {kListenKey, kPortKey}, values.listenPort, before.listenPort);
    setIfChanged(file, {kOpsListenKey, kHostKey}, values.opsHost, before.opsHost);
    setIfChanged(file, {kOpsListenKey, kPortKey}, values.opsPort, before.opsPort);
    setIfChanged(file, {kDirectListenKey, kHostKey}, values.directHost, before.directHost);
    setIfChanged(file, {kDirectListenKey, kPortKey}, values.directPort, before.directPort);
    setIfChanged(file, {kI2pKey, kI2pPrivacyKey}, values.i2pPrivacy, before.i2pPrivacy);
    setIfChanged(
        file, {kI2pKey, kI2pTunnelsKey}, values.i2pTunnelQuantity, before.i2pTunnelQuantity);
    setIfChanged(file, {kI2pKey, kI2pLogLevelKey}, values.i2pLogLevel, before.i2pLogLevel);
}

}  // namespace

FacadeSettings::FacadeSettings(fs::path configPath, Values initial)
    : SettingsFile(std::move(configPath), std::move(initial), persistFacadeSettings)
{
}

}  // namespace bazarish::facade
