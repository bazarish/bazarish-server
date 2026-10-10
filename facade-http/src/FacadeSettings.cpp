// Bazarish project (c) 2026
#include "FacadeSettings.hpp"

#include <bazarish/ConfigFile.hpp>

#include <stdexcept>
#include <utility>

namespace bazarish::facade {

namespace {

namespace fs = std::filesystem;

const char* const kLogLevelKey = "logLevel";
const char* const kMessagingKey = "messaging";
const char* const kListenKey = "listen";
const char* const kOpsListenKey = "opsListen";
const char* const kDirectListenKey = "directListen";
const char* const kHostKey = "host";
const char* const kPortKey = "port";
const char* const kI2pKey = "i2p";
const char* const kI2pPrivacyKey = "privacy";
const char* const kI2pTunnelsKey = "tunnelQuantity";

}  // namespace

FacadeSettings::FacadeSettings(fs::path configPath, Values initial)
    : configPath_(std::move(configPath))
    , values_(std::move(initial))
{
}

FacadeSettings::Values FacadeSettings::get() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return values_;
}

void FacadeSettings::set(const Values& values)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    persist(values);
    values_ = values;
}

void FacadeSettings::persist(const Values& values) const
{
    if (configPath_.empty()) {
        throw std::runtime_error("this facade was started without a config file to write to");
    }
    ConfigFile file(configPath_);
    setIfChanged(file, {kLogLevelKey}, values.logLevel, values_.logLevel);
    setIfChanged(file, {kMessagingKey, kHostKey}, values.messagingHost, values_.messagingHost);
    setIfChanged(file, {kMessagingKey, kPortKey}, values.messagingPort, values_.messagingPort);
    setIfChanged(file, {kListenKey, kHostKey}, values.listenHost, values_.listenHost);
    setIfChanged(file, {kListenKey, kPortKey}, values.listenPort, values_.listenPort);
    setIfChanged(file, {kOpsListenKey, kHostKey}, values.opsHost, values_.opsHost);
    setIfChanged(file, {kOpsListenKey, kPortKey}, values.opsPort, values_.opsPort);
    setIfChanged(file, {kDirectListenKey, kHostKey}, values.directHost, values_.directHost);
    setIfChanged(file, {kDirectListenKey, kPortKey}, values.directPort, values_.directPort);
    setIfChanged(file, {kI2pKey, kI2pPrivacyKey}, values.i2pPrivacy, values_.i2pPrivacy);
    setIfChanged(
        file, {kI2pKey, kI2pTunnelsKey}, values.i2pTunnelQuantity, values_.i2pTunnelQuantity);
}

}  // namespace bazarish::facade
