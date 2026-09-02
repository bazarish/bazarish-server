// Bazarish project (c) 2026
#include "FacadeSettings.hpp"

#include <bazarish/ConfigFile.hpp>

#include <stdexcept>
#include <utility>

namespace bazarish::facade {

namespace {

namespace fs = std::filesystem;

// How the config file spells each setting, so a hand-edited file and a
// panel-edited one are the same file.
const char* const kLogLevelKey = "logLevel";
const char* const kBasePathKey = "basePath";
const char* const kMessagingKey = "messaging";
const char* const kAccountKey = "account";
const char* const kListenKey = "listen";
const char* const kOpsListenKey = "opsListen";
const char* const kHostKey = "host";
const char* const kPortKey = "port";
const char* const kI2pKey = "i2p";
const char* const kI2pEnabledKey = "enabled";
const char* const kI2pDestinationsKey = "destinations";
const char* const kI2pPrivacyKey = "privacy";
const char* const kI2pTunnelsKey = "tunnelQuantity";

}  // namespace

bool isValidBasePath(const std::string& path)
{
    if (path.empty() || path.front() != '/' || path.back() == '/') {
        return false;
    }
    return path.find_first_of("?# ") == std::string::npos;
}

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
    if (values.logLevel != values_.logLevel) {
        file.set({kLogLevelKey}, values.logLevel);
    }
    if (values.basePath != values_.basePath) {
        file.set({kBasePathKey}, values.basePath);
    }
    if (values.messagingHost != values_.messagingHost) {
        file.set({kMessagingKey, kHostKey}, values.messagingHost);
    }
    if (values.messagingPort != values_.messagingPort) {
        file.set({kMessagingKey, kPortKey}, values.messagingPort);
    }
    if (values.accountHost != values_.accountHost) {
        file.set({kAccountKey, kHostKey}, values.accountHost);
    }
    if (values.accountPort != values_.accountPort) {
        file.set({kAccountKey, kPortKey}, values.accountPort);
    }
    if (values.listenHost != values_.listenHost) {
        file.set({kListenKey, kHostKey}, values.listenHost);
    }
    if (values.listenPort != values_.listenPort) {
        file.set({kListenKey, kPortKey}, values.listenPort);
    }
    if (values.opsHost != values_.opsHost) {
        file.set({kOpsListenKey, kHostKey}, values.opsHost);
    }
    if (values.opsPort != values_.opsPort) {
        file.set({kOpsListenKey, kPortKey}, values.opsPort);
    }
    if (values.i2pEnabled != values_.i2pEnabled) {
        file.set({kI2pKey, kI2pEnabledKey}, values.i2pEnabled);
    }
    if (values.i2pDestinations != values_.i2pDestinations) {
        file.set({kI2pKey, kI2pDestinationsKey}, values.i2pDestinations);
    }
    if (values.i2pPrivacy != values_.i2pPrivacy) {
        file.set({kI2pKey, kI2pPrivacyKey}, values.i2pPrivacy);
    }
    if (values.i2pTunnelQuantity != values_.i2pTunnelQuantity) {
        file.set({kI2pKey, kI2pTunnelsKey}, values.i2pTunnelQuantity);
    }
}

}  // namespace bazarish::facade
