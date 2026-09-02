// Bazarish project (c) 2026
#include "ServerSettings.hpp"

#include <bazarish/ConfigFile.hpp>

#include <stdexcept>
#include <utility>

namespace bazarish::server {

namespace {

namespace fs = std::filesystem;

// How the config file spells each setting, so a hand-edited file and a
// panel-edited one are the same file.
const char* const kLogLevelKey = "logLevel";
const char* const kI2pKey = "i2p";
const char* const kI2pLogKey = "log";
const char* const kI2pPrivacyKey = "privacy";
const char* const kI2pTunnelsKey = "tunnelQuantity";
const char* const kFederationRateKey = "federationRateLimit";
const char* const kRetentionKey = "mailboxRetentionDays";
const char* const kListenKey = "listen";
const char* const kHostKey = "host";
const char* const kPortKey = "port";
const char* const kServiceNodeKey = "serviceNode";

}  // namespace

ServerSettings::ServerSettings(fs::path configPath, Values initial)
    : configPath_(std::move(configPath))
    , values_(std::move(initial))
{
}

ServerSettings::Values ServerSettings::get() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return values_;
}

void ServerSettings::set(const Values& values)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    persist(values);
    values_ = values;
}

void ServerSettings::persist(const Values& values) const
{
    if (configPath_.empty()) {
        throw std::runtime_error("this server was started without a config file to write to");
    }
    ConfigFile file(configPath_);
    if (values.logLevel != values_.logLevel) {
        file.set({kLogLevelKey}, values.logLevel);
    }
    if (values.i2pLog != values_.i2pLog) {
        file.set({kI2pKey, kI2pLogKey}, values.i2pLog);
    }
    if (values.i2pPrivacy != values_.i2pPrivacy) {
        file.set({kI2pKey, kI2pPrivacyKey}, values.i2pPrivacy);
    }
    if (values.i2pTunnelQuantity != values_.i2pTunnelQuantity) {
        file.set({kI2pKey, kI2pTunnelsKey}, values.i2pTunnelQuantity);
    }
    if (values.federationRateLimit != values_.federationRateLimit) {
        file.set({kFederationRateKey}, values.federationRateLimit);
    }
    if (values.mailboxRetentionDays != values_.mailboxRetentionDays) {
        file.set({kRetentionKey}, values.mailboxRetentionDays);
    }
    if (values.listenHost != values_.listenHost) {
        file.set({kListenKey, kHostKey}, values.listenHost);
    }
    if (values.listenPort != values_.listenPort) {
        file.set({kListenKey, kPortKey}, values.listenPort);
    }
    if (values.serviceNodeUrl != values_.serviceNodeUrl) {
        file.set({kServiceNodeKey}, values.serviceNodeUrl);
    }
}

}  // namespace bazarish::server
