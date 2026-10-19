// Bazarish project (c) 2026
#include "ServerSettings.hpp"

#include <bazarish/ConfigFile.hpp>

#include <stdexcept>
#include <utility>

namespace bazarish::server {

namespace {

namespace fs = std::filesystem;

const char* const kLogLevelKey = "logLevel";
const char* const kI2pKey = "i2p";
const char* const kI2pLogKey = "log";
const char* const kI2pPrivacyKey = "privacy";
const char* const kI2pTunnelsKey = "tunnelQuantity";
const char* const kListenKey = "listen";
const char* const kHostKey = "host";
const char* const kPortKey = "port";
const char* const kServiceNodeKey = "serviceNode";
const char* const kGatewayListenKey = "gatewayListen";
const char* const kGatewaysKey = "gateways";

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
    setIfChanged(file, {kLogLevelKey}, values.logLevel, values_.logLevel);
    setIfChanged(file, {kI2pKey, kI2pLogKey}, values.i2pLog, values_.i2pLog);
    setIfChanged(file, {kI2pKey, kI2pPrivacyKey}, values.i2pPrivacy, values_.i2pPrivacy);
    setIfChanged(
        file, {kI2pKey, kI2pTunnelsKey}, values.i2pTunnelQuantity, values_.i2pTunnelQuantity);
    setIfChanged(file, {kListenKey, kHostKey}, values.listenHost, values_.listenHost);
    setIfChanged(file, {kListenKey, kPortKey}, values.listenPort, values_.listenPort);
    setIfChanged(file, {kServiceNodeKey}, values.serviceNodeUrl, values_.serviceNodeUrl);
    if (!values.gatewayListenHost.empty()) {
        setIfChanged(file, {kGatewayListenKey, kHostKey}, values.gatewayListenHost,
            values_.gatewayListenHost);
        setIfChanged(file, {kGatewayListenKey, kPortKey}, values.gatewayListenPort,
            values_.gatewayListenPort);
    }
    setIfChanged(file, {kGatewaysKey}, values.gateways, values_.gateways);
}

}  // namespace bazarish::server
