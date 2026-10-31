// Bazarish project (c) 2026
#include "NodeSettings.hpp"

#include <bazarish/ConfigFile.hpp>

#include <nlohmann/json.hpp>

#include <utility>

namespace bazarish::service {

namespace {

namespace fs = std::filesystem;

const char* const kRegistrationKey = "registration";
const char* const kRequireApprovalKey = "requireApproval";
const char* const kMessageKey = "message";
const char* const kIdleDaysKey = "idleDeleteDays";
const char* const kQuotaKey = "freeStorageBytes";
const char* const kPortalKey = "portal";
const char* const kPortalMessageKey = "message";
const char* const kPortalNameKey = "name";
const char* const kPortalAddressKey = "address";
const char* const kPortalRoleKey = "role";
const char* const kFacadesKey = "facades";
const char* const kReseedsKey = "reseeds";
const char* const kLinksKey = "links";
const char* const kLogLevelKey = "logLevel";
const char* const kListenKey = "listen";
const char* const kMessagingKey = "messaging";
const char* const kHostKey = "host";
const char* const kPortKey = "port";

}  // namespace

NodeSettings::NodeSettings(fs::path configPath, Values initial)
    : configPath_(std::move(configPath))
    , values_(std::move(initial))
{
}

NodeSettings::Values NodeSettings::get() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return values_;
}

void NodeSettings::set(const Values& values)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    persist(values);
    values_ = values;
}

void NodeSettings::persist(const Values& values) const
{
    ConfigFile file(configPath_);
    setIfChanged(file, {kRegistrationKey, kRequireApprovalKey}, values.requireApproval,
        values_.requireApproval);
    setIfChanged(file, {kRegistrationKey, kMessageKey}, values.registrationMessage,
        values_.registrationMessage);
    setIfChanged(
        file, {kRegistrationKey, kIdleDaysKey}, values.idleDeleteDays, values_.idleDeleteDays);
    setIfChanged(file, {kQuotaKey}, values.defaultQuotaBytes, values_.defaultQuotaBytes);
    setIfChanged(file, {kPortalKey, kPortalMessageKey}, values.portalMessage,
        values_.portalMessage);
    setIfChanged(file, {kPortalKey, kPortalNameKey}, values.loginConsumer.name,
        values_.loginConsumer.name);
    setIfChanged(file, {kPortalKey, kPortalAddressKey}, values.loginConsumer.place,
        values_.loginConsumer.place);
    setIfChanged(file, {kPortalKey, kPortalRoleKey}, values.loginConsumer.role,
        values_.loginConsumer.role);
    setIfChanged(file, {kPortalKey, kFacadesKey}, values.facades, values_.facades);
    setIfChanged(file, {kPortalKey, kReseedsKey}, values.reseeds, values_.reseeds);
    setIfChanged(file, {kPortalKey, kLinksKey}, values.portalLinks, values_.portalLinks);
    setIfChanged(file, {kLogLevelKey}, values.logLevel, values_.logLevel);
    setIfChanged(file, {kListenKey, kHostKey}, values.listenHost, values_.listenHost);
    setIfChanged(file, {kListenKey, kPortKey}, values.listenPort, values_.listenPort);
    setIfChanged(file, {kPortalKey, kListenKey, kHostKey}, values.portalListenHost,
        values_.portalListenHost);
    setIfChanged(file, {kPortalKey, kListenKey, kPortKey}, values.portalListenPort,
        values_.portalListenPort);
    setIfChanged(file, {kMessagingKey, kHostKey}, values.messagingHost, values_.messagingHost);
    setIfChanged(file, {kMessagingKey, kPortKey}, values.messagingPort, values_.messagingPort);
}

}  // namespace bazarish::service
