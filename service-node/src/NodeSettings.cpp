// Bazarish project (c) 2026
#include "NodeSettings.hpp"

#include <bazarish/ConfigFile.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

namespace fs = std::filesystem;

// How the config file spells the knobs, so a hand-edited file and a
// panel-edited one are the same file.
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
    if (configPath_.empty()) {
        throw std::runtime_error("this node was started without a config file to write to");
    }
    // One value at a time, patched into the file's own text: the rest of it -
    // the operator's key order, their spacing, their comments, and settings this
    // node has never heard of - comes back untouched.
    ConfigFile file(configPath_);
    if (values.requireApproval != values_.requireApproval) {
        file.set({kRegistrationKey, kRequireApprovalKey}, values.requireApproval);
    }
    if (values.registrationMessage != values_.registrationMessage) {
        file.set({kRegistrationKey, kMessageKey}, values.registrationMessage);
    }
    if (values.idleDeleteDays != values_.idleDeleteDays) {
        file.set({kRegistrationKey, kIdleDaysKey}, values.idleDeleteDays);
    }
    if (values.defaultQuotaBytes != values_.defaultQuotaBytes) {
        file.set({kQuotaKey}, values.defaultQuotaBytes);
    }
    if (values.portalMessage != values_.portalMessage) {
        file.set({kPortalKey, kPortalMessageKey}, values.portalMessage);
    }
    if (values.loginConsumer.name != values_.loginConsumer.name) {
        file.set({kPortalKey, kPortalNameKey}, values.loginConsumer.name);
    }
    if (values.loginConsumer.place != values_.loginConsumer.place) {
        file.set({kPortalKey, kPortalAddressKey}, values.loginConsumer.place);
    }
    if (values.loginConsumer.role != values_.loginConsumer.role) {
        file.set({kPortalKey, kPortalRoleKey}, values.loginConsumer.role);
    }
    if (values.facades != values_.facades) {
        file.set({kPortalKey, kFacadesKey}, values.facades);
    }
    if (values.reseeds != values_.reseeds) {
        file.set({kPortalKey, kReseedsKey}, values.reseeds);
    }
    if (values.portalLinks != values_.portalLinks) {
        file.set({kPortalKey, kLinksKey}, values.portalLinks);
    }
    if (values.logLevel != values_.logLevel) {
        file.set({kLogLevelKey}, values.logLevel);
    }
    if (values.listenHost != values_.listenHost) {
        file.set({kListenKey, kHostKey}, values.listenHost);
    }
    if (values.listenPort != values_.listenPort) {
        file.set({kListenKey, kPortKey}, values.listenPort);
    }
    if (values.portalListenHost != values_.portalListenHost) {
        file.set({kPortalKey, kListenKey, kHostKey}, values.portalListenHost);
    }
    if (values.portalListenPort != values_.portalListenPort) {
        file.set({kPortalKey, kListenKey, kPortKey}, values.portalListenPort);
    }
    if (values.messagingHost != values_.messagingHost) {
        file.set({kMessagingKey, kHostKey}, values.messagingHost);
    }
    if (values.messagingPort != values_.messagingPort) {
        file.set({kMessagingKey, kPortKey}, values.messagingPort);
    }
}

}  // namespace bazarish::service
