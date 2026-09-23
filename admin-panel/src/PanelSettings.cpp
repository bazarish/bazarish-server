// Bazarish project (c) 2026
#include "PanelSettings.hpp"

#include <bazarish/ConfigFile.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <utility>

namespace bazarish::admin {

namespace {

namespace fs = std::filesystem;

// How the config file spells each setting, so a hand-edited file and a
// panel-edited one are the same file.
const char* const kAdminKey = "admin";
const char* const kConsumerKey = "consumer";
const char* const kConsumerNameKey = "name";
const char* const kConsumerPlaceKey = "place";
const char* const kConsumerRoleKey = "role";
const char* const kListenKey = "listen";
const char* const kListenHostKey = "host";
const char* const kListenPortKey = "port";
const char* const kFleetsKey = "fleets";

nlohmann::json fleetsJson(const std::vector<Fleet>& fleets)
{
    nlohmann::json list = nlohmann::json::array();
    for (const Fleet& fleet : fleets) {
        nlohmann::json services = nlohmann::json::array();
        for (const ServiceEntry& service : fleet.services) {
            services.push_back({{"name", service.name}, {"kind", service.kind},
                {"url", service.url}, {"token", service.token}});
        }
        list.push_back({{"name", fleet.name}, {"services", services}});
    }
    return list;
}

}  // namespace

PanelSettings::PanelSettings(fs::path configPath, Config initial)
    : configPath_(std::move(configPath))
    , values_(std::move(initial))
{
}

Config PanelSettings::get() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return values_;
}

bool PanelSettings::unclaimed() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return values_.admins.empty();
}

bool PanelSettings::claim(const std::string& fingerprint)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (!values_.admins.empty()) {
        return false;
    }
    Config claimed = values_;
    claimed.admins = {fingerprint};
    persist(claimed);
    values_ = claimed;
    return true;
}

void PanelSettings::set(const Config& values)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    persist(values);
    values_ = values;
}

void PanelSettings::persist(const Config& values) const
{
    if (configPath_.empty()) {
        throw std::runtime_error("this panel was started without a config file to write to");
    }
    ConfigFile file(configPath_);
    if (values.admins != values_.admins) {
        file.set({kAdminKey}, values.admins);
    }
    if (values.consumer.name != values_.consumer.name) {
        file.set({kConsumerKey, kConsumerNameKey}, values.consumer.name);
    }
    if (values.consumer.place != values_.consumer.place) {
        file.set({kConsumerKey, kConsumerPlaceKey}, values.consumer.place);
    }
    if (values.consumer.role != values_.consumer.role) {
        file.set({kConsumerKey, kConsumerRoleKey}, values.consumer.role);
    }
    if (values.listenHost != values_.listenHost) {
        file.set({kListenKey, kListenHostKey}, values.listenHost);
    }
    if (values.listenPort != values_.listenPort) {
        file.set({kListenKey, kListenPortKey}, values.listenPort);
    }
    if (values.fleets != values_.fleets) {
        file.set({kFleetsKey}, fleetsJson(values.fleets));
    }
}

}  // namespace bazarish::admin
