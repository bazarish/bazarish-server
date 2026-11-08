// Bazarish project (c) 2026
#pragma once

#include <bazarish/ConfigFile.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <string>

namespace bazarish::server {

// The fields an operator's settings change shares across services, each checked; a field the
// body leaves out keeps the value given.
std::string logLevelIn(const nlohmann::json& body, const std::string& current);
std::string privacyIn(const nlohmann::json& body, const std::string& current);
int tunnelQuantityIn(const nlohmann::json& body, int current);

// The same two read from a service's config file at start; a wrong value throws.
i2p::Privacy configPrivacy(const ConfigView& config, i2p::Privacy absent);
log::Level configLogLevel(const ConfigView& config);

// Puts a changed log level in force.
void applyLogLevel(const std::string& before, const std::string& after);

}  // namespace bazarish::server
