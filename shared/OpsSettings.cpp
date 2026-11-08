// Bazarish project (c) 2026
#include "OpsSettings.hpp"

#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

#include <optional>
#include <stdexcept>

namespace bazarish::server {

std::string logLevelIn(const nlohmann::json& body, const std::string& current)
{
    if (!body.contains("logLevel")) {
        return current;
    }
    const std::string level = body.at("logLevel").get<std::string>();
    if (!log::levelFromString(level).has_value()) {
        throw std::invalid_argument("not a log level: " + level);
    }
    return level;
}

std::string privacyIn(const nlohmann::json& body, const std::string& current)
{
    if (!body.contains("i2pPrivacy")) {
        return current;
    }
    const std::string named = body.at("i2pPrivacy").get<std::string>();
    if (!i2p::privacyFromString(named).has_value()) {
        throw std::invalid_argument("not a privacy level: " + named);
    }
    return named;
}

int tunnelQuantityIn(const nlohmann::json& body, const int current)
{
    if (!body.contains("i2pTunnelQuantity")) {
        return current;
    }
    const int quantity = body.at("i2pTunnelQuantity").get<int>();
    if (quantity < 1 || quantity > i2p::kMaxTunnelQuantity) {
        throw std::invalid_argument("a destination carries between 1 and "
            + std::to_string(i2p::kMaxTunnelQuantity) + " tunnels");
    }
    return quantity;
}

i2p::Privacy configPrivacy(const ConfigView& config, const i2p::Privacy absent)
{
    const std::string named = config.text("i2p.privacy");
    if (named.empty()) {
        return absent;
    }
    const std::optional<i2p::Privacy> parsed = i2p::privacyFromString(named);
    if (!parsed.has_value()) {
        throw std::invalid_argument("i2p.privacy is not a privacy level");
    }
    return *parsed;
}

log::Level configLogLevel(const ConfigView& config)
{
    const std::string level = config.text("logLevel");
    if (level.empty()) {
        return log::Level::eInfo;
    }
    const std::optional<log::Level> parsed = log::levelFromString(level);
    if (!parsed.has_value()) {
        throw std::invalid_argument("logLevel is not a level");
    }
    return *parsed;
}

void applyLogLevel(const std::string& before, const std::string& after)
{
    if (after == before) {
        return;
    }
    const std::optional<log::Level> level = log::levelFromString(after);
    if (!level.has_value()) {
        throw std::invalid_argument("not a log level: " + after);
    }
    log::setLevel(*level);
}

}  // namespace bazarish::server
