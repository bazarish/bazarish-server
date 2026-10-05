// Bazarish project (c) 2026
#pragma once

#include "Config.hpp"

#include <filesystem>
#include <mutex>
#include <string>

namespace bazarish::admin {

class PanelSettings {
public:
    PanelSettings(std::filesystem::path configPath, Config initial);

    Config get() const;

    const std::filesystem::path& configPath() const { return configPath_; }

    // Applies the values and writes them to the config file.
    void set(const Config& values);

    bool unclaimed() const;

    // Hands an unclaimed panel to one key, and answers false when someone got there first.
    bool claim(const std::string& fingerprint);

private:
    void persist(const Config& values) const;

    std::filesystem::path configPath_;
    mutable std::mutex mutex_;
    Config values_;
};

}  // namespace bazarish::admin
