// Bazarish project (c) 2026
#pragma once

#include <bazarish/ConfigFile.hpp>

#include <filesystem>
#include <functional>
#include <mutex>
#include <utility>

namespace bazarish::server {

template <class Values>
class SettingsFile {
public:
    // Writes to the file what differs between before and after.
    using Persist
        = std::function<void(ConfigFile& file, const Values& after, const Values& before)>;

    SettingsFile(std::filesystem::path configPath, Values initial, Persist persist)
        : configPath_(std::move(configPath))
        , persist_(std::move(persist))
        , values_(std::move(initial))
    {
    }

    Values get() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return values_;
    }

    void set(const Values& values)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        ConfigFile file(configPath_);
        persist_(file, values, values_);
        values_ = values;
    }

private:
    std::filesystem::path configPath_;
    Persist persist_;
    mutable std::mutex mutex_;
    Values values_;
};

}  // namespace bazarish::server
