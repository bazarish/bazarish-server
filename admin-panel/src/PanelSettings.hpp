// Bazarish project (c) 2026
#pragma once

#include "Config.hpp"

#include <filesystem>
#include <mutex>
#include <string>

namespace bazarish::admin {

// The panel's own configuration while it runs, and the writer that puts it back in
// the file it was read from, one value at a time - so the panel is administered
// from the panel rather than by editing JSON over SSH.
//
// Some of what it holds is only read at startup (where it listens, where its state
// and web files are). It is kept here anyway, so an operator looking for a setting
// finds it in one place; this class only writes what it is given.
class PanelSettings {
public:
    PanelSettings(std::filesystem::path configPath, Config initial);

    Config get() const;

    // The file the values came from and go back to, for the operator to see
    // where the panel is writing.
    const std::filesystem::path& configPath() const { return configPath_; }

    // Applies the values and writes them to the config file. Throws when the
    // file cannot be written: an operator must not be told a change stuck when
    // it would vanish at the next restart.
    void set(const Config& values);

    // Whether this panel has an owner yet. An empty admin list is the one state
    // in which the setup wizard is open, and the first key to sign in claims it.
    bool unclaimed() const;

    // Hands an unclaimed panel to one key, and answers false when someone got
    // there first. Checking and claiming under one lock is the point: two people
    // opening the wizard at the same moment must not both become the owner.
    bool claim(const std::string& fingerprint);

private:
    void persist(const Config& values) const;

    std::filesystem::path configPath_;
    mutable std::mutex mutex_;
    Config values_;
};

}  // namespace bazarish::admin
