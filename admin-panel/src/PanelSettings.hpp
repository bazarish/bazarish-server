// Bazarish project (c) 2026
#pragma once

#include "Config.hpp"

#include <filesystem>
#include <mutex>
#include <string>

namespace bazarish::admin {

// The panel's own configuration while it runs, and the writer that puts it back
// in the file it was read from.
//
// It is the counterpart of the node's settings object: the same discipline (one
// value at a time, patched into the operator's own file) applied to the panel
// itself, so the panel can be administered from the panel - who may sign in, the
// words it signs under, and the deployments it manages - instead of by editing
// JSON over SSH.
//
// Some of what it holds is only read at startup (where it listens, where its
// state and web files are). Those are kept here too, because an operator looking
// for a setting should find it in one place; the interface says which ones need
// a restart, and this class simply writes what it is given.
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
