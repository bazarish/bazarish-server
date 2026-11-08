// Bazarish project (c) 2026
#pragma once

#include <filesystem>

#include <FleetPorts.hpp>
#include <string>

namespace bazarish::setup {

using fleet::kPanelPort;

struct Layout {
    std::filesystem::path configDir;
    std::filesystem::path stateDir;
    std::filesystem::path panelAssets;
    std::filesystem::path portalAssets;
    std::string fleetName;
};

// False, with nothing written, once any of the four configs is there.
bool setUpFleet(const Layout& layout);

}  // namespace bazarish::setup
