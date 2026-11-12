// Bazarish project (c) 2026
#pragma once

#include <filesystem>

#include <ServicePorts.hpp>

namespace bazarish::setup {

using ports::kPanelPort;

struct Layout {
    std::filesystem::path configDir;
    std::filesystem::path stateDir;
    std::filesystem::path panelAssets;
    std::filesystem::path portalAssets;
};

// False, with nothing written, once any of the four configs is there.
bool setUpServer(const Layout& layout);

}  // namespace bazarish::setup
