// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>

#include <filesystem>

namespace bazarish::server {

Identity loadOrCreateIdentity(const std::filesystem::path& stateDir);

}  // namespace bazarish::server
