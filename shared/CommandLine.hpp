// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <variant>

namespace bazarish::server {

inline constexpr int kUsageExitCode = 2;

// "--version" prints the banner and asks for 0; anything but "--config <path>" prints the usage.
std::variant<std::filesystem::path, int> configArgument(int argc, const char* const* argv,
    const std::string& banner, const std::function<void()>& printUsage);

}  // namespace bazarish::server
