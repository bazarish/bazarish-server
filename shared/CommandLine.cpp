// Bazarish project (c) 2026
#include "CommandLine.hpp"

#include <cstdio>
#include <string_view>

namespace bazarish::server {

std::variant<std::filesystem::path, int> configArgument(const int argc, const char* const* argv,
    const std::string& banner, const std::function<void()>& printUsage)
{
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::printf("%s\n", banner.c_str());
        return 0;
    }
    if (argc != 3 || std::string_view(argv[1]) != "--config") {
        printUsage();
        return kUsageExitCode;
    }
    return std::filesystem::path(argv[2]);
}

}  // namespace bazarish::server
