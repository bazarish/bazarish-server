// Bazarish project (c) 2026
#pragma once

#include <bazarish/GatewayProtocol.hpp>

#include <bazarish/ConfigFile.hpp>

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace bazarish::gateway {

inline constexpr const char* kVersion = "0.0.1";

struct Settings {
    std::string listenHost = "127.0.0.1";
    int listenPort = 0;
    std::string basePath;
    std::string token;
    std::filesystem::path stateDir;
    std::vector<std::string> reseedUrls;
    std::size_t decoyMinBytes = kDecoyMinBytes;
    std::size_t decoyMaxBytes = kDecoyMaxBytes;
    std::string notFoundBody;
    std::string serverName = "nginx";
    std::vector<std::string> operators;
    std::int64_t sessionTtlSeconds = kSessionTtl.count();

    static Settings from(const ConfigView& config);
};

}  // namespace bazarish::gateway
