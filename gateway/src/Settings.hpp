// Bazarish project (c) 2026
#pragma once

#include "Conduit.hpp"

#include <bazarish/GatewayProtocol.hpp>

#include <bazarish/ConfigFile.hpp>
#include <bazarish/I2p.hpp>

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace bazarish::gateway {

inline constexpr const char* kVersion = "0.0.1";
inline constexpr std::size_t kDefaultStreamPool = 4;
inline constexpr std::size_t kDefaultCallPool = 2;
inline constexpr std::size_t kMaxPoolDepth = 16;

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
    std::vector<DirectRoute> direct;
    std::string opsHost;
    int opsPort = 0;
    std::vector<std::string> opsClients;
    std::int64_t sessionTtlSeconds = kSessionTtl.count();
    i2p::Privacy tunnelPrivacy = i2p::Privacy::eMinimal;
    int tunnelQuantity = i2p::kDefaultTunnelQuantity;
    std::size_t streamPool = kDefaultStreamPool;
    std::size_t callPool = kDefaultCallPool;

    static Settings from(const ConfigView& config);
};

std::vector<DirectRoute> directRoutesFrom(const nlohmann::json& list);

}  // namespace bazarish::gateway
