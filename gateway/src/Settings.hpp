// Bazarish project (c) 2026
#pragma once

#include "Conduit.hpp"

#include <bazarish/GatewayProtocol.hpp>

#include <bazarish/ConfigFile.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::gateway {

inline constexpr std::size_t kDefaultStreamPool = 4;
inline constexpr std::size_t kDefaultCallPool = 2;
inline constexpr std::size_t kDefaultWatchPool = 2;
inline constexpr std::size_t kMaxPoolDepth = 16;

struct Settings {
    std::string listenHost = "127.0.0.1";
    int listenPort = 0;
    std::string basePath;
    // Where clients reach the front: "https://host[:port]", no path. Empty: not told yet.
    std::string publicAddress;
    std::filesystem::path stateDir;
    std::vector<std::string> reseedUrls;
    std::size_t decoyMinBytes = kDecoyMinBytes;
    std::size_t decoyMaxBytes = kDecoyMaxBytes;
    std::string notFoundBody;
    std::string serverName = "nginx";
    std::vector<std::string> operators;
    std::vector<DirectRoute> direct;
    std::optional<ServerLink> server;
    std::string opsHost;
    int opsPort = 0;
    std::vector<std::string> opsClients;
    std::int64_t sessionTtlSeconds = kSessionTtl.count();
    i2p::Privacy tunnelPrivacy = i2p::Privacy::eMinimal;
    std::size_t streamPool = kDefaultStreamPool;
    std::size_t callPool = kDefaultCallPool;
    std::size_t watchPool = kDefaultWatchPool;
    log::Level logLevel = log::Level::eInfo;
    i2p::I2pLogLevel i2pLogLevel = i2p::I2pLogLevel::eNone;

    static Settings from(const ConfigView& config);
};

std::vector<DirectRoute> directRoutesFrom(const nlohmann::json& list);
std::string publicAddressFrom(const std::string& text);
std::string clientLink(const Settings& settings, const std::string& fingerprint);
std::optional<ServerLink> serverLinkFrom(const nlohmann::json& link);

}  // namespace bazarish::gateway
