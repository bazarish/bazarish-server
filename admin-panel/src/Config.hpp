// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace bazarish::admin {

inline constexpr const char* kServerCoreKind = "server-core";
inline constexpr const char* kServiceNodeKind = "service-node";
inline constexpr const char* kFacadeKind = "facade";
inline constexpr const char* kGatewayKind = "gateway";

struct ServiceEntry {
    std::string name;
    std::string kind;
    std::string url;
    std::string pin;

    friend bool operator==(const ServiceEntry&, const ServiceEntry&) = default;
};

struct Fleet {
    std::string name;
    std::vector<ServiceEntry> services;

    friend bool operator==(const Fleet&, const Fleet&) = default;
};

bool isKnownServiceKind(const std::string& kind);

void requireCoherentFleet(const Fleet& fleet);

nlohmann::json fleetsJson(const std::vector<Fleet>& fleets);

struct Config {
    std::vector<std::string> admins;
    std::string stateDir;
    std::string assetsDir;
    service::LoginConsumer consumer;
    std::string listenHost = "127.0.0.1";
    int listenPort = 8460;
    std::vector<Fleet> fleets;

    static Config fromJson(const std::string& text);

    static Config fromFile(const std::string& path);
};

}  // namespace bazarish::admin
