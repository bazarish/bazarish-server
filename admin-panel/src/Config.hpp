// Bazarish project (c) 2026
#pragma once

#include <bazarish/Portal.hpp>

#include <ServicePorts.hpp>

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

bool isKnownServiceKind(const std::string& kind);

void requireCoherentServices(const std::vector<ServiceEntry>& services);
// Throws std::invalid_argument on a malformed list.
std::vector<ServiceEntry> servicesFromJson(const nlohmann::json& list);

nlohmann::json servicesJson(const std::vector<ServiceEntry>& services);

struct Config {
    std::vector<std::string> admins;
    std::string stateDir;
    std::string assetsDir;
    service::LoginConsumer consumer;
    std::string listenHost = "127.0.0.1";
    int listenPort = ports::kPanelPort;
    std::vector<ServiceEntry> services;

    static Config fromJson(const std::string& text);

    static Config fromFile(const std::string& path);
};

}  // namespace bazarish::admin
