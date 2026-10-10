// Bazarish project (c) 2026
#pragma once

#include "Config.hpp"

#include <map>
#include <string>
#include <vector>

namespace bazarish {
class Identity;
}

namespace bazarish::tls {
struct Credential;
}

namespace bazarish::admin {

struct FacadeReport {
    std::string name;
    std::string url;
    std::string error;
};

std::vector<FacadeReport> facadeReports(
    const Fleet& fleet, const Identity& identity, const tls::Credential& credential);

std::string publishFacades(const Fleet& fleet, const Identity& identity,
    const tls::Credential& credential, const std::map<std::string, std::string>& known = {});

struct GatewayRepoint {
    std::string name;
    bool changed = false;
    std::string error;
};

std::vector<GatewayRepoint> repointGateways(const std::vector<Fleet>& fleets,
    const std::string& fromUrl, const std::string& toUrl, const Identity& identity,
    const tls::Credential& credential);

std::string hostOf(const std::string& url);

}  // namespace bazarish::admin
