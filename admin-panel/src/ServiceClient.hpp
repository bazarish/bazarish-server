// Bazarish project (c) 2026
#pragma once

#include "Config.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace bazarish {
class Identity;
}

namespace bazarish::admin {

struct HealthResult {
    bool reachable = false;
    int status = 0;
    std::string error;
    long latencyMs = 0;
    std::string version;
    std::int64_t uptime = 0;
    std::uint64_t ramBytes = 0;
    std::uint64_t ramPeakBytes = 0;
    std::uint64_t requestsLastMinute = 0;
    std::uint64_t requestsLastHour = 0;
    std::uint64_t requestsLastDay = 0;
    std::uint64_t inFlight = 0;
};

HealthResult probeHealth(const ServiceEntry& service, const Identity& identity);

struct JsonResult {
    bool ok = false;
    int status = 0;
    std::string body;
    std::string error;
};

JsonResult callJson(const ServiceEntry& service, const Identity& identity,
    const std::string& method, const std::string& path, const std::string& body = {});

}  // namespace bazarish::admin
