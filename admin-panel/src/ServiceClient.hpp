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

// Outcome of a /healthz probe. `reachable` is true only on a 200 with a parseable
// body; `status` and `error` describe other cases (no response, or e.g. a 403
// when the panel identity is not an authorized operator, which still means the
// service is up).
struct HealthResult {
    bool reachable = false;
    int status = 0;
    std::string error;
    long latencyMs = 0;
    std::string version;
    std::int64_t uptime = 0;
    std::uint64_t ramBytes = 0;
    std::uint64_t ramPeakBytes = 0;
    // What a facade is carrying: the counts it samples for the panel. Zero for
    // every other kind of service, which reports none of this.
    std::uint64_t requestsLastMinute = 0;
    std::uint64_t requestsLastHour = 0;
    std::uint64_t requestsLastDay = 0;
    std::uint64_t inFlight = 0;
    // Server-core only: the warm pool its contact-card lookups dial from, which
    // an operator watches for load.
    std::uint64_t warmPoolReady = 0;
    std::uint64_t warmPoolTarget = 0;
};

// Every call is signed with the panel identity (hybrid request auth); the service
// authorizes the panel fingerprint. There is no shared secret.

// Probes <service.url>/healthz. Short timeouts so a dead service cannot stall the
// dashboard.
HealthResult probeHealth(const ServiceEntry& service, const Identity& identity);

// A service's own answer, passed through as it came. The panel's browser side
// reads the same JSON the service speaks, so a field added on a service reaches
// the screen without a second schema in the middle.
struct JsonResult {
    bool ok = false;  // the service answered 2xx
    int status = 0;   // 0 when nothing answered at all
    std::string body;
    std::string error;
};

// One signed request to a service, returning its body verbatim.
JsonResult callJson(const ServiceEntry& service, const Identity& identity,
    const std::string& method, const std::string& path, const std::string& body = {});

}  // namespace bazarish::admin
