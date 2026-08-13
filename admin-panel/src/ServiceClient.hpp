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
};

// Outcome of an operator action.
struct OpResult {
    bool ok = false;
    int status = 0;
    std::string message;
};

// Every call is signed with the panel identity (hybrid request auth); the service
// authorizes the panel fingerprint. There is no shared secret.

// Probes <service.url>/healthz. Short timeouts so a dead service cannot stall the
// dashboard.
HealthResult probeHealth(const ServiceEntry& service, const Identity& identity);

// Sets a user's mailbox quota via the operator endpoint of a server-core
// (/v1/messaging/quota).
OpResult setQuota(const ServiceEntry& service, const Identity& identity, const std::string& user,
    std::uint64_t quotaBytes);

// Provisions or revokes a user's personal I2P destination on server-core
// (/v1/messaging/i2p-dest). An empty transient revokes.
OpResult setI2pDest(const ServiceEntry& service, const Identity& identity,
    const std::string& user, const std::string& transientBase64, std::int64_t expiresUnix);

// One account waiting for the operator on a moderated service node.
struct PendingAccount {
    std::string user;
    std::int64_t requestedAt = 0;
};

// Accounts awaiting approval (GET /v1/account/pending on service-node), oldest
// first. `ok` is false when the node could not be reached or refused the panel.
struct PendingResult {
    bool ok = false;
    std::string error;
    std::vector<PendingAccount> accounts;
};

PendingResult listPending(const ServiceEntry& service, const Identity& identity);

// Approves a frozen account, which lets it delegate its I2P destination.
OpResult approveAccount(
    const ServiceEntry& service, const Identity& identity, const std::string& user);

}  // namespace bazarish::admin
