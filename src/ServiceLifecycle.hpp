// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "LedgerStore.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

namespace bazarish::service {

// Auto-renews the user's term-based paid services from their prepaid balance and
// projects when each will lapse given the current balance. It is the single
// source of truth for the i2pDest enable/disable toggle and the negative-balance
// grace, so the account API, the portal and the status endpoint all agree.
//
// Renewal rules differ per service:
//   * i2pDest — one step into the negative is allowed (a grace term served on
//     credit); refused once the balance is already negative. Stays "enabled"
//     across a lapse so a later top-up auto-revives it; the user turns it off
//     explicitly via disableI2pDest.
//   * storage — strict: when the balance cannot cover a renewal the upgrade
//     drops to the free quota (a visible shrink, pushed to the messaging server)
//     and stops auto-renewing; the user re-buys to restore it.
//
// evaluate() is the catch-up: it runs the elapsed renewals (mutating the ledger
// and grants) and is called wherever a client touches the node (status poll,
// transient upload, subscribe). It is serialized so concurrent calls cannot
// double-charge.
class ServiceLifecycle {
public:
    struct Plan {
        std::uint64_t priceAtomic = 0;
        std::int64_t termSeconds = 0;
    };
    using PublishQuotaFn = std::function<void(const std::string& user, std::uint64_t quotaBytes)>;
    // Pushes an empty transient to the messaging server, dropping the user's
    // personal destination (used when the i2pDest toggle is turned off).
    using RevokeI2pFn = std::function<void(const std::string& user)>;

    ServiceLifecycle(GrantStore& grants, LedgerStore& ledger, Plan i2pDest, Plan storage,
        std::uint64_t storageQuotaBytes, std::uint64_t freeQuotaBytes,
        PublishQuotaFn publishQuota = {}, RevokeI2pFn revokeI2p = {});

    struct ServiceState {
        bool enabled = false;
        bool active = false;
        std::int64_t paidThrough = 0;
        // When the service will lapse if the balance is not topped up. Zero when
        // it is already off.
        std::int64_t projectedShutoff = 0;
    };
    struct Snapshot {
        ServiceState i2pDest;
        ServiceState storage;
        std::int64_t balanceAtomic = 0;
        // The user's current effective storage quota (paid plan while active,
        // otherwise the free quota).
        std::uint64_t storageQuotaBytes = 0;
        // The provisioned i2pDest transient's recorded validity.
        std::int64_t transientExpires = 0;
        std::int64_t transientUpdatedAt = 0;
    };

    // Runs elapsed renewals for both services, then returns the resulting state
    // with honest forward-projected shutoff dates. Mutating; serialized.
    Snapshot evaluate(const std::string& user, std::int64_t now);

    // Turns the i2pDest toggle on. Resumes immediately if the entitlement is
    // still paid; otherwise charges one term up front (strict — it needs a
    // non-negative balance covering the price). Returns false if it cannot be
    // paid, true once active.
    bool enableI2pDest(const std::string& user, std::int64_t now);

    // Turns the i2pDest toggle off: stops auto-renewing and revokes the personal
    // destination (the user falls back to their fixed pool address). The paid
    // term, if any, is left intact.
    void disableI2pDest(const std::string& user, std::int64_t now);

private:
    GrantStore& grants_;
    LedgerStore& ledger_;
    Plan i2pDest_;
    Plan storage_;
    std::uint64_t storageQuotaBytes_;
    std::uint64_t freeQuotaBytes_;
    PublishQuotaFn publishQuota_;
    RevokeI2pFn revokeI2p_;
    std::mutex mutex_;
};

}  // namespace bazarish::service
