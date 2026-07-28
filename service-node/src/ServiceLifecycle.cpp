// Bazarish project (c) 2026
#include "ServiceLifecycle.hpp"

#include <algorithm>
#include <optional>
#include <utility>
#include <vector>

namespace bazarish::service {

ServiceLifecycle::ServiceLifecycle(GrantStore& grants, LedgerStore& ledger, Plan i2pDest,
    Plan storage, const std::uint64_t storageQuotaBytes, const std::uint64_t freeQuotaBytes,
    PublishQuotaFn publishQuota, RevokeI2pFn revokeI2p)
    : grants_(grants)
    , ledger_(ledger)
    , i2pDest_(i2pDest)
    , storage_(storage)
    , storageQuotaBytes_(storageQuotaBytes)
    , freeQuotaBytes_(freeQuotaBytes)
    , publishQuota_(std::move(publishQuota))
    , revokeI2p_(std::move(revokeI2p))
{
}

namespace {

// A service in the forward projection: it draws on the shared balance at its
// renewal dates until the balance cannot cover the next charge.
struct Sim {
    ServiceLifecycle::ServiceState* state = nullptr;
    std::uint64_t price = 0;
    std::int64_t term = 0;
    std::int64_t paidThrough = 0;
    bool overdraft = false;  // i2pDest may go one step negative; storage is strict
    bool active = false;
};

// Walks the renewal schedule forward from the remaining balance (no income), in
// chronological order, recording where each service lapses. The balance strictly
// decreases on every charge, so this terminates; the guard only bounds a
// pathological tiny-price/huge-balance config.
void projectShutoffs(std::int64_t balance, std::vector<Sim>& sims)
{
    for (int guard = 0; guard < 200000; ++guard) {
        Sim* next = nullptr;
        for (Sim& s : sims) {
            if (s.active && (next == nullptr || s.paidThrough < next->paidThrough)) {
                next = &s;
            }
        }
        if (next == nullptr) {
            return;
        }
        const std::int64_t price = static_cast<std::int64_t>(next->price);
        const bool canPay = next->overdraft ? (balance >= 0) : (balance >= price);
        if (canPay) {
            balance -= price;
            next->paidThrough += next->term;
        } else {
            next->state->projectedShutoff = next->paidThrough;
            next->active = false;
        }
    }
}

}  // namespace

ServiceLifecycle::Snapshot ServiceLifecycle::evaluate(const std::string& user, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    Snapshot snap;

    // i2pDest: auto-renew with the one-step overdraft grace.
    {
        const std::optional<GrantStore::ServiceGrant> g = grants_.peekService(user, "i2pDest");
        if (g.has_value()) {
            snap.i2pDest.enabled = g->enabled;
            snap.i2pDest.paidThrough = g->paidThrough;
            snap.transientExpires = g->transientExpires;
            snap.transientUpdatedAt = g->transientUpdatedAt;
            if (g->enabled && i2pDest_.termSeconds > 0 && i2pDest_.priceAtomic > 0) {
                std::int64_t paidThrough = g->paidThrough;
                while (now >= paidThrough) {
                    if (!ledger_.debitOverdraft(user, i2pDest_.priceAtomic, "renew:i2pDest", now)) {
                        break;  // already in debt - the grace is spent, it lapses
                    }
                    paidThrough += i2pDest_.termSeconds;
                    grants_.grantService(user, "i2pDest", paidThrough, now);
                }
                snap.i2pDest.paidThrough = paidThrough;
            }
            snap.i2pDest.active = snap.i2pDest.enabled && now < snap.i2pDest.paidThrough;
        }
    }

    // storage: strict auto-renew; lapses to the free quota and stops.
    std::uint64_t effectiveQuota = freeQuotaBytes_;
    {
        const std::optional<GrantStore::ServiceGrant> g = grants_.peekService(user, "storage");
        if (g.has_value()) {
            snap.storage.enabled = g->enabled;
            snap.storage.paidThrough = g->paidThrough;
            if (g->enabled && storage_.termSeconds > 0 && storage_.priceAtomic > 0) {
                std::int64_t paidThrough = g->paidThrough;
                bool lapsed = false;
                while (now >= paidThrough) {
                    if (!ledger_.debit(user, storage_.priceAtomic, "renew:storage", now)) {
                        lapsed = true;
                        break;
                    }
                    paidThrough += storage_.termSeconds;
                    grants_.grantService(user, "storage", paidThrough, now);
                }
                snap.storage.paidThrough = paidThrough;
                if (lapsed) {
                    grants_.setServiceEnabled(user, "storage", false);
                    snap.storage.enabled = false;
                    if (publishQuota_) {
                        publishQuota_(user, freeQuotaBytes_);
                    }
                }
            }
            snap.storage.active = snap.storage.enabled && now < snap.storage.paidThrough;
            if (snap.storage.active) {
                effectiveQuota = storageQuotaBytes_;
            }
        }
    }
    snap.storageQuotaBytes = effectiveQuota;

    snap.balanceAtomic = ledger_.get(user).balanceAtomic;

    // Forward-project lapse dates from the remaining balance. An active service
    // that cannot auto-renew (config-disabled) simply lapses at its paid-through.
    std::vector<Sim> sims;
    if (snap.i2pDest.active) {
        if (i2pDest_.termSeconds > 0 && i2pDest_.priceAtomic > 0) {
            sims.push_back({&snap.i2pDest, i2pDest_.priceAtomic, i2pDest_.termSeconds,
                snap.i2pDest.paidThrough, true, true});
        } else {
            snap.i2pDest.projectedShutoff = snap.i2pDest.paidThrough;
        }
    }
    if (snap.storage.active) {
        if (storage_.termSeconds > 0 && storage_.priceAtomic > 0) {
            sims.push_back({&snap.storage, storage_.priceAtomic, storage_.termSeconds,
                snap.storage.paidThrough, false, true});
        } else {
            snap.storage.projectedShutoff = snap.storage.paidThrough;
        }
    }
    projectShutoffs(snap.balanceAtomic, sims);
    return snap;
}

bool ServiceLifecycle::enableI2pDest(const std::string& user, const std::int64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (i2pDest_.termSeconds <= 0 || i2pDest_.priceAtomic == 0) {
        return false;  // not offered here
    }
    const std::optional<GrantStore::ServiceGrant> g = grants_.peekService(user, "i2pDest");
    if (g.has_value() && g->paidThrough > now) {
        // Still paid for: just re-arm the toggle (it may have been turned off).
        grants_.setServiceEnabled(user, "i2pDest", true);
        return true;
    }
    if (!ledger_.debit(user, i2pDest_.priceAtomic, "buy:i2pDest", now)) {
        return false;  // top up first
    }
    const std::int64_t base = g.has_value() ? std::max(now, g->paidThrough) : now;
    grants_.grantService(user, "i2pDest", base + i2pDest_.termSeconds, now);
    return true;
}

void ServiceLifecycle::disableI2pDest(const std::string& user, const std::int64_t /*now*/)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    grants_.setServiceEnabled(user, "i2pDest", false);
    if (revokeI2p_) {
        revokeI2p_(user);
    }
}

}  // namespace bazarish::service
