// Bazarish project (c) 2026
#include "GrantStore.hpp"
#include "LedgerStore.hpp"
#include "ServiceLifecycle.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;
using namespace bazarish::service;

namespace {

constexpr std::int64_t kTerm = 100;          // term length in seconds (test scale)
constexpr std::uint64_t kI2pPrice = 100;     // i2pDest price per term
constexpr std::uint64_t kStoragePrice = 50;  // storage price per term
constexpr std::uint64_t kStorageQuota = 5ULL * 1024 * 1024 * 1024;
constexpr std::uint64_t kFreeQuota = 10ULL * 1024 * 1024;

}  // namespace

int main()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-svclife-" + toHex(randomBytes(8)));
    fs::create_directories(root);

    std::vector<std::string> revoked;
    std::vector<std::pair<std::string, std::uint64_t>> quotaPushes;

    GrantStore grants(root);
    LedgerStore ledger(root, "XMR");
    ServiceLifecycle life(grants, ledger, {kI2pPrice, kTerm}, {kStoragePrice, kTerm}, kStorageQuota,
        kFreeQuota,
        [&quotaPushes](const std::string& user, const std::uint64_t quota) {
            quotaPushes.push_back({user, quota});
        },
        [&revoked](const std::string& user) { revoked.push_back(user); });

    // --- i2pDest: enable, auto-renew, one-step grace, lapse, revive ---
    {
        const std::string user = Identity::generate().fingerprint();
        // Cannot enable with an empty balance.
        CHECK(!life.enableI2pDest(user, 1000));
        ledger.credit(user, 250, "topup", 1000);
        CHECK(life.enableI2pDest(user, 1000));  // debits one term: 250 -> 150
        CHECK(ledger.get(user).balanceAtomic == 150);

        ServiceLifecycle::Snapshot s = life.evaluate(user, 1000);
        CHECK(s.i2pDest.enabled && s.i2pDest.active);
        CHECK(s.i2pDest.paidThrough == 1100);
        CHECK(s.balanceAtomic == 150);

        s = life.evaluate(user, 1100);  // first renewal: 150 -> 50
        CHECK(s.i2pDest.active && s.i2pDest.paidThrough == 1200);
        CHECK(s.balanceAtomic == 50);

        s = life.evaluate(user, 1200);  // grace renewal into the negative: 50 -> -50
        CHECK(s.i2pDest.active && s.i2pDest.paidThrough == 1300);
        CHECK(s.balanceAtomic == -50);

        s = life.evaluate(user, 1300);  // grace spent: refused, lapses (still enabled)
        CHECK(s.i2pDest.enabled && !s.i2pDest.active);
        CHECK(s.balanceAtomic == -50);  // no further debit while negative

        ledger.credit(user, 200, "topup2", 1300);  // -50 -> 150 clears the debt
        s = life.evaluate(user, 1300);              // auto-revives: 150 -> 50
        CHECK(s.i2pDest.active && s.i2pDest.paidThrough == 1400);
        CHECK(s.balanceAtomic == 50);
    }

    // --- i2pDest: disable revokes and falls back to the pool ---
    {
        const std::string user = Identity::generate().fingerprint();
        ledger.credit(user, 500, "topup", 1000);
        CHECK(life.enableI2pDest(user, 1000));
        const std::size_t before = revoked.size();
        life.disableI2pDest(user, 1000);
        CHECK(revoked.size() == before + 1 && revoked.back() == user);
        const ServiceLifecycle::Snapshot s = life.evaluate(user, 1000);
        CHECK(!s.i2pDest.enabled && !s.i2pDest.active);
    }

    // --- i2pDest: re-enable while still paid resumes without charging again ---
    {
        const std::string user = Identity::generate().fingerprint();
        ledger.credit(user, 100, "topup", 1000);
        CHECK(life.enableI2pDest(user, 1000));  // 100 -> 0, paidThrough 1100
        CHECK(ledger.get(user).balanceAtomic == 0);
        life.disableI2pDest(user, 1010);
        CHECK(life.enableI2pDest(user, 1010));  // still paid (<1100): no charge
        CHECK(ledger.get(user).balanceAtomic == 0);
        const ServiceLifecycle::Snapshot s = life.evaluate(user, 1010);
        CHECK(s.i2pDest.enabled && s.i2pDest.active && s.i2pDest.paidThrough == 1100);
    }

    // --- storage: strict auto-renew, lapses to the free quota and pushes it ---
    {
        const std::string user = Identity::generate().fingerprint();
        ledger.credit(user, 60, "topup", 1000);
        grants.grantService(user, "storage", 1100, 1000);  // simulate a purchase

        ServiceLifecycle::Snapshot s = life.evaluate(user, 1000);
        CHECK(s.storage.active && s.storageQuotaBytes == kStorageQuota);

        s = life.evaluate(user, 1100);  // renew once: 60 -> 10
        CHECK(s.storage.active && s.storageQuotaBytes == kStorageQuota);
        CHECK(s.balanceAtomic == 10);

        const std::size_t pushesBefore = quotaPushes.size();
        s = life.evaluate(user, 1200);  // 10 < 50: cannot renew -> drop to free
        CHECK(!s.storage.active && s.storageQuotaBytes == kFreeQuota);
        CHECK(s.balanceAtomic == 10);  // strict: not debited into the negative
        CHECK(quotaPushes.size() == pushesBefore + 1);
        CHECK(quotaPushes.back().first == user && quotaPushes.back().second == kFreeQuota);

        // Lapsed storage does not auto-revive even after a top-up (re-buy needed).
        ledger.credit(user, 1000, "topup2", 1200);
        s = life.evaluate(user, 1300);
        CHECK(!s.storage.active && s.storageQuotaBytes == kFreeQuota);
    }

    // --- projection: honest forward shutoff for i2pDest (incl. grace) ---
    {
        const std::string user = Identity::generate().fingerprint();
        ledger.credit(user, 250, "topup", 1000);
        CHECK(life.enableI2pDest(user, 1000));  // 250 -> 150, paidThrough 1100
        const ServiceLifecycle::Snapshot s = life.evaluate(user, 1000);
        // balance 150 covers 1100 (->50) and grace at 1200 (->-50); refused at 1300.
        CHECK(s.i2pDest.projectedShutoff == 1300);
    }

    fs::remove_all(root);
    std::printf("TestServiceLifecycle: all checks passed\n");
    return 0;
}
