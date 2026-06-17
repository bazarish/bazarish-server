// Bazarish project (c) 2026
#include "LedgerStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#define CHECK_THROWS(expression)                                                       \
    do {                                                                               \
        bool thrown = false;                                                           \
        try {                                                                          \
            (void)(expression);                                                        \
        } catch (const std::exception&) {                                              \
            thrown = true;                                                             \
        }                                                                              \
        if (!thrown) {                                                                 \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d\n", __FILE__, __LINE__); \
            std::exit(1);                                                              \
        }                                                                              \
    } while (false)

using namespace bazarish;
using namespace bazarish::service;

int main()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / ("bazarish-ledger-" + toHex(randomBytes(8)));
    const std::string user = Identity::generate().fingerprint();
    const std::int64_t t = 1000;

    {
        LedgerStore ledger(root, "XMR");

        const LedgerStore::Account empty = ledger.get(user);
        CHECK(empty.balanceAtomic == 0);
        CHECK(empty.entries.empty());
        CHECK(empty.currency == "XMR");

        CHECK(ledger.credit(user, 1000, "topup:tx1", t) == 1000);
        CHECK(ledger.credit(user, 500, "topup:tx2", t + 1) == 1500);

        CHECK(ledger.debit(user, 700, "buy:username", t + 2));
        const LedgerStore::Account afterDebit = ledger.get(user);
        CHECK(afterDebit.balanceAtomic == 800);
        CHECK(afterDebit.entries.size() == 3);
        CHECK(afterDebit.entries.back().type == "debit");
        CHECK(afterDebit.entries.back().amountAtomic == 700);
        CHECK(afterDebit.entries.back().balanceAfter == 800);

        // Insufficient balance: rejected, nothing changes.
        CHECK(!ledger.debit(user, 100000, "buy:storage", t + 3));
        CHECK(ledger.get(user).balanceAtomic == 800);
        CHECK(ledger.get(user).entries.size() == 3);

        // Zero amounts are rejected (a no-op debit; a zero top-up throws).
        CHECK(!ledger.debit(user, 0, "noop", t + 4));
        CHECK_THROWS(ledger.credit(user, 0, "noop", t + 4));

        // A non-fingerprint is rejected.
        CHECK_THROWS(ledger.get("not-a-fingerprint"));
    }

    // Overdraft: one step into the negative is allowed, a second is refused
    // until a top-up clears the debt (the i2pDest grace).
    {
        LedgerStore ledger(root, "XMR");
        const std::string grace = Identity::generate().fingerprint();
        ledger.credit(grace, 30, "topup", t);
        // Strict debit cannot exceed balance; overdraft can, once.
        CHECK(!ledger.debit(grace, 100, "renew", t));
        CHECK(ledger.get(grace).balanceAtomic == 30);
        CHECK(ledger.debitOverdraft(grace, 100, "renew:i2pDest", t));
        CHECK(ledger.get(grace).balanceAtomic == -70);
        // While negative, both debit and a second overdraft are refused.
        CHECK(!ledger.debitOverdraft(grace, 100, "renew:i2pDest", t + 1));
        CHECK(!ledger.debit(grace, 1, "buy", t + 1));
        CHECK(ledger.get(grace).balanceAtomic == -70);
        // A top-up clears the debt and re-arms the overdraft.
        CHECK(ledger.credit(grace, 200, "topup2", t + 2) == 130);
        CHECK(ledger.debitOverdraft(grace, 200, "renew:i2pDest", t + 3));
        CHECK(ledger.get(grace).balanceAtomic == -70);
    }

    // Persistence across reopen.
    {
        LedgerStore reopened(root, "XMR");
        const LedgerStore::Account account = reopened.get(user);
        CHECK(account.balanceAtomic == 800);
        CHECK(account.entries.size() == 3);
        CHECK(account.entries.front().type == "credit");
        CHECK(account.entries.front().ref == "topup:tx1");
    }

    fs::remove_all(root);
    std::printf("TestLedger: all checks passed\n");
    return 0;
}
