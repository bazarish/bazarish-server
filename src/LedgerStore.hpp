// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::service {

// Per-user prepaid balance plus an append-only ledger of money movements, in
// atomic units of one settlement currency (piconero for monerod). A confirmed
// top-up credits the balance; buying a paid service debits it. The ledger is
// the account history the portal shows, and every entry records the balance
// after it, so the running total is auditable.
//
// Layout: <root>/ledger/<fingerprint>.json
//   { "currency", "balanceAtomic", "entries":[{ts,type,amountAtomic,ref,balanceAfter}] }
class LedgerStore {
public:
    struct Entry {
        std::int64_t ts = 0;
        std::string type;  // "credit" | "debit"
        std::uint64_t amountAtomic = 0;
        std::string ref;  // e.g. "topup:<txid>", "buy:username"
        std::uint64_t balanceAfter = 0;
    };

    struct Account {
        std::string currency;
        std::uint64_t balanceAtomic = 0;
        std::vector<Entry> entries;
    };

    LedgerStore(std::filesystem::path root, std::string currency);

    // The account; a zero balance with no history when never touched.
    Account get(const std::string& user);

    // Every account fingerprint that has a ledger file, for aggregate/admin
    // views (total balances, total payments). A read-only directory scan.
    std::vector<std::string> users();

    // Credits the balance (a confirmed top-up) and appends an entry; returns the
    // new balance. Throws on a zero amount or on balance overflow.
    std::uint64_t credit(
        const std::string& user, std::uint64_t amount, const std::string& ref, std::int64_t now);

    // Idempotent credit by ref: if a credit with this ref was already applied,
    // makes no change and returns false; otherwise credits and returns true.
    // Lets poll, webhook and txid notifications for one invoice race safely.
    bool creditOnce(
        const std::string& user, std::uint64_t amount, const std::string& ref, std::int64_t now);

    // Debits the balance for a purchase and appends an entry. Returns false and
    // changes nothing when the amount is zero or exceeds the balance.
    bool debit(
        const std::string& user, std::uint64_t amount, const std::string& ref, std::int64_t now);

private:
    std::filesystem::path accountPath(const std::string& user) const;
    Account load(const std::string& user) const;
    void save(const std::string& user, const Account& account) const;

    std::filesystem::path root_;
    std::string currency_;
    std::mutex mutex_;
};

}  // namespace bazarish::service
