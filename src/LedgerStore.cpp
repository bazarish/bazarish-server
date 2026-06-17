// Bazarish project (c) 2026
#include "LedgerStore.hpp"

#include <bazarish/Address.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <limits>
#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

namespace fs = std::filesystem;

void requireUser(const std::string& user)
{
    if (!isFingerprint(user)) {
        throw std::invalid_argument("user is not a fingerprint");
    }
}

void writeFileAtomic(const fs::path& target, const std::string& text)
{
    const fs::path temporary = target.parent_path() / (target.filename().string() + ".tmp");
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("failed to open " + temporary.string());
        }
        out << text;
        if (!out) {
            throw std::runtime_error("failed to write " + temporary.string());
        }
    }
    fs::rename(temporary, target);
}

nlohmann::json readJsonFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return nlohmann::json::parse(in);
}

}  // namespace

LedgerStore::LedgerStore(fs::path root, std::string currency)
    : root_(std::move(root))
    , currency_(std::move(currency))
{
    fs::create_directories(root_ / "ledger");
}

fs::path LedgerStore::accountPath(const std::string& user) const
{
    return root_ / "ledger" / (user + ".json");
}

LedgerStore::Account LedgerStore::load(const std::string& user) const
{
    Account account;
    account.currency = currency_;
    const fs::path path = accountPath(user);
    if (!fs::exists(path)) {
        return account;
    }
    const nlohmann::json body = readJsonFile(path);
    account.currency = body.value("currency", currency_);
    account.balanceAtomic = body.at("balanceAtomic").get<std::int64_t>();
    for (const nlohmann::json& item : body.at("entries")) {
        Entry entry;
        entry.ts = item.at("ts").get<std::int64_t>();
        entry.type = item.at("type").get<std::string>();
        entry.amountAtomic = item.at("amountAtomic").get<std::uint64_t>();
        entry.ref = item.at("ref").get<std::string>();
        entry.balanceAfter = item.at("balanceAfter").get<std::int64_t>();
        account.entries.push_back(std::move(entry));
    }
    return account;
}

void LedgerStore::save(const std::string& user, const Account& account) const
{
    nlohmann::json entries = nlohmann::json::array();
    for (const Entry& entry : account.entries) {
        entries.push_back({
            {"ts", entry.ts},
            {"type", entry.type},
            {"amountAtomic", entry.amountAtomic},
            {"ref", entry.ref},
            {"balanceAfter", entry.balanceAfter},
        });
    }
    const nlohmann::json body = {
        {"currency", account.currency},
        {"balanceAtomic", account.balanceAtomic},
        {"entries", entries},
    };
    writeFileAtomic(accountPath(user), body.dump());
}

LedgerStore::Account LedgerStore::get(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    return load(user);
}

std::vector<std::string> LedgerStore::users()
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    const fs::path dir = root_ / "ledger";
    if (!fs::exists(dir)) {
        return result;
    }
    for (const fs::directory_entry& item : fs::directory_iterator(dir)) {
        if (item.is_regular_file() && item.path().extension() == ".json") {
            result.push_back(item.path().stem().string());
        }
    }
    return result;
}

namespace {

// The largest movement that fits the signed balance. Amounts are passed as
// unsigned (a magnitude); a single account never approaches this in practice
// (it is half the unsigned ceiling, ~9.2e18 piconero), so this only rejects
// nonsense.
bool amountFitsSigned(const std::uint64_t amount)
{
    return amount <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
}

}  // namespace

std::int64_t LedgerStore::credit(
    const std::string& user, const std::uint64_t amount, const std::string& ref, std::int64_t now)
{
    requireUser(user);
    if (amount == 0) {
        throw std::invalid_argument("credit amount must be positive");
    }
    if (!amountFitsSigned(amount)) {
        throw std::overflow_error("ledger credit amount too large");
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    Account account = load(user);
    const std::int64_t add = static_cast<std::int64_t>(amount);
    if (account.balanceAtomic > std::numeric_limits<std::int64_t>::max() - add) {
        throw std::overflow_error("ledger balance overflow");
    }
    account.balanceAtomic += add;
    account.entries.push_back({now, "credit", amount, ref, account.balanceAtomic});
    save(user, account);
    return account.balanceAtomic;
}

bool LedgerStore::creditOnce(
    const std::string& user, const std::uint64_t amount, const std::string& ref, std::int64_t now)
{
    requireUser(user);
    if (amount == 0) {
        throw std::invalid_argument("credit amount must be positive");
    }
    if (!amountFitsSigned(amount)) {
        throw std::overflow_error("ledger credit amount too large");
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    Account account = load(user);
    for (const Entry& entry : account.entries) {
        if (entry.type == "credit" && entry.ref == ref) {
            return false;  // already applied — duplicate notification
        }
    }
    const std::int64_t add = static_cast<std::int64_t>(amount);
    if (account.balanceAtomic > std::numeric_limits<std::int64_t>::max() - add) {
        throw std::overflow_error("ledger balance overflow");
    }
    account.balanceAtomic += add;
    account.entries.push_back({now, "credit", amount, ref, account.balanceAtomic});
    save(user, account);
    return true;
}

bool LedgerStore::debit(
    const std::string& user, const std::uint64_t amount, const std::string& ref, std::int64_t now)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    Account account = load(user);
    if (amount == 0 || !amountFitsSigned(amount)) {
        return false;
    }
    const std::int64_t sub = static_cast<std::int64_t>(amount);
    if (sub > account.balanceAtomic) {
        return false;  // a purchase never takes the balance below zero
    }
    account.balanceAtomic -= sub;
    account.entries.push_back({now, "debit", amount, ref, account.balanceAtomic});
    save(user, account);
    return true;
}

bool LedgerStore::debitOverdraft(
    const std::string& user, const std::uint64_t amount, const std::string& ref, std::int64_t now)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    Account account = load(user);
    if (amount == 0 || !amountFitsSigned(amount)) {
        return false;
    }
    if (account.balanceAtomic < 0) {
        return false;  // grace already spent — top up to re-arm it
    }
    account.balanceAtomic -= static_cast<std::int64_t>(amount);  // may go negative once
    account.entries.push_back({now, "debit", amount, ref, account.balanceAtomic});
    save(user, account);
    return true;
}

}  // namespace bazarish::service
