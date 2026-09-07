// Bazarish project (c) 2026
#include "SubscriptionStore.hpp"

#include <bazarish/Log.hpp>

#include <bazarish/Address.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>
#include <system_error>

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

SubscriptionStore::SubscriptionStore(const fs::path& root)
    : root_(root)
{
    fs::create_directories(root_ / "subscriptions");
}

fs::path SubscriptionStore::accountPath(const std::string& user) const
{
    return root_ / "subscriptions" / (user + ".json");
}

void SubscriptionStore::putAccount(const Account& account)
{
    requireUser(account.user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const nlohmann::json body = {
        {"user", account.user},
        {"registeredAt", account.registeredAt},
        {"quotaBytes", account.quotaBytes},
        {"dest", account.dest},
        {"delegatedAt", account.delegatedAt},
        {"view", account.view},
        {"pendingView", account.pendingView},
        {"pendingServingKey", account.pendingServingKey},
        {"card", toBase64(account.card)},
    };
    writeFileAtomic(accountPath(account.user), body.dump());
}

namespace {

SubscriptionStore::Account accountFromJson(const nlohmann::json& body)
{
    SubscriptionStore::Account account;
    account.user = body.at("user").get<std::string>();
    account.registeredAt = body.at("registeredAt").get<std::int64_t>();
    account.quotaBytes = body.at("quotaBytes").get<std::uint64_t>();
    account.dest = body.value("dest", std::string());
    account.delegatedAt = body.value("delegatedAt", std::int64_t{0});
    account.view = body.value("view", std::string());
    account.pendingView = body.value("pendingView", std::string());
    account.pendingServingKey = body.value("pendingServingKey", std::string());
    account.card = fromBase64(body.value("card", std::string()));
    return account;
}

}  // namespace

std::optional<SubscriptionStore::Account> SubscriptionStore::getAccount(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = accountPath(user);
    if (!fs::exists(path)) {
        return std::nullopt;
    }
    return accountFromJson(readJsonFile(path));
}

std::vector<SubscriptionStore::Account> SubscriptionStore::allAccounts() const
{
    std::vector<Account> out;
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    std::filesystem::directory_iterator entries(root_ / "subscriptions", ec);
    if (ec) {
        return out;  // none stored yet: not an error
    }
    for (const auto& entry : entries) {
        if (!entry.is_regular_file()) {
            continue;
        }
        try {
            out.push_back(accountFromJson(readJsonFile(entry.path())));
        } catch (const std::exception& error) {
            bazarish::log::warn("account record {} unreadable: {}",
                bazarish::log::redact(entry.path().filename().string()), error.what());
        }
    }
    return out;
}

void SubscriptionStore::deleteAccount(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ignored;
    fs::remove(accountPath(user), ignored);
}

}  // namespace bazarish::service
