// Bazarish project (c) 2026
#include "SubscriptionStore.hpp"

#include <bazarish/Log.hpp>

#include <bazarish/Address.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/PrivateFile.hpp>

#include <nlohmann/json.hpp>

#include <system_error>

namespace bazarish::service {

namespace fs = std::filesystem;

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
    requireFingerprint(account.user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const nlohmann::json body = {
        {"user", account.user},
        {"registeredAt", account.registeredAt},
        {"quotaBytes", account.quotaBytes},
        {"dest", account.dest},
        {"delegatedAt", account.delegatedAt},
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
    account.dest = body.at("dest").get<std::string>();
    account.delegatedAt = body.at("delegatedAt").get<std::int64_t>();
    account.card = fromBase64(body.at("card").get<std::string>());
    return account;
}

}  // namespace

std::optional<SubscriptionStore::Account> SubscriptionStore::getAccount(const std::string& user)
{
    requireFingerprint(user);
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
        return out;
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
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ignored;
    fs::remove(accountPath(user), ignored);
}

}  // namespace bazarish::service
