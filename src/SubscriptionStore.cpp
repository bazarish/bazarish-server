// Bazarish project (c) 2026
#include "SubscriptionStore.hpp"

#include <bazarish/Address.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>
#include <system_error>

namespace bazarish::service {

namespace {

namespace fs = std::filesystem;

constexpr std::size_t kAliasMaxLength = 32;

void requireUser(const std::string& user)
{
    if (!isFingerprint(user)) {
        throw std::invalid_argument("user is not a fingerprint");
    }
}

void requireAlias(const std::string& alias)
{
    if (!isAlias(alias) || alias.size() > kAliasMaxLength) {
        throw std::invalid_argument("alias has invalid format");
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
    fs::create_directories(root_ / "aliases");
}

fs::path SubscriptionStore::subscriptionPath(const std::string& user) const
{
    return root_ / "subscriptions" / (user + ".json");
}

fs::path SubscriptionStore::aliasPath(const std::string& alias) const
{
    return root_ / "aliases" / (alias + ".json");
}

void SubscriptionStore::putSubscription(const Subscription& subscription)
{
    requireUser(subscription.user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const nlohmann::json body = {
        {"user", subscription.user},
        {"issuedAt", subscription.issuedAt},
        {"notAfter", subscription.notAfter},
        {"quotaBytes", subscription.quotaBytes},
        {"cert", toBase64(subscription.certificate)},
    };
    writeFileAtomic(subscriptionPath(subscription.user), body.dump());
}

std::optional<SubscriptionStore::Subscription> SubscriptionStore::getSubscription(
    const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = subscriptionPath(user);
    if (!fs::exists(path)) {
        return std::nullopt;
    }
    const nlohmann::json body = readJsonFile(path);
    Subscription subscription;
    subscription.user = body.at("user").get<std::string>();
    subscription.issuedAt = body.at("issuedAt").get<std::int64_t>();
    subscription.notAfter = body.at("notAfter").get<std::int64_t>();
    subscription.quotaBytes = body.at("quotaBytes").get<std::uint64_t>();
    subscription.certificate = fromBase64(body.at("cert").get<std::string>());
    return subscription;
}

void SubscriptionStore::deleteSubscription(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ignored;
    fs::remove(subscriptionPath(user), ignored);
}

bool SubscriptionStore::putAlias(const Alias& alias)
{
    requireAlias(alias.alias);
    requireUser(alias.user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = aliasPath(alias.alias);
    if (fs::exists(path)) {
        const nlohmann::json existing = readJsonFile(path);
        if (existing.at("user").get<std::string>() != alias.user) {
            return false;
        }
    }
    const nlohmann::json body = {
        {"alias", alias.alias},
        {"user", alias.user},
        {"cert", toBase64(alias.certificate)},
    };
    writeFileAtomic(path, body.dump());
    return true;
}

std::optional<SubscriptionStore::Alias> SubscriptionStore::getAlias(const std::string& alias)
{
    requireAlias(alias);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = aliasPath(alias);
    if (!fs::exists(path)) {
        return std::nullopt;
    }
    const nlohmann::json body = readJsonFile(path);
    Alias record;
    record.alias = body.at("alias").get<std::string>();
    record.user = body.at("user").get<std::string>();
    record.certificate = fromBase64(body.at("cert").get<std::string>());
    return record;
}

bool SubscriptionStore::deleteAlias(const std::string& alias, const std::string& user)
{
    requireAlias(alias);
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = aliasPath(alias);
    if (!fs::exists(path)) {
        return false;
    }
    const nlohmann::json body = readJsonFile(path);
    if (body.at("user").get<std::string>() != user) {
        return false;
    }
    std::error_code ignored;
    return fs::remove(path, ignored);
}

}  // namespace bazarish::service
