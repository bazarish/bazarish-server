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

fs::path SubscriptionStore::subscriptionPath(const std::string& user) const
{
    return root_ / "subscriptions" / (user + ".json");
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
        {"dest", subscription.dest},
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
    subscription.dest = body.value("dest", std::string());
    subscription.certificate = fromBase64(body.at("cert").get<std::string>());
    return subscription;
}

std::vector<SubscriptionStore::Subscription> SubscriptionStore::allSubscriptions() const
{
    std::vector<Subscription> out;
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
            std::ifstream in(entry.path(), std::ios::binary);
            const std::string text(
                (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            const nlohmann::json record = nlohmann::json::parse(text);
            Subscription subscription;
            subscription.user = record.at("user").get<std::string>();
            subscription.issuedAt = record.at("issuedAt").get<std::int64_t>();
            subscription.notAfter = record.at("notAfter").get<std::int64_t>();
            subscription.quotaBytes = record.at("quotaBytes").get<std::uint64_t>();
            out.push_back(std::move(subscription));
        } catch (const std::exception& error) {
            bazarish::log::warn("subscription record {} unreadable: {}",
                entry.path().filename().string(), error.what());
        }
    }
    return out;
}

void SubscriptionStore::deleteSubscription(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ignored;
    fs::remove(subscriptionPath(user), ignored);
}

}  // namespace bazarish::service
