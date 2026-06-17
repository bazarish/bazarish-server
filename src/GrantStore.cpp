// Bazarish project (c) 2026
#include "GrantStore.hpp"

#include <bazarish/Address.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>
#include <system_error>
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

GrantStore::GrantStore(fs::path root)
    : root_(std::move(root))
{
    fs::create_directories(root_ / "grants");
}

fs::path GrantStore::grantPath(const std::string& user) const
{
    return root_ / "grants" / (user + ".json");
}

void GrantStore::grantSubscription(const std::string& user, const std::uint64_t quotaBytes,
    const std::int64_t termSeconds, const std::int64_t now)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json body = nlohmann::json::object();
    const fs::path path = grantPath(user);
    if (fs::exists(path)) {
        body = readJsonFile(path);
    }
    body["subscription"] = {
        {"quotaBytes", quotaBytes},
        {"termSeconds", termSeconds},
        {"grantedAt", now},
    };
    writeFileAtomic(path, body.dump());
}

std::optional<GrantStore::SubscriptionGrant> GrantStore::peekSubscription(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    if (!fs::exists(path)) {
        return std::nullopt;
    }
    const nlohmann::json body = readJsonFile(path);
    if (!body.contains("subscription")) {
        return std::nullopt;
    }
    const nlohmann::json& grant = body.at("subscription");
    SubscriptionGrant result;
    result.quotaBytes = grant.at("quotaBytes").get<std::uint64_t>();
    result.termSeconds = grant.at("termSeconds").get<std::int64_t>();
    result.grantedAt = grant.at("grantedAt").get<std::int64_t>();
    return result;
}

void GrantStore::grantService(const std::string& user, const std::string& service,
    const std::int64_t paidThrough, const std::int64_t now)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    nlohmann::json body = fs::exists(path) ? readJsonFile(path) : nlohmann::json::object();
    // Preserve the per-service fields a purchase/renewal does not set: the
    // enabled flag (a fresh buy re-arms it) and the recorded transient validity.
    nlohmann::json& entry = body["services"][service];
    entry["paidThrough"] = paidThrough;
    entry["grantedAt"] = now;
    entry["enabled"] = true;
    writeFileAtomic(path, body.dump());
}

std::optional<GrantStore::ServiceGrant> GrantStore::peekService(
    const std::string& user, const std::string& service)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    if (!fs::exists(path)) {
        return std::nullopt;
    }
    const nlohmann::json body = readJsonFile(path);
    if (!body.contains("services") || !body.at("services").contains(service)) {
        return std::nullopt;
    }
    const nlohmann::json& grant = body.at("services").at(service);
    ServiceGrant result;
    result.paidThrough = grant.at("paidThrough").get<std::int64_t>();
    result.grantedAt = grant.at("grantedAt").get<std::int64_t>();
    result.enabled = grant.value("enabled", true);
    result.transientExpires = grant.value("transientExpires", std::int64_t{0});
    result.transientUpdatedAt = grant.value("transientUpdatedAt", std::int64_t{0});
    return result;
}

void GrantStore::setServiceEnabled(
    const std::string& user, const std::string& service, const bool enabled)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    if (!fs::exists(path)) {
        return;
    }
    nlohmann::json body = readJsonFile(path);
    if (!body.contains("services") || !body.at("services").contains(service)) {
        return;
    }
    body.at("services").at(service)["enabled"] = enabled;
    writeFileAtomic(path, body.dump());
}

void GrantStore::setI2pTransient(
    const std::string& user, const std::int64_t transientExpires, const std::int64_t updatedAt)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    if (!fs::exists(path)) {
        return;
    }
    nlohmann::json body = readJsonFile(path);
    if (!body.contains("services") || !body.at("services").contains("i2pDest")) {
        return;
    }
    nlohmann::json& entry = body.at("services").at("i2pDest");
    entry["transientExpires"] = transientExpires;
    entry["transientUpdatedAt"] = updatedAt;
    writeFileAtomic(path, body.dump());
}

std::optional<GrantStore::SubscriptionGrant> GrantStore::takeSubscription(const std::string& user)
{
    const std::optional<SubscriptionGrant> grant = peekSubscription(user);
    if (!grant.has_value()) {
        return std::nullopt;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    nlohmann::json body = fs::exists(path) ? readJsonFile(path) : nlohmann::json::object();
    body.erase("subscription");
    if (body.empty()) {
        std::error_code ignored;
        fs::remove(path, ignored);
    } else {
        writeFileAtomic(path, body.dump());
    }
    return grant;
}

}  // namespace bazarish::service
