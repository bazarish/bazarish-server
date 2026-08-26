// Bazarish project (c) 2026
#include "GrantStore.hpp"

#include <bazarish/Address.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
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
    fs::create_directories(root_ / "bans");
}

fs::path GrantStore::banPath(const std::string& user) const
{
    return root_ / "bans" / (user + ".json");
}

fs::path GrantStore::grantPath(const std::string& user) const
{
    return root_ / "grants" / (user + ".json");
}

void GrantStore::grantSubscription(
    const std::string& user, const std::uint64_t quotaBytes, const std::int64_t now)
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
    result.grantedAt = grant.at("grantedAt").get<std::int64_t>();
    return result;
}

void GrantStore::setI2pTransient(const std::string& user, const std::int64_t transientExpires,
    const std::int64_t updatedAt)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    nlohmann::json body = fs::exists(path) ? readJsonFile(path) : nlohmann::json::object();
    body["transient"] = {{"expires", transientExpires}, {"updatedAt", updatedAt}};
    writeFileAtomic(path, body.dump());
}

std::optional<GrantStore::Transient> GrantStore::peekTransient(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    if (!fs::exists(path)) {
        return std::nullopt;
    }
    const nlohmann::json body = readJsonFile(path);
    if (!body.contains("transient")) {
        return std::nullopt;
    }
    const nlohmann::json& entry = body.at("transient");
    Transient result;
    result.expires = entry.at("expires").get<std::int64_t>();
    result.updatedAt = entry.at("updatedAt").get<std::int64_t>();
    return result;
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

void GrantStore::recordRegistration(
    const std::string& user, const std::int64_t now, const bool approved)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    nlohmann::json body = fs::exists(path) ? readJsonFile(path) : nlohmann::json::object();
    nlohmann::json& entry = body["approval"];
    if (!entry.contains("requestedAt")) {
        entry["requestedAt"] = now;
    }
    if (!entry.contains("approvedAt")) {
        entry["approvedAt"] = 0;
    }
    if (approved && entry.at("approvedAt").get<std::int64_t>() == 0) {
        entry["approvedAt"] = now;
    }
    writeFileAtomic(path, body.dump());
}

std::optional<GrantStore::Approval> GrantStore::peekApproval(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    if (!fs::exists(path)) {
        return std::nullopt;
    }
    const nlohmann::json body = readJsonFile(path);
    if (!body.contains("approval")) {
        return std::nullopt;
    }
    const nlohmann::json& entry = body.at("approval");
    Approval result;
    result.requestedAt = entry.at("requestedAt").get<std::int64_t>();
    result.approvedAt = entry.at("approvedAt").get<std::int64_t>();
    result.message = entry.value("message", std::string());
    return result;
}

void GrantStore::approve(const std::string& user, const std::int64_t now)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    if (!fs::exists(path)) {
        return;
    }
    nlohmann::json body = readJsonFile(path);
    if (!body.contains("approval")) {
        return;
    }
    nlohmann::json& entry = body.at("approval");
    if (entry.at("approvedAt").get<std::int64_t>() != 0) {
        return;
    }
    entry["approvedAt"] = now;
    entry["message"] = "";
    writeFileAtomic(path, body.dump());
}

void GrantStore::hold(const std::string& user, const std::string& message, const std::int64_t now)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = grantPath(user);
    nlohmann::json body = fs::exists(path) ? readJsonFile(path) : nlohmann::json::object();
    nlohmann::json& entry = body["approval"];
    // An account put on hold before it was ever recorded still has to have a
    // request date, or it would look like it had waited forever.
    if (!entry.contains("requestedAt")) {
        entry["requestedAt"] = now;
    }
    entry["approvedAt"] = 0;
    entry["message"] = message;
    writeFileAtomic(path, body.dump());
}

void GrantStore::ban(const std::string& user, const std::string& reason, const std::int64_t now)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    writeFileAtomic(banPath(user),
        nlohmann::json{{"reason", reason}, {"bannedAt", now}}.dump());
}

std::optional<GrantStore::Ban> GrantStore::peekBan(const std::string& user) const
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = banPath(user);
    if (!fs::exists(path)) {
        return std::nullopt;
    }
    const nlohmann::json body = readJsonFile(path);
    Ban result;
    result.reason = body.value("reason", std::string());
    result.bannedAt = body.value("bannedAt", std::int64_t{0});
    return result;
}

void GrantStore::unban(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ignored;
    fs::remove(banPath(user), ignored);
}


std::vector<std::string> GrantStore::allUsers() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> users;
    // Banned keys have no account left, and are exactly the ones an operator
    // may need to find again to lift the ban.
    for (const char* const directory : {"grants", "bans"}) {
        for (const fs::directory_entry& entry : fs::directory_iterator(root_ / directory)) {
            if (entry.path().extension() == ".json") {
                users.push_back(entry.path().stem().string());
            }
        }
    }
    std::sort(users.begin(), users.end());
    users.erase(std::unique(users.begin(), users.end()), users.end());
    return users;
}

void GrantStore::erase(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ignored;
    fs::remove(grantPath(user), ignored);
}

}  // namespace bazarish::service
