// Bazarish project (c) 2026
#include "DiskStorage.hpp"

#include <bazarish/Address.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Pass.hpp>
#include <bazarish/PrivateFile.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <system_error>

namespace {

namespace fs = std::filesystem;

constexpr std::size_t kIdMaxLength = 64;

constexpr std::int64_t kContactWindowSeconds = 60;

bool isSafeId(const std::string& id)
{
    if (id.empty() || id.size() > kIdMaxLength) {
        return false;
    }
    for (const char c : id) {
        const bool ok
            = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

void requireSafeId(const std::string& id)
{
    if (!isSafeId(id)) {
        throw std::invalid_argument("identifier has invalid format");
    }
}

std::int64_t arrivalMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t arrivalOf(const nlohmann::json& meta)
{
    return meta.at("receivedAtMs").get<std::int64_t>();
}

std::vector<std::string> listDirectoryNames(const fs::path& dir)
{
    std::vector<std::string> names;
    if (!fs::exists(dir)) {
        return names;
    }
    for (const fs::directory_entry& entry : fs::directory_iterator(dir)) {
        names.push_back(entry.path().filename().string());
    }
    return names;
}

bool ackedBy(const nlohmann::json& meta, const std::string& clientId)
{
    for (const nlohmann::json& entry : meta.at("acked")) {
        if (entry.get<std::string>() == clientId) {
            return true;
        }
    }
    return false;
}

bool ackedByAll(const nlohmann::json& meta, const std::vector<std::string>& clients)
{
    if (clients.empty()) {
        return false;
    }
    for (const std::string& clientId : clients) {
        if (!ackedBy(meta, clientId)) {
            return false;
        }
    }
    return true;
}

void createDirectoryDurably(const fs::path& directory)
{
    if (fs::exists(directory)) {
        return;
    }
    createDirectoryDurably(directory.parent_path());
    fs::create_directory(directory);
    bazarish::syncDirectory(directory.parent_path());
}

void writeMarker(const fs::path& path)
{
    std::ofstream marker(path, std::ios::binary | std::ios::trunc);
    if (!marker) {
        throw std::runtime_error("failed to create " + path.string());
    }
}

}  // namespace

namespace bazarish::server {

DiskStorage::DiskStorage(const fs::path& root)
    : root_(root)
{
    fs::create_directories(root_ / "users");
}

fs::path DiskStorage::userDir(const std::string& user) const
{
    return root_ / "users" / user;
}

void DiskStorage::registerClient(const std::string& user, const std::string& clientId)
{
    requireFingerprint(user);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path dir = userDir(user) / "clients";
    createDirectoryDurably(dir);
    writeFileAtomic(dir / clientId, std::string_view());
}

void DiskStorage::unregisterClient(const std::string& user, const std::string& clientId)
{
    requireFingerprint(user);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path clients = userDir(user) / "clients";
    std::vector<std::string> staying = listDirectoryNames(clients);
    staying.erase(std::remove(staying.begin(), staying.end(), clientId), staying.end());
    for (const std::string& blobId : listDirectoryNames(userDir(user) / "blobs")) {
        const fs::path metaPath = userDir(user) / "meta" / (blobId + ".json");
        if (fs::exists(metaPath) && ackedByAll(readJsonFile(metaPath), staying)) {
            removeItem(user, blobId);
        }
    }
    if (fs::remove(clients / clientId)) {
        syncDirectory(clients);
    }
}

std::vector<std::string> DiskStorage::listClients(const std::string& user)
{
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    return listDirectoryNames(userDir(user) / "clients");
}

bool DiskStorage::isClientRegistered(const std::string& user, const std::string& clientId)
{
    requireFingerprint(user);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);
    return fs::exists(userDir(user) / "clients" / clientId);
}

void DiskStorage::registerPasses(const std::string& user, const std::vector<Bytes>& handles)
{
    requireFingerprint(user);
    for (const Bytes& handle : handles) {
        if (handle.size() != bazarish::kDeliveryPassSize) {
            throw std::invalid_argument("delivery pass handle has wrong size");
        }
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path dir = userDir(user) / "passes";
    createDirectoryDurably(dir);
    for (const Bytes& handle : handles) {
        writeMarker(dir / toHex(handle));
    }
    syncDirectory(dir);
}

bool DiskStorage::hasPass(const std::string& user, const Bytes& handle)
{
    requireFingerprint(user);
    if (handle.size() != bazarish::kDeliveryPassSize) {
        return false;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code error;
    return fs::exists(userDir(user) / "passes" / toHex(handle), error) && !error;
}

std::size_t DiskStorage::passCount(const std::string& user)
{
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    return listDirectoryNames(userDir(user) / "passes").size();
}

std::size_t DiskStorage::revokePasses(const std::string& user, const std::vector<Bytes>& handles)
{
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path dir = userDir(user) / "passes";
    std::size_t dropped = 0;
    for (const Bytes& handle : handles) {
        if (handle.size() != bazarish::kDeliveryPassSize) {
            continue;
        }
        if (fs::remove(dir / toHex(handle))) {
            ++dropped;
        }
    }
    if (dropped > 0) {
        syncDirectory(dir);
    }
    return dropped;
}

Storage::PutResult DiskStorage::putBlob(const std::string& user, const std::string& blobId,
    const Bytes& data, const std::string& deliveryClass, const std::uint64_t quotaBytes,
    const std::int64_t receivedAt, const std::string& alreadyAcked)
{
    requireFingerprint(user);
    requireSafeId(blobId);
    const std::lock_guard<std::mutex> lock(mutex_);

    const fs::path blobs = userDir(user) / "blobs";
    const fs::path meta = userDir(user) / "meta";
    if (fs::exists(blobs / blobId)) {
        return PutResult::eDuplicate;
    }
    if (usageLocked(user) + data.size() > quotaBytes) {
        return PutResult::eQuotaExceeded;
    }

    const fs::path seen = userDir(user) / "seen";
    createDirectoryDurably(blobs);
    createDirectoryDurably(meta);
    createDirectoryDurably(seen);

    nlohmann::json acked = nlohmann::json::array();
    if (!alreadyAcked.empty()) {
        acked.push_back(alreadyAcked);
    }
    const nlohmann::json metaBody = {
        {"receivedAtMs", arrivalMillis()},
        {"class", deliveryClass},
        {"acked", acked},
    };
    writeFileAtomic(meta / (blobId + ".json"), metaBody.dump());
    writeFileAtomic(blobs / blobId, data);
    writeFileAtomic(seen / blobId, std::to_string(receivedAt));
    return PutResult::eStored;
}

bool DiskStorage::hasBlob(const std::string& user, const std::string& blobId)
{
    requireFingerprint(user);
    requireSafeId(blobId);
    const std::lock_guard<std::mutex> lock(mutex_);
    return fs::exists(userDir(user) / "blobs" / blobId);
}

bool DiskStorage::isPendingFor(
    const std::string& user, const std::string& blobId, const std::string& clientId)
{
    requireFingerprint(user);
    requireSafeId(blobId);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path metaPath = userDir(user) / "meta" / (blobId + ".json");
    if (!fs::exists(userDir(user) / "blobs" / blobId) || !fs::exists(metaPath)) {
        return false;
    }
    return !ackedBy(readJsonFile(metaPath), clientId);
}

bool DiskStorage::hasSeen(const std::string& user, const std::string& deliveryId)
{
    requireFingerprint(user);
    requireSafeId(deliveryId);
    const std::lock_guard<std::mutex> lock(mutex_);
    return fs::exists(userDir(user) / "seen" / deliveryId);
}

bool DiskStorage::allowContactRequest(const std::string& user, const std::int64_t now)
{
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    Window& window = contactWindows_[user];
    if (now - window.start >= kContactWindowSeconds) {
        window.start = now;
        window.count = 0;
    }
    if (window.count >= kContactRequestsPerMinute) {
        return false;
    }
    ++window.count;
    return true;
}

std::size_t DiskStorage::countHeld(const std::string& user, const std::string& deliveryClass)
{
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::size_t held = 0;
    for (const std::string& blobId : listDirectoryNames(userDir(user) / "blobs")) {
        const fs::path metaPath = userDir(user) / "meta" / (blobId + ".json");
        std::error_code ec;
        if (!fs::exists(metaPath, ec) || ec) {
            continue;
        }
        if (readJsonFile(metaPath).at("class").get<std::string>() == deliveryClass) {
            ++held;
        }
    }
    return held;
}

std::vector<Storage::PendingEntry> DiskStorage::listPending(const std::string& user,
    const std::string& clientId)
{
    requireFingerprint(user);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);
    struct Waiting {
        std::int64_t arrivedAtMs = 0;
        PendingEntry entry;
    };
    std::vector<Waiting> waiting;
    for (const std::string& blobId : listDirectoryNames(userDir(user) / "blobs")) {
        const fs::path metaPath = userDir(user) / "meta" / (blobId + ".json");
        std::error_code ec;
        if (!fs::exists(metaPath, ec) || ec) {
            bazarish::log::warn("ignoring an item with no record in the mailbox of {}: {}",
                bazarish::log::redact(user), blobId);
            continue;
        }
        const nlohmann::json meta = readJsonFile(metaPath);
        if (!ackedBy(meta, clientId)) {
            waiting.push_back({arrivalOf(meta),
                PendingEntry{blobId, meta.at("class").get<std::string>(),
                    fs::file_size(userDir(user) / "blobs" / blobId)}});
        }
    }
    std::sort(waiting.begin(), waiting.end(), [](const Waiting& a, const Waiting& b) {
        if (a.arrivedAtMs != b.arrivedAtMs) {
            return a.arrivedAtMs < b.arrivedAtMs;
        }
        return a.entry.blobId < b.entry.blobId;
    });
    std::vector<PendingEntry> pending;
    pending.reserve(waiting.size());
    for (Waiting& item : waiting) {
        pending.push_back(std::move(item.entry));
    }
    return pending;
}

Bytes DiskStorage::getBlob(const std::string& user, const std::string& blobId)
{
    requireFingerprint(user);
    requireSafeId(blobId);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream in(userDir(user) / "blobs" / blobId, std::ios::binary);
    if (!in) {
        throw std::runtime_error("no such blob");
    }
    return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void DiskStorage::ackBlob(const std::string& user, const std::string& blobId,
    const std::string& clientId)
{
    requireFingerprint(user);
    requireSafeId(blobId);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);

    const fs::path metaPath = userDir(user) / "meta" / (blobId + ".json");
    if (!fs::exists(metaPath)) {
        return;
    }
    nlohmann::json meta = readJsonFile(metaPath);
    const bool fresh = !ackedBy(meta, clientId);
    if (fresh) {
        meta.at("acked").push_back(clientId);
    }
    if (ackedByAll(meta, listDirectoryNames(userDir(user) / "clients"))) {
        removeItem(user, blobId);
    } else if (fresh) {
        writeFileAtomic(metaPath, meta.dump());
    }
}

void DiskStorage::forgetUser(const std::string& user)
{
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    if (fs::remove_all(userDir(user)) > 0) {
        syncDirectory(root_ / "users");
    }
}

void DiskStorage::purgeExpired(const std::int64_t receivedBefore)
{
    std::vector<fs::path> users;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!fs::exists(root_ / "users")) {
            return;
        }
        for (const fs::directory_entry& userEntry : fs::directory_iterator(root_ / "users")) {
            users.push_back(userEntry.path());
        }
    }
    for (const fs::path& userPath : users) {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const std::string& deliveryId : listDirectoryNames(userPath / "seen")) {
            const fs::path marker = userPath / "seen" / deliveryId;
            std::ifstream in(marker, std::ios::binary);
            std::int64_t receivedAt = 0;
            if (!(in >> receivedAt) || receivedAt < receivedBefore) {
                std::error_code ignored;
                fs::remove(marker, ignored);
            }
        }
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (auto entry = contactWindows_.begin(); entry != contactWindows_.end();) {
            entry = entry->second.start < receivedBefore ? contactWindows_.erase(entry)
                                                         : std::next(entry);
        }
    }
}

std::uint64_t DiskStorage::usage(const std::string& user)
{
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    return usageLocked(user);
}

void DiskStorage::setUserQuota(const std::string& user, const std::uint64_t quotaBytes)
{
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    createDirectoryDurably(userDir(user));
    writeFileAtomic(userDir(user) / "quota", std::to_string(quotaBytes));
}

std::uint64_t DiskStorage::userQuota(const std::string& user, const std::uint64_t fallback)
{
    requireFingerprint(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path path = userDir(user) / "quota";
    if (!fs::exists(path)) {
        return fallback;
    }
    std::ifstream in(path, std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return static_cast<std::uint64_t>(std::stoull(text));
}

std::uint64_t DiskStorage::usageLocked(const std::string& user) const
{
    std::uint64_t total = 0;
    const fs::path blobs = userDir(user) / "blobs";
    if (!fs::exists(blobs)) {
        return total;
    }
    for (const fs::directory_entry& entry : fs::directory_iterator(blobs)) {
        if (isSafeId(entry.path().filename().string())) {
            total += entry.file_size();
        }
    }
    return total;
}

// Blob first: a blob left without its record would still count against the quota.
void DiskStorage::removeItem(const std::string& user, const std::string& blobId)
{
    if (fs::remove(userDir(user) / "blobs" / blobId)) {
        syncDirectory(userDir(user) / "blobs");
    }
    if (fs::remove(userDir(user) / "meta" / (blobId + ".json"))) {
        syncDirectory(userDir(user) / "meta");
    }
}

}  // namespace bazarish::server
