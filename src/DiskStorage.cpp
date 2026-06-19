// Bazarish project (c) 2026
#include "DiskStorage.hpp"

#include <bazarish/Address.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>
#include <system_error>

namespace {

namespace fs = std::filesystem;

constexpr std::size_t kIdMaxLength = 64;

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

void requireUser(const std::string& user)
{
    if (!bazarish::isFingerprint(user)) {
        throw std::invalid_argument("user is not a fingerprint");
    }
}

void requireSafeId(const std::string& id)
{
    if (!isSafeId(id)) {
        throw std::invalid_argument("identifier has invalid format");
    }
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

void writeFileAtomic(const fs::path& target, const void* data, const std::size_t size)
{
    const fs::path temporary = target.parent_path() / (target.filename().string() + ".tmp");
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("failed to open " + temporary.string());
        }
        out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
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
    requireUser(user);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path dir = userDir(user) / "clients";
    fs::create_directories(dir);
    writeFileAtomic(dir / clientId, "", 0);
}

void DiskStorage::unregisterClient(const std::string& user, const std::string& clientId)
{
    requireUser(user);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ignored;
    fs::remove(userDir(user) / "clients" / clientId, ignored);
    // Blobs that were waiting only on the retired client are now complete.
    for (const std::string& blobId : listDirectoryNames(userDir(user) / "blobs")) {
        deleteIfFullyAcked(user, blobId);
    }
}

std::vector<std::string> DiskStorage::listClients(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    return listDirectoryNames(userDir(user) / "clients");
}

bool DiskStorage::isClientRegistered(const std::string& user, const std::string& clientId)
{
    requireUser(user);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);
    return fs::exists(userDir(user) / "clients" / clientId);
}

void DiskStorage::registerTokenHashes(const std::string& user, const std::vector<Bytes>& hashes)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path dir = userDir(user) / "tokens";
    fs::create_directories(dir);
    for (const Bytes& hash : hashes) {
        writeFileAtomic(dir / toHex(hash), "", 0);
    }
}

bool DiskStorage::consumeTokenHash(const std::string& user, const Bytes& hash)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code error;
    // remove() returns true only when the entry existed: exactly the
    // consume-once semantics one-time tokens need.
    return fs::remove(userDir(user) / "tokens" / toHex(hash), error) && !error;
}

void DiskStorage::deleteTokenHashes(const std::string& user, const std::vector<Bytes>& hashes)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    for (const Bytes& hash : hashes) {
        std::error_code ignored;
        fs::remove(userDir(user) / "tokens" / toHex(hash), ignored);
    }
}

std::size_t DiskStorage::tokenHashCount(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    return listDirectoryNames(userDir(user) / "tokens").size();
}

Storage::PutResult DiskStorage::putBlob(const std::string& user, const std::string& blobId,
    const Bytes& data, const std::string& deliveryClass, const std::int64_t receivedAt,
    const std::uint64_t quotaBytes)
{
    requireUser(user);
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

    fs::create_directories(blobs);
    fs::create_directories(meta);

    const nlohmann::json metaBody = {
        {"receivedAt", receivedAt},
        {"class", deliveryClass},
        {"acked", nlohmann::json::array()},
    };
    const std::string metaText = metaBody.dump();
    // Write the meta record first: a blob without meta would be invisible
    // to the TTL sweep, the reverse is harmless.
    writeFileAtomic(meta / (blobId + ".json"), metaText.data(), metaText.size());
    writeFileAtomic(blobs / blobId, data.data(), data.size());
    return PutResult::eStored;
}

bool DiskStorage::hasBlob(const std::string& user, const std::string& blobId)
{
    requireUser(user);
    requireSafeId(blobId);
    const std::lock_guard<std::mutex> lock(mutex_);
    return fs::exists(userDir(user) / "blobs" / blobId);
}

bool DiskStorage::hasSeen(const std::string& user, const std::string& messageId)
{
    requireUser(user);
    requireSafeId(messageId);
    const std::lock_guard<std::mutex> lock(mutex_);
    return fs::exists(userDir(user) / "seen" / messageId);
}

void DiskStorage::markSeen(const std::string& user, const std::string& messageId,
    const std::int64_t receivedAt)
{
    requireUser(user);
    requireSafeId(messageId);
    const std::lock_guard<std::mutex> lock(mutex_);
    const fs::path dir = userDir(user) / "seen";
    fs::create_directories(dir);
    // The marker payload is the receive time, so the TTL sweep can age it out.
    const std::string text = std::to_string(receivedAt);
    writeFileAtomic(dir / messageId, text.data(), text.size());
}

std::vector<Storage::PendingEntry> DiskStorage::listPending(const std::string& user,
    const std::string& clientId)
{
    requireUser(user);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PendingEntry> pending;
    for (const std::string& blobId : listDirectoryNames(userDir(user) / "blobs")) {
        const nlohmann::json meta = readJsonFile(userDir(user) / "meta" / (blobId + ".json"));
        bool acked = false;
        for (const nlohmann::json& entry : meta.at("acked")) {
            if (entry.get<std::string>() == clientId) {
                acked = true;
                break;
            }
        }
        if (!acked) {
            pending.push_back(PendingEntry{blobId, meta.at("class").get<std::string>()});
        }
    }
    return pending;
}

Bytes DiskStorage::getBlob(const std::string& user, const std::string& blobId)
{
    requireUser(user);
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
    requireUser(user);
    requireSafeId(blobId);
    requireSafeId(clientId);
    const std::lock_guard<std::mutex> lock(mutex_);

    const fs::path metaPath = userDir(user) / "meta" / (blobId + ".json");
    if (!fs::exists(metaPath)) {
        // Acking something already deleted is a no-op, not an error: the
        // blob may have been completed by another client's ack already.
        return;
    }
    nlohmann::json meta = readJsonFile(metaPath);
    nlohmann::json& acked = meta.at("acked");
    bool present = false;
    for (const nlohmann::json& entry : acked) {
        if (entry.get<std::string>() == clientId) {
            present = true;
            break;
        }
    }
    if (!present) {
        acked.push_back(clientId);
        const std::string metaText = meta.dump();
        writeFileAtomic(metaPath, metaText.data(), metaText.size());
    }
    deleteIfFullyAcked(user, blobId);
}

void DiskStorage::purgeUser(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ignored;
    fs::remove_all(userDir(user) / "blobs", ignored);
    fs::remove_all(userDir(user) / "meta", ignored);
    fs::remove_all(userDir(user) / "seen", ignored);
}

void DiskStorage::purgeExpired(const std::int64_t receivedBefore)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (!fs::exists(root_ / "users")) {
        return;
    }
    for (const fs::directory_entry& userEntry : fs::directory_iterator(root_ / "users")) {
        const std::string user = userEntry.path().filename().string();
        for (const std::string& blobId : listDirectoryNames(userEntry.path() / "blobs")) {
            const nlohmann::json meta
                = readJsonFile(userEntry.path() / "meta" / (blobId + ".json"));
            if (meta.at("receivedAt").get<std::int64_t>() < receivedBefore) {
                std::error_code ignored;
                fs::remove(userEntry.path() / "blobs" / blobId, ignored);
                fs::remove(userEntry.path() / "meta" / (blobId + ".json"), ignored);
            }
        }
        // Age out replay markers on the same horizon as the blobs they guard.
        for (const std::string& messageId : listDirectoryNames(userEntry.path() / "seen")) {
            const fs::path marker = userEntry.path() / "seen" / messageId;
            std::ifstream in(marker, std::ios::binary);
            std::int64_t receivedAt = 0;
            if (in >> receivedAt && receivedAt < receivedBefore) {
                std::error_code ignored;
                fs::remove(marker, ignored);
            }
        }
        (void)user;
    }
}

std::uint64_t DiskStorage::usage(const std::string& user)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    return usageLocked(user);
}

void DiskStorage::setUserQuota(const std::string& user, const std::uint64_t quotaBytes)
{
    requireUser(user);
    const std::lock_guard<std::mutex> lock(mutex_);
    fs::create_directories(userDir(user));
    const std::string text = std::to_string(quotaBytes);
    writeFileAtomic(userDir(user) / "quota", text.data(), text.size());
}

std::uint64_t DiskStorage::userQuota(const std::string& user, const std::uint64_t fallback)
{
    requireUser(user);
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
        total += entry.file_size();
    }
    return total;
}

void DiskStorage::deleteIfFullyAcked(const std::string& user, const std::string& blobId)
{
    const fs::path metaPath = userDir(user) / "meta" / (blobId + ".json");
    if (!fs::exists(metaPath)) {
        return;
    }
    const nlohmann::json meta = readJsonFile(metaPath);
    const std::vector<std::string> clients = listDirectoryNames(userDir(user) / "clients");
    for (const std::string& clientId : clients) {
        bool acked = false;
        for (const nlohmann::json& entry : meta.at("acked")) {
            if (entry.get<std::string>() == clientId) {
                acked = true;
                break;
            }
        }
        if (!acked) {
            return;
        }
    }
    // Every registered client has acked (or none are registered while the
    // blob still exists - in that degenerate case the content is kept
    // until the TTL sweep, so a user temporarily without clients does not
    // lose mail).
    if (clients.empty()) {
        return;
    }
    std::error_code ignored;
    fs::remove(userDir(user) / "blobs" / blobId, ignored);
    fs::remove(metaPath, ignored);
}

}  // namespace bazarish::server
