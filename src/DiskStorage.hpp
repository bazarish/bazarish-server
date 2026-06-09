// Bazarish project (c) 2026
#pragma once

#include "Storage.hpp"

#include <filesystem>
#include <mutex>

namespace bazarish::server {

// Filesystem storage backend — the simple-deploy default.
//
// Layout under the root directory:
//   users/<fingerprint>/clients/<clientId>   registered client marker
//   users/<fingerprint>/tokens/<hash-hex>    registered token hash marker
//   users/<fingerprint>/blobs/<blobId>       pending content
//   users/<fingerprint>/meta/<blobId>.json   {"receivedAt": ..., "kind": ..., "acked": [...]}
//
// Token consumption maps to unlink(), which the filesystem makes atomic.
// A single coarse mutex serializes mutations; revisit when profiling says so.
class DiskStorage final : public Storage {
public:
    explicit DiskStorage(const std::filesystem::path& root);

    void registerClient(const std::string& user, const std::string& clientId) override;
    void unregisterClient(const std::string& user, const std::string& clientId) override;
    std::vector<std::string> listClients(const std::string& user) override;
    bool isClientRegistered(const std::string& user, const std::string& clientId) override;

    void registerTokenHashes(const std::string& user, const std::vector<Bytes>& hashes) override;
    bool consumeTokenHash(const std::string& user, const Bytes& hash) override;
    void deleteTokenHashes(const std::string& user, const std::vector<Bytes>& hashes) override;
    std::size_t tokenHashCount(const std::string& user) override;

    PutResult putBlob(const std::string& user, const std::string& blobId, const Bytes& data,
        const std::string& kind, std::int64_t receivedAt, std::uint64_t quotaBytes) override;
    bool hasBlob(const std::string& user, const std::string& blobId) override;
    std::vector<PendingEntry> listPending(const std::string& user,
        const std::string& clientId) override;
    Bytes getBlob(const std::string& user, const std::string& blobId) override;
    void ackBlob(const std::string& user, const std::string& blobId,
        const std::string& clientId) override;
    void purgeUser(const std::string& user) override;
    void purgeExpired(std::int64_t receivedBefore) override;
    std::uint64_t usage(const std::string& user) override;

private:
    std::filesystem::path userDir(const std::string& user) const;
    std::uint64_t usageLocked(const std::string& user) const;
    void deleteIfFullyAcked(const std::string& user, const std::string& blobId);

    std::filesystem::path root_;
    std::mutex mutex_;
};

}  // namespace bazarish::server
