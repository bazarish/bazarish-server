// Bazarish project (c) 2026
#pragma once

#include "Storage.hpp"

#include <filesystem>
#include <map>
#include <mutex>

namespace bazarish::server {

// Filesystem storage backend - the simple-deploy default.
//
// Layout under the root directory:
//   users/<fingerprint>/clients/<clientId>   registered client marker
//   users/<fingerprint>/tokens/<hash-hex>    registered token hash marker
//   users/<fingerprint>/blobs/<blobId>       pending content
//   users/<fingerprint>/meta/<blobId>.json   {"receivedAt": ..., "class": ..., "acked": [...]}
//   users/<fingerprint>/seen/<messageId>     admitted-messageId marker (receivedAt text)
//   outbound/<id>.json                       a send accepted and not delivered yet
//   users/<fingerprint>/undelivered/<msgId>  a send given up on, until the sender asks
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
        const std::string& deliveryClass, std::int64_t receivedAt, std::uint64_t quotaBytes,
        const std::string& alreadyAcked = {}) override;
    bool hasBlob(const std::string& user, const std::string& blobId) override;
    bool hasSeen(const std::string& user, const std::string& messageId) override;
    void markSeen(const std::string& user, const std::string& messageId,
        std::int64_t receivedAt) override;
    void purgeTokensRegisteredBefore(std::int64_t registeredBefore) override;
    bool allowContactRequest(
        const std::string& user, std::int64_t now, std::size_t maxPerMinute) override;
    std::vector<PendingEntry> listPending(const std::string& user,
        const std::string& clientId) override;
    Bytes getBlob(const std::string& user, const std::string& blobId) override;
    void ackBlob(const std::string& user, const std::string& blobId,
        const std::string& clientId) override;
    void purgeUser(const std::string& user) override;
    void purgeExpired(std::int64_t receivedBefore) override;
    std::uint64_t usage(const std::string& user) override;
    void setUserQuota(const std::string& user, std::uint64_t quotaBytes) override;
    std::uint64_t userQuota(const std::string& user, std::uint64_t fallback) override;

    std::string queueOutbound(const OutboundEntry& entry) override;
    std::vector<OutboundEntry> listOutbound() override;
    void updateOutbound(const std::string& id, int attempts, std::int64_t nextAttemptAt) override;
    void removeOutbound(const std::string& id) override;
    void noteUndelivered(const std::string& user, const std::string& messageId) override;
    std::vector<std::string> listUndelivered(const std::string& user) override;
    void clearUndelivered(const std::string& user, const std::string& messageId) override;

private:
    // One minute window per mailbox for the tokenless path. In memory: a restart
    // forgives whatever was counted, which is the right way round - a restart
    // must not lock a mailbox out of receiving contact requests.
    struct Window {
        std::int64_t start = 0;
        std::size_t count = 0;
    };
    std::map<std::string, Window> contactWindows_;

    std::filesystem::path userDir(const std::string& user) const;
    std::uint64_t usageLocked(const std::string& user) const;
    void deleteIfFullyAcked(const std::string& user, const std::string& blobId);

    std::filesystem::path root_;
    std::mutex mutex_;
};

}  // namespace bazarish::server
