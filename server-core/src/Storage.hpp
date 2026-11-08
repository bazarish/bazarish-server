// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::server {

// What a mailbox may hold until its node grants a quota of its own.
inline constexpr std::uint64_t kDefaultQuotaBytes = 50 * 1024 * 1024;

class Storage {
public:
    virtual ~Storage() = default;

    virtual void registerClient(const std::string& user, const std::string& clientId) = 0;
    virtual void unregisterClient(const std::string& user, const std::string& clientId) = 0;
    virtual std::vector<std::string> listClients(const std::string& user) = 0;
    virtual bool isClientRegistered(const std::string& user, const std::string& clientId) = 0;

    // False, and nothing kept, when the new ones would take the mailbox past `cap`.
    virtual bool registerPasses(
        const std::string& user, const std::vector<Bytes>& handles, std::size_t cap)
        = 0;
    virtual bool hasPass(const std::string& user, const Bytes& handle) = 0;
    virtual std::size_t passCount(const std::string& user) = 0;
    virtual std::size_t revokePasses(
        const std::string& user, const std::vector<Bytes>& handles) = 0;

    enum class PutResult {
        eStored,
        eDuplicate,
        eQuotaExceeded,
        eClassFull,
    };

    struct PendingEntry {
        std::string blobId;
        std::string deliveryClass;
        std::uint64_t bytes = 0;

        bool operator==(const PendingEntry&) const = default;
    };

    // Duplicate when held or seen before; `heldLimit` bounds what the class may hold at once.
    virtual PutResult putBlob(const std::string& user, const std::string& blobId,
        const Bytes& data, const std::string& deliveryClass, std::uint64_t quotaBytes,
        std::int64_t receivedAt, const std::string& alreadyAcked = {},
        std::optional<std::size_t> heldLimit = std::nullopt)
        = 0;
    virtual bool hasBlob(const std::string& user, const std::string& blobId) = 0;
    virtual bool isPendingFor(
        const std::string& user, const std::string& blobId, const std::string& clientId) = 0;

    virtual bool hasSeen(const std::string& user, const std::string& deliveryId) = 0;

    virtual bool allowContactRequest(const std::string& user, std::int64_t now) = 0;

    virtual std::size_t countHeld(const std::string& user, const std::string& deliveryClass) = 0;

    virtual std::vector<PendingEntry> listPending(const std::string& user,
        const std::string& clientId)
        = 0;
    virtual Bytes getBlob(const std::string& user, const std::string& blobId) = 0;
    virtual void ackBlob(const std::string& user, const std::string& blobId,
        const std::string& clientId)
        = 0;
    virtual void forgetUser(const std::string& user) = 0;
    virtual void purgeExpired(std::int64_t receivedBefore) = 0;
    virtual std::uint64_t usage(const std::string& user) = 0;

    virtual void setUserQuota(const std::string& user, std::uint64_t quotaBytes) = 0;
    virtual std::uint64_t userQuota(const std::string& user, std::uint64_t fallback) = 0;

};

}  // namespace bazarish::server
