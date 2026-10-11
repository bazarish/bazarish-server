// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace bazarish::server {

class Storage {
public:
    virtual ~Storage() = default;

    virtual void registerClient(const std::string& user, const std::string& clientId) = 0;
    virtual void unregisterClient(const std::string& user, const std::string& clientId) = 0;
    virtual std::vector<std::string> listClients(const std::string& user) = 0;
    virtual bool isClientRegistered(const std::string& user, const std::string& clientId) = 0;

    virtual void registerPasses(const std::string& user, const std::vector<Bytes>& handles) = 0;
    virtual bool hasPass(const std::string& user, const Bytes& handle) = 0;
    virtual std::size_t passCount(const std::string& user) = 0;
    virtual std::size_t revokePasses(
        const std::string& user, const std::vector<Bytes>& handles) = 0;

    enum class PutResult {
        eStored,
        eDuplicate,
        eQuotaExceeded,
    };

    struct PendingEntry {
        std::string blobId;
        std::string deliveryClass;

        bool operator==(const PendingEntry&) const = default;
    };

    virtual PutResult putBlob(const std::string& user, const std::string& blobId,
        const Bytes& data, const std::string& deliveryClass, std::uint64_t quotaBytes, const std::string& alreadyAcked = {})
        = 0;
    virtual bool hasBlob(const std::string& user, const std::string& blobId) = 0;

    virtual bool hasSeen(const std::string& user, const std::string& deliveryId) = 0;
    virtual void markSeen(const std::string& user, const std::string& deliveryId,
        std::int64_t receivedAt)
        = 0;

    virtual bool allowContactRequest(
        const std::string& user, std::int64_t now, std::size_t maxPerMinute)
        = 0;

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
