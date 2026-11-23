// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>

#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::server {

// What a mailbox may hold until its server service grants a quota of its own.
inline constexpr std::uint64_t kDefaultQuotaBytes = 50 * 1024 * 1024;

class DiskStorage {
public:
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

    enum class RegisterResult {
        eRegistered,
        // The device is registered from another copy of its keys.
        eTaken,
    };

    struct DeviceEntry {
        Bytes certDer;
        Bytes sealingDer;
        bool registered = false;
        Bytes departure;
    };

    struct DeviceList {
        std::uint64_t version = 0;
        std::vector<DeviceEntry> devices;
    };

    explicit DiskStorage(const std::filesystem::path& root);

    // Told under the storage lock whenever what a user's mailbox holds or who reads it changes.
    void watch(std::function<void(const std::string& user)> changed);

    void watchDevices(std::function<void(const std::string& user)> changed);

    RegisterResult registerClient(const std::string& user, const std::string& clientId,
        const std::string& install, const Bytes& certDer, const Bytes& sealingDer,
        std::int64_t now);
    void unregisterClient(const std::string& user, const std::string& clientId);
    void departClient(const std::string& user, const std::string& clientId, const Bytes& departure);
    // A revoked device: unregistered and off the list.
    void dropDevice(const std::string& user, const std::string& clientId);
    DeviceList deviceList(const std::string& user);
    std::uint64_t devicesVersion(const std::string& user);
    // UTC seconds; what the silence of `purgeExpired` is measured from.
    void noteAsked(const std::string& user, const std::string& clientId, std::int64_t now);
    std::vector<std::string> listClients(const std::string& user);
    bool isClientRegistered(const std::string& user, const std::string& clientId);

    // False, and nothing kept, when the new ones would take the mailbox past `cap`.
    bool registerPasses(
        const std::string& user, const std::vector<Bytes>& handles, std::size_t cap);
    bool hasPass(const std::string& user, const Bytes& handle);
    std::size_t passCount(const std::string& user);
    std::size_t revokePasses(const std::string& user, const std::vector<Bytes>& handles);

    // Duplicate when held or seen before; `heldLimit` bounds what the class may hold at once.
    PutResult putBlob(const std::string& user, const std::string& blobId, const Bytes& data,
        const std::string& deliveryClass, std::uint64_t quotaBytes, std::int64_t receivedAt,
        std::optional<std::size_t> heldLimit = std::nullopt);
    // Pending for every registered device but the writer.
    PutResult putSelfBlob(const std::string& user, const std::string& blobId, const Bytes& data,
        std::uint64_t quotaBytes, std::int64_t receivedAt, const std::string& writer);
    // Pending for that one device, and gone once it acks.
    PutResult putAddressedBlob(const std::string& user, const std::string& blobId,
        const Bytes& data, const std::string& deliveryClass, std::uint64_t quotaBytes,
        std::int64_t receivedAt, const std::string& device);
    bool hasBlob(const std::string& user, const std::string& blobId);
    bool isPendingFor(const std::string& user, const std::string& blobId,
        const std::string& clientId);
    bool hasSeen(const std::string& user, const std::string& deliveryId);
    bool allowContactRequest(const std::string& user, std::int64_t now);
    std::size_t countHeld(const std::string& user, const std::string& deliveryClass);
    std::vector<PendingEntry> listPending(const std::string& user,
        const std::string& clientId);
    Bytes getBlob(const std::string& user, const std::string& blobId);
    void ackBlob(const std::string& user, const std::string& blobId,
        const std::string& clientId);
    void forgetUser(const std::string& user);
    // UTC seconds: seen markers before the first go; items stored and devices silent before the second.
    void purgeExpired(std::int64_t receivedBefore, std::int64_t storedBefore);
    std::uint64_t usage(const std::string& user);
    void setUserQuota(const std::string& user, std::uint64_t quotaBytes);
    std::uint64_t userQuota(const std::string& user, std::uint64_t fallback);

private:
    struct Window {
        std::int64_t start = 0;
        std::size_t count = 0;
    };
    std::map<std::string, Window> contactWindows_;

    std::filesystem::path userDir(const std::string& user) const;
    std::uint64_t usageLocked(const std::string& user) const;
    std::size_t countHeldLocked(const std::string& user, const std::string& deliveryClass);
    void removeItem(const std::string& user, const std::string& blobId);
    void tellChanged(const std::string& user) const;
    void unregisterLocked(const std::string& user, const std::string& clientId);
    void bumpDevicesLocked(const std::string& user);
    PutResult putLocked(const std::string& user, const std::string& blobId, const Bytes& data,
        const std::string& deliveryClass, std::uint64_t quotaBytes, std::int64_t receivedAt,
        std::optional<std::size_t> heldLimit, const std::string& addressedTo,
        const std::string& ackedBy);

    std::filesystem::path root_;
    std::mutex mutex_;
    std::function<void(const std::string& user)> changed_;
    std::function<void(const std::string& user)> devicesChanged_;
};

}  // namespace bazarish::server
