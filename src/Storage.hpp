// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace bazarish::server {

// Persistent server-side state for one node: per-user client registry,
// delivery-token hash sets and pending encrypted content. Content is opaque
// ciphertext; the interface never interprets blob contents.
//
// Identifier conventions enforced by implementations:
//   user    — a key fingerprint (52 chars base32);
//   clientId, blobId — [a-z0-9_-], length 1..64. blobId is the
//   client-generated messageId, which makes putBlob deduplication the
//   messageId deduplication required by the delivery flow.
class Storage {
public:
    virtual ~Storage() = default;

    // --- Client registry (drives the delete-when-all-acked rule) ---

    virtual void registerClient(const std::string& user, const std::string& clientId) = 0;
    // Retiring a client re-evaluates ack-completeness: blobs that were
    // waiting only on this client are deleted.
    virtual void unregisterClient(const std::string& user, const std::string& clientId) = 0;
    virtual std::vector<std::string> listClients(const std::string& user) = 0;
    virtual bool isClientRegistered(const std::string& user, const std::string& clientId) = 0;

    // --- One-time delivery token hashes ---

    virtual void registerTokenHashes(const std::string& user, const std::vector<Bytes>& hashes)
        = 0;
    // Atomically consumes the hash. Returns false when it was not present
    // (never registered or already consumed).
    virtual bool consumeTokenHash(const std::string& user, const Bytes& hash) = 0;
    virtual void deleteTokenHashes(const std::string& user, const std::vector<Bytes>& hashes) = 0;
    virtual std::size_t tokenHashCount(const std::string& user) = 0;

    // --- Pending content ---

    enum class PutResult {
        kStored,
        // Same blobId already present: success without storing again
        // (idempotent retries must not consume a second token).
        kDuplicate,
        // Storing would exceed quotaBytes; nothing was stored.
        kQuotaExceeded,
    };

    // Delivery kind, surfaced back to fetching clients ("message" or
    // "contact-request").
    struct PendingEntry {
        std::string blobId;
        std::string kind;

        bool operator==(const PendingEntry&) const = default;
    };

    virtual PutResult putBlob(const std::string& user, const std::string& blobId,
        const Bytes& data, const std::string& kind, std::int64_t receivedAt,
        std::uint64_t quotaBytes)
        = 0;
    virtual bool hasBlob(const std::string& user, const std::string& blobId) = 0;
    // Blobs not yet acked by this client.
    virtual std::vector<PendingEntry> listPending(const std::string& user,
        const std::string& clientId)
        = 0;
    virtual Bytes getBlob(const std::string& user, const std::string& blobId) = 0;
    // Records the ack; deletes the blob immediately once every registered
    // client has acked it.
    virtual void ackBlob(const std::string& user, const std::string& blobId,
        const std::string& clientId)
        = 0;
    // Drops all pending content of the user (subscription expiry).
    virtual void purgeUser(const std::string& user) = 0;
    // TTL sweep: removes blobs received strictly before the threshold.
    virtual void purgeExpired(std::int64_t receivedBefore) = 0;
    // Current pending-content usage in bytes.
    virtual std::uint64_t usage(const std::string& user) = 0;
};

}  // namespace bazarish::server
