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

    // Delivery class, surfaced back to fetching clients ("content" or
    // "contact"). This is the admission selector, not the content type, which
    // is end-to-end encrypted and never seen here.
    struct PendingEntry {
        std::string blobId;
        std::string deliveryClass;

        bool operator==(const PendingEntry&) const = default;
    };

    virtual PutResult putBlob(const std::string& user, const std::string& blobId,
        const Bytes& data, const std::string& deliveryClass, std::int64_t receivedAt,
        std::uint64_t quotaBytes)
        = 0;
    virtual bool hasBlob(const std::string& user, const std::string& blobId) = 0;

    // --- Replay protection (seen-messageId cache) ---
    //
    // Records every messageId admitted into a mailbox, independent of the
    // blob's lifecycle, so a replay of an already-delivered envelope — even one
    // since fetched, acked and swept from the mailbox — is recognised and
    // refused re-admission. One-time tokens already guard content-class
    // replays; tokenless contact requests have no token to spend, so this cache
    // is what closes them. Markers are retained until the TTL sweep
    // (purgeExpired), like pending blobs.
    virtual bool hasSeen(const std::string& user, const std::string& messageId) = 0;
    virtual void markSeen(const std::string& user, const std::string& messageId,
        std::int64_t receivedAt)
        = 0;

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

    // --- Per-user storage quota override ---
    //
    // The server enforces a quota when storing content. By default every user
    // gets the node's configured default; the operator's service node raises or
    // lowers a specific user's quota (a paid storage plan, or a lapse) by
    // setting an override here over the private channel.
    virtual void setUserQuota(const std::string& user, std::uint64_t quotaBytes) = 0;
    // The user's quota override, or fallback (the server default) when none.
    virtual std::uint64_t userQuota(const std::string& user, std::uint64_t fallback) = 0;

    // --- Content store (content-addressed bulk media) ---
    //
    // A global, content-addressed store for large encrypted media referenced
    // from messages (see docs Messages.md). contentId is the lowercase hex
    // SHA-256 of the ciphertext, so identical content dedups. The store holds
    // opaque ciphertext and never sees the decryption key or the content type
    // — adding a new media type needs no change here.

    virtual PutResult putContent(const std::string& contentId, const Bytes& data) = 0;
    virtual bool hasContent(const std::string& contentId) = 0;
    virtual Bytes getContent(const std::string& contentId) = 0;
};

}  // namespace bazarish::server
