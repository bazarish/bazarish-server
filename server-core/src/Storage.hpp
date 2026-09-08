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
//   user    - a key fingerprint (52 chars base32);
//   clientId, blobId - [a-z0-9_-], length 1..64. blobId is the
//   client-generated deliveryId, which makes putBlob deduplication the
//   deliveryId deduplication required by the delivery flow.
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

    // --- Delivery passes ---
    //
    // What admits one correspondent's mail, for as long as the account that
    // issued it lets them write. A pass does not expire and is not spent, so
    // there is one of these per correspondent rather than one per delivery.
    //
    // Only the hash of a pass is held. The sender presents the pass itself, so
    // what is on this disk recognises a delivery and cannot produce one - which
    // is what the token directory beside it could not say.

    virtual void registerPasses(const std::string& user, const std::vector<Bytes>& handles) = 0;
    virtual bool hasPass(const std::string& user, const Bytes& handle) = 0;
    virtual std::size_t passCount(const std::string& user) = 0;
    // Drops exactly these passes and returns how many were there. The account
    // knows what it issued, so nothing is swept for and nothing else is touched.
    virtual std::size_t revokePasses(
        const std::string& user, const std::vector<Bytes>& handles) = 0;

    // --- Pending content ---

    enum class PutResult {
        eStored,
        // Same blobId already present: success without storing again
        // (idempotent retries must not consume a second token).
        eDuplicate,
        // Storing would exceed quotaBytes; nothing was stored.
        eQuotaExceeded,
    };

    // Delivery class, surfaced back to fetching clients ("content" or
    // "contact"). This is the admission selector, not the content type, which
    // is end-to-end encrypted and never seen here.
    struct PendingEntry {
        std::string blobId;
        std::string deliveryClass;

        bool operator==(const PendingEntry&) const = default;
    };

    // alreadyAcked names a client that must not be waited for: the device that
    // wrote the blob in the first place. Mail from a stranger names nobody.
    virtual PutResult putBlob(const std::string& user, const std::string& blobId,
        const Bytes& data, const std::string& deliveryClass, std::int64_t receivedAt,
        std::uint64_t quotaBytes, const std::string& alreadyAcked = {})
        = 0;
    virtual bool hasBlob(const std::string& user, const std::string& blobId) = 0;

    // --- Replay protection (seen-deliveryId cache) ---
    //
    // Records every deliveryId admitted into a mailbox, independent of the
    // blob's lifecycle, so a replay of an already-delivered envelope - even one
    // since fetched, acked and swept from the mailbox - is recognised and
    // refused re-admission. One-time tokens already guard content-class
    // replays; tokenless contact requests have no token to spend, so this cache
    // is what closes them. Markers are retained until the TTL sweep
    // (purgeExpired), like pending blobs.
    virtual bool hasSeen(const std::string& user, const std::string& deliveryId) = 0;
    virtual void markSeen(const std::string& user, const std::string& deliveryId,
        std::int64_t receivedAt)
        = 0;

    virtual bool allowContactRequest(
        const std::string& user, std::int64_t now, std::size_t maxPerMinute)
        = 0;

    // How many blobs of one delivery class the mailbox is holding, whoever has or
    // has not acked them. What the tokenless path is bounded by: the rate limit
    // above says how fast requests may come, this says how many may pile up.
    virtual std::size_t countHeld(const std::string& user, const std::string& deliveryClass) = 0;

    // Blobs not yet acked by this client, oldest arrival first. The order is
    // part of the contract: a client shows a burst in the order its mailbox took
    // it, and nothing else here knows that order.
    virtual std::vector<PendingEntry> listPending(const std::string& user,
        const std::string& clientId)
        = 0;
    virtual Bytes getBlob(const std::string& user, const std::string& blobId) = 0;
    // Records the ack; deletes the blob immediately once every registered
    // client has acked it.
    virtual void ackBlob(const std::string& user, const std::string& blobId,
        const std::string& clientId)
        = 0;
    // Drops everything this server holds for the user: pending content, replay
    // markers, token hashes, the device registry and any quota override. What an
    // account being deleted means here - after it, the fingerprint is a stranger
    // again.
    virtual void forgetUser(const std::string& user) = 0;
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

};

}  // namespace bazarish::server
