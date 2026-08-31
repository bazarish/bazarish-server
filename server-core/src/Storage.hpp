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

    // --- One-time delivery tokens ---
    //
    // The tokens themselves are held, not their hashes: every token carries,
    // under the mask it was minted with, the mark that says which mask that was,
    // and revoking a correspondent means sweeping for that mark. A hash would
    // hide it. The consequence is deliberate: what is stored here can be spent,
    // so this directory is as sensitive as the mailbox beside it.

    virtual void registerTokens(const std::string& user, const std::vector<Bytes>& tokens) = 0;
    // Atomically consumes the token. Returns false when it was not present
    // (never registered, already consumed, or revoked).
    virtual bool consumeToken(const std::string& user, const Bytes& token) = 0;
    virtual std::size_t tokenCount(const std::string& user) = 0;
    // Drops every token of this user's minted under `mask`, and returns how many
    // went. Walks all of them, so it belongs on the node's own thread rather
    // than on the one answering a request.
    virtual std::size_t revokeTokens(const std::string& user, const Bytes& mask) = 0;

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

    // Counts one tokenless contact request against the destination's own minute
    // window and says whether it fits. Keyed by the destination's owner, not by
    // the mailbox the envelope named, so the answer never depends on a guess.
    // Drops token hashes registered before this instant. Tokens are one-time and
    // may wait years to be spent, so the horizon is long; this only stops an
    // abandoned mailbox's hashes from living forever.
    virtual void purgeTokensRegisteredBefore(std::int64_t registeredBefore) = 0;

    virtual bool allowContactRequest(
        const std::string& user, std::int64_t now, std::size_t maxPerMinute)
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
