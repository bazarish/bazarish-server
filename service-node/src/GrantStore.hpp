// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::service {

// Pending entitlement grants, set by the portal once a user has passed the
// captcha (free tier) or paid (paid tier), and consumed when the Client submits
// the corresponding user-signed certificate. This is how a browser flow (no
// private key) authorises an artifact only the Client can sign: the portal
// grants, the Client submits, the node checks the grant.
//
// Layout: <root>/grants/<fingerprint>.json  { "subscription": {...}? }
class GrantStore {
public:
    struct SubscriptionGrant {
        std::uint64_t quotaBytes = 0;
        std::int64_t termSeconds = 0;
        std::int64_t grantedAt = 0;
    };

    // The validity of the offline I2P transient the user's client last delegated.
    // Recorded so any of the user's devices can tell when to issue the next one
    // without holding the expiry itself.
    struct Transient {
        std::int64_t expires = 0;
        std::int64_t updatedAt = 0;
    };

    explicit GrantStore(std::filesystem::path root);

    // Grants (or refreshes) a pending subscription for the user - the quota and
    // maximum term the node will then accept on the user's submitted cert.
    void grantSubscription(const std::string& user, std::uint64_t quotaBytes,
        std::int64_t termSeconds, std::int64_t now);

    // The pending subscription grant without consuming it (UI / checks).
    std::optional<SubscriptionGrant> peekSubscription(const std::string& user);

    // Consumes the pending subscription grant (one-shot); nullopt if none.
    std::optional<SubscriptionGrant> takeSubscription(const std::string& user);

    void setI2pTransient(
        const std::string& user, std::int64_t transientExpires, std::int64_t updatedAt);

    std::optional<Transient> peekTransient(const std::string& user);

    // Whether an account may be served. On a server with open registration every
    // account is approved the moment it is created; on a moderated one the
    // operator approves it by hand, and until then the account exists but its
    // destination is never brought up.
    struct Approval {
        std::int64_t requestedAt = 0;
        std::int64_t approvedAt = 0;  // 0 while pending
        // What the operator wrote when they put this account back on hold, shown
        // to that user in place of the node-wide registration message. Empty
        // when the account is simply waiting its turn.
        std::string message;

        bool pending() const { return approvedAt == 0; }
    };

    // Records account creation. Keeps the original requestedAt on repeat calls
    // (a renewal must not restart the approval deadline) and never downgrades an
    // account that is already approved.
    void recordRegistration(const std::string& user, std::int64_t now, bool approved);

    std::optional<Approval> peekApproval(const std::string& user);

    // Marks the account approved. A no-op if it was never registered or is
    // already approved.
    void approve(const std::string& user, std::int64_t now);

    // Puts an approved account back on hold, with the operator's own words for
    // its owner. The account keeps everything else it has; what it loses is
    // being served.
    void hold(const std::string& user, const std::string& message, std::int64_t now);

    // Accounts still awaiting approval, oldest request first.
    std::vector<std::string> pendingUsers();

    // Every account this node has a record of, in fingerprint order. The operator
    // surface lists and searches over this: an account exists here from the
    // moment it registers, before any certificate is submitted.
    std::vector<std::string> allUsers() const;

    // Drops every grant of a user (account deletion). A ban, kept apart, stays.
    void erase(const std::string& user);

    // --- Bans ---
    //
    // A ban outlives the account it removed: it is what stops the same key from
    // registering again, so it is stored on its own rather than inside a record
    // the ban itself deletes.

    // Refuses this fingerprint from now on, with the reason its owner is shown.
    void ban(const std::string& user, const std::string& reason, std::int64_t now);

    struct Ban {
        std::string reason;
        std::int64_t bannedAt = 0;
    };

    // The ban on this fingerprint, if any.
    std::optional<Ban> peekBan(const std::string& user) const;

    // Lifts a ban. A no-op when there is none.
    void unban(const std::string& user);

private:
    std::filesystem::path grantPath(const std::string& user) const;
    std::filesystem::path banPath(const std::string& user) const;

    std::filesystem::path root_;
    mutable std::mutex mutex_;
};

}  // namespace bazarish::service
