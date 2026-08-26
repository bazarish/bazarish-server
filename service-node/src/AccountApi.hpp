// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "NodeSettings.hpp"
#include "SubscriptionStore.hpp"

#include <nlohmann/json.hpp>

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::http {
class Server;
}

namespace bazarish::service {

struct AccountApiOptions {
    // The messaging server this service node belongs to.
    std::string serverFingerprint;
    // The server card the node hands its own clients (DER). It names the server,
    // so it is never part of what a contact can fetch.
    Bytes serverCardDer;
    // Quota granted to a new account. The initial value: an operator can change
    // it while the node runs (see settings).
    std::uint64_t defaultQuotaBytes = 50 * 1024 * 1024;
    // Version string reported by /healthz.
    std::string version;
    // Fingerprints authorised to call /healthz (the admin panel). The caller
    // proves possession by signing the request; no shared secret. Empty disables
    // /healthz.
    std::vector<std::string> operatorFingerprints;

    // Service-portal onboarding, advertised by GET /v1/account/portal so a
    // client can show the user where to register.
    std::string portalMessage;
    std::vector<std::string> portalLinks;
    bool freeRegistrationCaptcha = false;

    // Pushes the user's offline I2P transient (or, with an empty transient, a
    // revoke) to the messaging server's per-user-destination endpoint. Empty =
    // no push (e.g. tests, or a deployment without per-user destinations).
    // Returns whether the messaging server took it: a delegation that did not
    // arrive leaves the destination unserved, so it must not be recorded as held.
    std::function<bool(const std::string& user, const std::string& transientB64,
        std::int64_t expiresUnix)>
        publishI2pTransient;

    // Tells the messaging server an account is gone, so the mailbox and
    // everything else held for that fingerprint goes with it. Empty = no push
    // (tests, or a node with no messaging server configured). Returns whether
    // the messaging server took it: a deletion it refused leaves mail behind,
    // and that is worth a line in the log rather than silence.
    std::function<bool(const std::string& user)> forgetMailbox;

    // Pushes the quota a subscription grants to the messaging server, which
    // stores the mail and would otherwise answer the user with its own default.
    // Empty = no push (tests, or a deployment where the two are configured by
    // hand to the same number).
    std::function<void(const std::string& user, std::uint64_t quotaBytes)> publishQuota;

    // Rotating the serving sealing key the messaging server holds for a user's
    // destination. Two phases: prepare mints a replacement and returns its public
    // half, commit puts it in force. The old key keeps serving until the commit,
    // so a rotation the user never finishes changes nothing.
    std::function<std::optional<std::string>(const std::string& user)> prepareServingKey;
    std::function<bool(const std::string& user)> commitServingKey;

    // How an account becomes servable. eOpen: live the moment it is created.
    // eApproval: the account is created but stays frozen - its destination is
    // never brought up, so it can neither send nor receive - until an operator
    // approves it by hand. This is moderation, not a paywall: the operator sets
    // registrationMessage to tell the user how to reach them.
    // The initial values: an operator changes both while the node runs.
    enum class Registration { eOpen, eApproval };
    Registration registration = Registration::eOpen;
    std::string registrationMessage;

    // The live knobs, shared with the portal so the two cannot disagree and
    // written back to the node config. When null (tests), the values above are
    // taken as the settings and nothing is persisted.
    std::shared_ptr<NodeSettings> settings;
};

// The /v1/account/* HTTP API: subscriptions, aliases and alias resolution.
// Authenticated requests carry the caller's hybrid identity (see common
// Auth); a caller may only act on certificates naming its own UID.
class AccountApi {
public:
    AccountApi(SubscriptionStore& store, GrantStore& grants, AccountApiOptions options);
    ~AccountApi();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    void stop();

private:
    // One account as the operator surface reports it: what it is entitled to,
    // whether it is served yet, and how long its delegation still stands.
    // Revokes the user's destination on the messaging server (an empty transient
    // is the revoke) and forgets the delegation this node recorded.
    void revokeDestination(const std::string& user);
    // Removes an account: its certificate, its grants and its destination. The
    // ban, if any, is not part of it - a ban outlives what it removed.
    void deleteAccount(const std::string& user);

    // The address an account is served at, repairing the cached field when an
    // older record carries only the certificate.
    std::string destinationOf(const std::optional<SubscriptionStore::Account>& held);

    // What the operator has set, live.
    NodeSettings::Values settings() const { return settings_->get(); }

    nlohmann::json userRecord(
        const std::string& user, const std::optional<GrantStore::Approval>& approval);

    // Binds on a chosen port (0 lets the kernel pick) and starts serving.
    int bindToAnyPort(const std::string& host, int port);
    void setupRoutes();

    std::shared_ptr<NodeSettings> settings_;
    SubscriptionStore& store_;
    GrantStore& grants_;
    const AccountApiOptions options_;
    std::unique_ptr<bazarish::http::Server> http_;
    std::int64_t startedAt_ = 0;

    // listenAfterBind() parks the caller's thread here until stop() releases it.
    std::mutex stopMutex_;
    std::condition_variable stopCv_;
    bool stopping_ = false;

    auth::ReplayCache replayCache_;
};

}  // namespace bazarish::service
