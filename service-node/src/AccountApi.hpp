// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "NodeSettings.hpp"
#include "SubscriptionStore.hpp"

#include <nlohmann/json.hpp>

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <Restart.hpp>

#include <cstdint>
#include <functional>
#include <memory>
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
    // Version string reported by /healthz.
    std::string version;
    // Fingerprints authorised to call /healthz (the admin panel). The caller
    // proves possession by signing the request; no shared secret. Empty disables
    // /healthz.
    std::vector<std::string> operatorFingerprints;
    // Asked for by the panel once a setting only a start reads has been written.
    // Empty answers that this node cannot restart itself rather than pretending.
    std::function<void()> requestRestart;

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

    // The live knobs, shared with the portal so the two cannot disagree and written
    // back to the node config: the quota a new account gets, whether it waits for
    // an operator, what it is told meanwhile, and how the portal presents itself.
    // Required - there is no second place any of it is kept.
    std::shared_ptr<NodeSettings> settings;
};

// The /v1/account/* HTTP API: who has an account here, what they are allowed, and
// the operator's view of both. Authenticated requests carry the caller's hybrid
// identity; a caller may only act on its own account.
class AccountApi {
public:
    AccountApi(SubscriptionStore& store, GrantStore& grants, AccountApiOptions options);
    ~AccountApi();

    AccountApi(const AccountApi&) = delete;
    AccountApi& operator=(const AccountApi&) = delete;

    // Binds and starts serving (port 0 lets the kernel pick). Returns the bound
    // port, 0 when the socket could not be taken.
    int bind(const std::string& host, int port);
    // Parks the caller until stop(). The engine serves on its own threads.
    void wait();
    void stop();

private:
    // Revokes the user's destination on the messaging server (an empty transient is
    // the revoke) and forgets the delegation this node recorded.
    void revokeDestination(const std::string& user);
    // Removes an account: its certificate, its grants and its destination. The
    // ban, if any, is not part of it - a ban outlives what it removed.
    void deleteAccount(const std::string& user);

    // The address an account is served at, repairing the cached field when an
    // older record carries only the certificate.
    std::string destinationOf(const std::optional<SubscriptionStore::Account>& held);

    // What the operator has set, live.
    NodeSettings::Values settings() const { return settings_->get(); }

    // One account as the operator surface reports it: what it is entitled to,
    // whether it is served yet, and how long its delegation still stands.
    nlohmann::json userRecord(
        const std::string& user, const std::optional<GrantStore::Approval>& approval);

    void setupRoutes();

    std::shared_ptr<NodeSettings> settings_;
    SubscriptionStore& store_;
    GrantStore& grants_;
    const AccountApiOptions options_;
    std::unique_ptr<bazarish::http::Server> http_;
    std::int64_t startedAt_ = 0;
    bazarish::StopGate stopGate_;

    auth::ReplayCache replayCache_;
};

}  // namespace bazarish::service
