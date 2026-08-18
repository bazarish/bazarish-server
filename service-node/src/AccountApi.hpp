// Bazarish project (c) 2026
#pragma once

#include "GrantStore.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace httplib {
class Server;
}

namespace bazarish::service {

struct AccountApiOptions {
    // The messaging server this service node belongs to; subscription
    // certificates must name it.
    std::string serverFingerprint;
    // The server card returned to clients on subscribe (DER).
    Bytes serverCardDer;
    // Quota granted to a free subscription.
    std::uint64_t defaultQuotaBytes = 10 * 1024 * 1024;
    // Maximum subscription validity the server accepts.
    std::int64_t maxTermSeconds = 14 * 24 * 3600;
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
    std::function<void(const std::string& user, const std::string& transientB64,
        std::int64_t expiresUnix)>
        publishI2pTransient;

    // Pushes the quota a subscription grants to the messaging server, which
    // stores the mail and would otherwise answer the user with its own default.
    // Empty = no push (tests, or a deployment where the two are configured by
    // hand to the same number).
    std::function<void(const std::string& user, std::uint64_t quotaBytes)> publishQuota;

    // How an account becomes servable. eOpen: live the moment it is created.
    // eApproval: the account is created but stays frozen - its destination is
    // never brought up, so it can neither send nor receive - until an operator
    // approves it by hand. This is moderation, not a paywall: the operator sets
    // registrationMessage to tell the user how to reach them.
    enum class Registration { eOpen, eApproval };
    Registration registration = Registration::eOpen;
    std::string registrationMessage;
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
    void setupRoutes();

    SubscriptionStore& store_;
    GrantStore& grants_;
    const AccountApiOptions options_;
    std::unique_ptr<httplib::Server> http_;
    std::int64_t startedAt_ = 0;

    auth::ReplayCache replayCache_;
};

}  // namespace bazarish::service
