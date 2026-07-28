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

class ServiceLifecycle;

// A recurring paid service the portal offers, advertised in the discovery
// response. Every paid service is term-based and renewed from the user's
// cabinet - none are one-shot, so an ongoing server-side cost (an always-online
// destination, stored bytes, a reserved name) maps to ongoing payment.
struct PortalService {
    bool enabled = false;
    // Price per term, in atomic units of the settlement currency (never float).
    std::string priceAtomic;
    // Billing term length in days (e.g. 30 for an i2p-dest).
    std::int64_t periodDays = 0;
};

// A paid storage plan: a larger quota than the free default, billed per term.
struct StoragePlan {
    bool enabled = false;
    std::uint64_t quotaBytes = 0;
    std::string priceAtomic;
    std::int64_t periodDays = 30;
};

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
    // client can show the user where to register. Onboarding itself happens on
    // the portal (captcha for free registration, payment for paid services).
    std::string portalMessage;
    std::vector<std::string> portalLinks;
    std::string settlementCurrency = "XMR";
    bool freeRegistrationCaptcha = false;
    PortalService i2pDestService;
    // Storage: every account gets defaultQuotaBytes free; storagePlan is the
    // optional paid upgrade (a bigger quota, billed monthly).
    StoragePlan storagePlan;

    // Pushes a user's effective storage quota to the messaging server when their
    // plan is (re)evaluated on subscribe/renew. Empty = no push (e.g. tests).
    std::function<void(const std::string& user, std::uint64_t quotaBytes)> publishQuota;
    // Pushes a paid user's offline I2P transient (or, with an empty transient,
    // a revoke) to the messaging server's per-user-destination endpoint. Empty =
    // no push (e.g. tests, or a deployment without per-user destinations).
    std::function<void(const std::string& user, const std::string& transientB64,
        std::int64_t expiresUnix)>
        publishI2pTransient;
    // Auto-renew/grace and the per-user i2p-dest status. Null in a deployment
    // without paid services: the transient upload then falls back to a plain
    // entitlement check and the status endpoint is unavailable.
    ServiceLifecycle* lifecycle = nullptr;
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
