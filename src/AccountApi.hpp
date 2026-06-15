// Bazarish project (c) 2026
#pragma once

#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace httplib {
class Server;
}

namespace bazarish::service {

// A recurring paid service the portal offers, advertised in the discovery
// response. Every paid service is term-based and renewed from the user's
// cabinet — none are one-shot, so an ongoing server-side cost (an always-online
// destination, stored bytes, a reserved name) maps to ongoing payment.
struct PortalService {
    bool enabled = false;
    // Price per term, in atomic units of the settlement currency (never float).
    std::string priceAtomic;
    // Billing term length in days (e.g. 365 for a username, 30 for an i2p-dest).
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

    // Service-portal onboarding, advertised by GET /v1/account/portal so a
    // client can show the user where to register. Onboarding itself happens on
    // the portal (captcha for free registration, payment for paid services).
    std::string portalMessage;
    std::vector<std::string> portalLinks;
    std::string settlementCurrency = "XMR";
    bool freeRegistrationCaptcha = false;
    PortalService usernameService;
    PortalService i2pDestService;
    // Storage: every account gets defaultQuotaBytes free; storagePlan is the
    // optional paid upgrade (a bigger quota, billed monthly).
    StoragePlan storagePlan;
};

// The /v1/account/* HTTP API: subscriptions, aliases and alias resolution.
// Authenticated requests carry the caller's hybrid identity (see common
// Auth); a caller may only act on certificates naming its own UID.
class AccountApi {
public:
    AccountApi(SubscriptionStore& store, AccountApiOptions options);
    ~AccountApi();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    void stop();

private:
    void setupRoutes();

    SubscriptionStore& store_;
    const AccountApiOptions options_;
    std::unique_ptr<httplib::Server> http_;
};

}  // namespace bazarish::service
