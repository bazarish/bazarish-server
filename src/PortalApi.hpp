// Bazarish project (c) 2026
#pragma once

#include "Captcha.hpp"
#include "GrantStore.hpp"
#include "InvoiceStore.hpp"
#include "LedgerStore.hpp"
#include "LoginChallenge.hpp"
#include "PaymentGateway.hpp"
#include "PortalSession.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>

namespace httplib {
class Server;
}

namespace bazarish::service {

class ServiceLifecycle;

struct PortalApiOptions {
    // This service node's fingerprint — the login challenge audience, so a
    // challenge issued here cannot be replayed against another portal.
    std::string audience;
    // Portal-local HMAC secrets (login challenge binding, session cookie).
    std::string challengeSecret;
    std::string sessionSecret;
    std::int64_t sessionTtlSeconds = 3600;
    // Free-tier subscription granted on captcha registration.
    std::uint64_t defaultQuotaBytes = 10 * 1024 * 1024;
    std::int64_t freeSubscriptionTermSeconds = 14 * 24 * 3600;
    // When false, free registration is open to any logged-in (sign-in-with-key)
    // user without solving a captcha. Advertised to clients via the discovery
    // endpoint's freeRegistration.captcha flag, so the two cannot disagree.
    bool requireCaptcha = true;

    // Balance/pricing are in atomic units of this settlement currency.
    std::string settlementCurrency = "XMR";
    // A buyable service: its per-term price and term length.
    struct PaidService {
        std::uint64_t priceAtomic = 0;
        std::int64_t termSeconds = 0;
    };
    // Keyed by service name ("username", "i2pDest", "storage").
    std::map<std::string, PaidService> paidServices;
    // The quota the storage plan grants, pushed to the messaging server on a
    // storage purchase.
    std::uint64_t storageQuotaBytes = 0;
    // Pushes a user's effective storage quota to the messaging server. Empty =
    // no push (e.g. tests).
    std::function<void(const std::string& user, std::uint64_t quotaBytes)> publishQuota;
    // Drives the per-user i2p-dest toggle (enable/disable). Null in a deployment
    // without per-user destinations: the cabinet then offers no personal-dest
    // option.
    ServiceLifecycle* lifecycle = nullptr;
};

// The service node's web portal (browser-facing). It exposes two faces on one
// HTTP server, sharing all state:
//   * a JSON API under /portal/* and /v1/* for programmatic clients
//     (sign-in-with-key login, captcha, register, balance, topup, pay, buy);
//   * a server-rendered, JS-free HTML site at / (login, cabinet, register,
//     topup, pay, buy) so a user can onboard from a plain browser. The private
//     key never enters the browser: the login page shows a challenge the user
//     signs in their client and pastes back.
class PortalApi {
public:
    PortalApi(PortalApiOptions options, Captcha& captcha, GrantStore& grants, LedgerStore& ledger,
        InvoiceStore& invoices, PaymentGateway& gateway);
    ~PortalApi();

    bool listen(const std::string& host, int port);
    int bindToAnyPort(const std::string& host);
    bool listenAfterBind();
    void stop();

private:
    void setupRoutes();
    // Registers the browser-facing HTML routes on the same server.
    void setupWebRoutes();
    // Credits a confirmed invoice to its owner exactly once. Returns whether a
    // credit was applied.
    bool settleInvoice(
        const std::string& invoiceId, const PaymentStatus& status, std::int64_t now);

    // Buying (or renewing) a paid service: debit the balance and extend the
    // entitlement. Shared by the JSON and the HTML buy paths so the money
    // handling lives in one place.
    enum class BuyOutcome { eOk, eNotOffered, eInsufficient };
    struct BuyResult {
        BuyOutcome outcome = BuyOutcome::eOk;
        std::int64_t paidThrough = 0;
    };
    BuyResult buyService(const std::string& user, const std::string& service, std::int64_t now);

    PortalApiOptions options_;
    Captcha& captcha_;
    GrantStore& grants_;
    LedgerStore& ledger_;
    InvoiceStore& invoices_;
    PaymentGateway& gateway_;
    LoginChallenge login_;
    PortalSession session_;
    std::unique_ptr<httplib::Server> http_;
};

}  // namespace bazarish::service
