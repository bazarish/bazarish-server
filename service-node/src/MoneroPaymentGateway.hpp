// Bazarish project (c) 2026
#pragma once

#include "PaymentGateway.hpp"

#include <cstdint>
#include <map>
#include <string>

namespace bazarish::service {

// Monero through a monero-wallet-rpc. An invoice is a fresh subaddress of the
// configured account; the invoice id is that subaddress's minor index. Both a
// push path (a watcher posts a callback authenticated by an HMAC over a shared
// secret) and a pull path (the frontend submits a txid) converge on the same
// wallet-verified settlement - a callback's amount is never trusted, it only
// triggers a get_transfer_by_txid against the wallet. Amounts are atomic
// piconero (integer strings). Parameters: url (http://host:port of
// monero-wallet-rpc), user/password (optional HTTP digest auth), account
// (default "0"), minconf (default "10"), callback_secret (HMAC key for webhooks).
class MoneroPaymentGateway : public PaymentGateway {
public:
    struct Config {
        std::string url;
        std::string user;
        std::string password;
        std::uint32_t accountIndex = 0;
        std::uint64_t minConf = 10;
        std::string callbackSecret;
    };

    explicit MoneroPaymentGateway(Config config);

    std::string name() const override;
    Invoice createInvoice(const Money& amount, const std::string& orderRef) override;
    PaymentStatus checkStatus(const std::string& invoiceId) override;
    PaymentStatus verifyByTxid(const std::string& invoiceId, const std::string& txid) override;
    std::optional<PaymentStatus> parseWebhook(
        const std::string& body, const std::string& signature) override;

private:
    const Config config_;
};

std::unique_ptr<PaymentGateway> makeMoneroPaymentGateway(
    const std::map<std::string, std::string>& params);

}  // namespace bazarish::service
