// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace bazarish::service {

// Settlement state of a payment, normalised across all backends.
enum class PaymentState {
    kPending,    // invoice created, nothing (or not enough) received yet
    kPaid,       // funds seen but not final (0-conf / processing)
    kConfirmed,  // settled: enough confirmations, or the gateway calls it final
    kExpired,    // the invoice window passed unpaid
    kFailed,     // backend error, or underpaid past policy
};

const char* toString(PaymentState state);

// A monetary amount as an exact decimal string (never a float — money must not
// lose precision) plus its currency/asset code ("BTC", "XMR", "USD", ...).
struct Money {
    std::string amount;
    std::string currency;
};

// An invoice/order presented to the payer.
struct Invoice {
    std::string id;     // gateway-side invoice id (opaque to the caller)
    std::string payTo;  // an on-chain address OR a hosted checkout URL
    Money amount;
    std::int64_t expiresAt = 0;  // unix seconds; 0 means no explicit expiry
    PaymentState state = PaymentState::kPending;
};

// The current settlement status of a previously created invoice.
struct PaymentStatus {
    PaymentState state = PaymentState::kPending;
    std::string paidAmount;  // exact decimal string of what has been received
    int confirmations = 0;   // on-chain confirmations (0 for instant gateways)
};

// A pluggable payment backend. Each implementation maps the normalised
// invoice/status model onto one concrete processor — bitcoind, monerod,
// BTCPayServer, a fiat gateway, or anything self-written. Implementations must
// be safe to call concurrently from multiple request threads.
class PaymentGateway {
public:
    virtual ~PaymentGateway() = default;

    // The backend's registered type name (e.g. "bitcoind").
    virtual std::string name() const = 0;

    // Creates an invoice for amount. orderRef is an opaque caller token (e.g.
    // the user's fingerprint plus the feature) a backend may attach for its own
    // bookkeeping/labelling. Throws std::runtime_error on a backend failure.
    virtual Invoice createInvoice(const Money& amount, const std::string& orderRef) = 0;

    // Returns the current status of a previously created invoice. Throws
    // std::runtime_error on a backend failure (an unknown invoice is a failure).
    virtual PaymentStatus checkStatus(const std::string& invoiceId) = 0;

    // Pull path: verifies a transaction id the payer supplies (e.g. from the
    // frontend when a callback was missed) against the given invoice, returning
    // the resulting status. Backends without a txid concept throw
    // std::runtime_error (the default).
    virtual PaymentStatus verifyByTxid(
        const std::string& /*invoiceId*/, const std::string& /*txid*/)
    {
        throw std::runtime_error("payment gateway does not support txid verification");
    }

    // Push path: verifies and parses a notification (webhook) from the backend.
    // Backends that only support polling return std::nullopt (the default).
    virtual std::optional<PaymentStatus> parseWebhook(
        const std::string& /*body*/, const std::string& /*signature*/)
    {
        return std::nullopt;
    }
};

// Backend configuration: a type name plus an opaque key/value parameter bag
// (RPC endpoint, credentials, store id, …). Generic on purpose so a
// self-written gateway needs no change to this struct or the factory plumbing.
struct PaymentGatewayConfig {
    std::string type;
    std::map<std::string, std::string> params;
};

// A factory builds a backend from its parameter bag, reading the params it
// needs and throwing std::runtime_error on anything missing or invalid.
using PaymentGatewayFactory
    = std::function<std::unique_ptr<PaymentGateway>(const std::map<std::string, std::string>&)>;

// Registers a backend under type. Call this before makePaymentGateway to plug
// in a custom/self-written gateway; the built-ins register themselves. A
// repeated type overwrites the earlier registration.
void registerPaymentGateway(const std::string& type, PaymentGatewayFactory factory);

// Builds the gateway named by config.type from its params. Throws
// std::runtime_error when the type is neither a built-in nor registered.
std::unique_ptr<PaymentGateway> makePaymentGateway(const PaymentGatewayConfig& config);

// Small helpers shared by backend factories.
std::string paramOr(const std::map<std::string, std::string>& params, const std::string& key,
    const std::string& fallback);
std::string requireParam(const std::map<std::string, std::string>& params, const std::string& key);

}  // namespace bazarish::service
