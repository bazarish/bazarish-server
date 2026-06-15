// Bazarish project (c) 2026
#pragma once

#include "PaymentGateway.hpp"

#include <map>
#include <mutex>
#include <string>

namespace bazarish::service {

// A deterministic in-process gateway with no external processor and no network.
// It doubles as the test stand-in for the entitlement flow and as a worked
// template for "self-written" backends. createInvoice mints a synthetic
// address; markPaid (a test/admin hook) drives settlement. With the
// "autoconfirm" parameter, invoices settle immediately on creation.
class MockPaymentGateway : public PaymentGateway {
public:
    explicit MockPaymentGateway(bool autoConfirm);

    std::string name() const override;
    Invoice createInvoice(const Money& amount, const std::string& orderRef) override;
    PaymentStatus checkStatus(const std::string& invoiceId) override;

    // Simulates an incoming payment for an existing invoice. confirmations >= 1
    // settles it (kConfirmed); 0 marks it seen-but-unconfirmed (kPaid).
    void markPaid(const std::string& invoiceId, const std::string& paidAmount, int confirmations);

private:
    const bool autoConfirm_;
    std::mutex mutex_;
    int counter_ = 0;
    std::map<std::string, PaymentStatus> statuses_;
};

std::unique_ptr<PaymentGateway> makeMockPaymentGateway(
    const std::map<std::string, std::string>& params);

}  // namespace bazarish::service
