// Bazarish project (c) 2026
#include "MockPaymentGateway.hpp"

#include <stdexcept>

namespace bazarish::service {

MockPaymentGateway::MockPaymentGateway(const bool autoConfirm)
    : autoConfirm_(autoConfirm)
{
}

std::string MockPaymentGateway::name() const
{
    return "mock";
}

Invoice MockPaymentGateway::createInvoice(const Money& amount, const std::string& orderRef)
{
    (void)orderRef;
    const std::lock_guard<std::mutex> lock(mutex_);
    const std::string id = "mock-" + std::to_string(++counter_);

    PaymentStatus status;
    Invoice invoice;
    invoice.id = id;
    invoice.payTo = "mock:" + id;  // synthetic receiving "address"
    invoice.amount = amount;
    if (autoConfirm_) {
        status.state = PaymentState::kConfirmed;
        status.paidAmount = amount.amount;
        status.confirmations = 1;
        invoice.state = PaymentState::kConfirmed;
    }
    statuses_[id] = status;
    return invoice;
}

PaymentStatus MockPaymentGateway::checkStatus(const std::string& invoiceId)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto it = statuses_.find(invoiceId);
    if (it == statuses_.end()) {
        throw std::runtime_error("mock gateway: unknown invoice " + invoiceId);
    }
    return it->second;
}

void MockPaymentGateway::markPaid(
    const std::string& invoiceId, const std::string& paidAmount, const int confirmations)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto it = statuses_.find(invoiceId);
    if (it == statuses_.end()) {
        throw std::runtime_error("mock gateway: unknown invoice " + invoiceId);
    }
    it->second.paidAmount = paidAmount;
    it->second.confirmations = confirmations;
    it->second.state = confirmations >= 1 ? PaymentState::kConfirmed : PaymentState::kPaid;
}

std::unique_ptr<PaymentGateway> makeMockPaymentGateway(
    const std::map<std::string, std::string>& params)
{
    const bool autoConfirm = paramOr(params, "autoconfirm", "false") == "true";
    return std::make_unique<MockPaymentGateway>(autoConfirm);
}

}  // namespace bazarish::service
