// Bazarish project (c) 2026
#pragma once

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::service {

// Maps a payment-gateway invoice id to the user who created it, so a paid
// invoice is credited to the right account when settlement arrives by poll,
// webhook or txid (the webhook/txid paths carry only the invoice id, not the
// session). One small JSON map file.
class InvoiceStore {
public:
    explicit InvoiceStore(std::filesystem::path path);

    void put(const std::string& invoiceId, const std::string& user);
    std::optional<std::string> user(const std::string& invoiceId);

    // All invoice ids on record, for aggregate/admin views (outstanding
    // top-up invoices are these minus the ones already credited in the ledger).
    std::vector<std::string> ids();

private:
    std::filesystem::path path_;
    std::mutex mutex_;
};

}  // namespace bazarish::service
