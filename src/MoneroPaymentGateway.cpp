// Bazarish project (c) 2026
#include "MoneroPaymentGateway.hpp"

#include "Hmac.hpp"

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

struct HostPort {
    std::string host;
    int port = 0;
};

// Splits "http://host:port" into host/port (monero-wallet-rpc default 18082).
HostPort parseRpcUrl(const std::string& url)
{
    std::string rest = url;
    const std::string scheme = "http://";
    if (rest.rfind(scheme, 0) == 0) {
        rest = rest.substr(scheme.size());
    }
    if (const auto slash = rest.find('/'); slash != std::string::npos) {
        rest = rest.substr(0, slash);
    }
    HostPort hostPort;
    if (const auto colon = rest.find(':'); colon == std::string::npos) {
        hostPort.host = rest;
        hostPort.port = 18082;
    } else {
        hostPort.host = rest.substr(0, colon);
        hostPort.port = std::stoi(rest.substr(colon + 1));
    }
    if (hostPort.host.empty()) {
        throw std::runtime_error("monero: malformed url: " + url);
    }
    return hostPort;
}

// One JSON-RPC 2.0 call to monero-wallet-rpc; returns the "result" node. Throws
// on transport failure, malformed response, or an RPC-level error.
nlohmann::json rpcCall(const MoneroPaymentGateway::Config& config, const std::string& method,
    const nlohmann::json& params)
{
    const HostPort hostPort = parseRpcUrl(config.url);
    httplib::Client client(hostPort.host, hostPort.port);
    if (!config.user.empty()) {
        client.set_digest_auth(config.user, config.password);
    }
    client.set_connection_timeout(5, 0);
    client.set_read_timeout(20, 0);

    const nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"id", "0"},
        {"method", method},
        {"params", params},
    };
    const httplib::Result response = client.Post("/json_rpc", request.dump(), "application/json");
    if (!response) {
        throw std::runtime_error("monero: RPC transport failure for " + method);
    }
    const nlohmann::json body = nlohmann::json::parse(response->body, nullptr, false);
    if (body.is_discarded()) {
        throw std::runtime_error("monero: malformed RPC response for " + method + " (HTTP "
            + std::to_string(response->status) + ")");
    }
    if (body.contains("error") && !body.at("error").is_null()) {
        throw std::runtime_error("monero: RPC error for " + method + ": " + body.at("error").dump());
    }
    return body.value("result", nlohmann::json::object());
}

// Reduces incoming transfers to a normalised status against the conf threshold.
PaymentStatus statusFromTransfers(const nlohmann::json& transfers, const std::uint64_t minConf)
{
    std::uint64_t confirmed = 0;
    std::uint64_t seen = 0;
    int maxConf = 0;
    for (const nlohmann::json& transfer : transfers) {
        if (transfer.value("type", std::string("in")) != "in") {
            continue;  // ignore outgoing/other transfers sharing the txid
        }
        const std::uint64_t amount = transfer.value("amount", std::uint64_t{0});
        const std::uint64_t conf = transfer.value("confirmations", std::uint64_t{0});
        seen += amount;
        if (conf >= minConf) {
            confirmed += amount;
        }
        if (static_cast<int>(conf) > maxConf) {
            maxConf = static_cast<int>(conf);
        }
    }
    PaymentStatus status;
    if (confirmed > 0) {
        status.state = PaymentState::eConfirmed;
        status.paidAmount = std::to_string(confirmed);
        status.confirmations = maxConf;
    } else if (seen > 0) {
        status.state = PaymentState::ePaid;
        status.paidAmount = std::to_string(seen);
        status.confirmations = maxConf;
    } else {
        status.state = PaymentState::ePending;
        status.paidAmount = "0";
    }
    return status;
}

}  // namespace

MoneroPaymentGateway::MoneroPaymentGateway(Config config)
    : config_(std::move(config))
{
}

std::string MoneroPaymentGateway::name() const
{
    return "monerod";
}

Invoice MoneroPaymentGateway::createInvoice(const Money& amount, const std::string& orderRef)
{
    // A fresh subaddress of the configured account, labelled with the order ref.
    // Its minor index is the invoice id; the amount due is tracked by the caller.
    const nlohmann::json result = rpcCall(config_, "create_address",
        {{"account_index", config_.accountIndex}, {"count", 1}, {"label", orderRef}});
    Invoice invoice;
    invoice.id = std::to_string(result.at("address_index").get<std::uint32_t>());
    invoice.payTo = result.at("address").get<std::string>();
    invoice.amount = amount;
    invoice.state = PaymentState::ePending;
    return invoice;
}

PaymentStatus MoneroPaymentGateway::checkStatus(const std::string& invoiceId)
{
    const auto index = static_cast<std::uint32_t>(std::stoul(invoiceId));
    const nlohmann::json result = rpcCall(config_, "get_transfers",
        {{"in", true}, {"account_index", config_.accountIndex},
            {"subaddr_indices", nlohmann::json::array({index})}});
    return statusFromTransfers(result.value("in", nlohmann::json::array()), config_.minConf);
}

PaymentStatus MoneroPaymentGateway::verifyByTxid(
    const std::string& invoiceId, const std::string& txid)
{
    const auto index = static_cast<std::uint32_t>(std::stoul(invoiceId));
    const nlohmann::json result = rpcCall(
        config_, "get_transfer_by_txid", {{"txid", txid}, {"account_index", config_.accountIndex}});

    // Keep only transfers that credit this invoice's subaddress.
    nlohmann::json matching = nlohmann::json::array();
    const auto consider = [&](const nlohmann::json& transfer) {
        if (transfer.contains("subaddr_index")
            && transfer.at("subaddr_index").value("minor", std::uint32_t{0}) == index) {
            matching.push_back(transfer);
        }
    };
    if (result.contains("transfer")) {
        consider(result.at("transfer"));
    }
    for (const nlohmann::json& transfer : result.value("transfers", nlohmann::json::array())) {
        consider(transfer);
    }
    return statusFromTransfers(matching, config_.minConf);
}

std::optional<PaymentStatus> MoneroPaymentGateway::parseWebhook(
    const std::string& body, const std::string& signature)
{
    if (config_.callbackSecret.empty()) {
        return std::nullopt;  // callbacks disabled when no secret is configured
    }
    if (!constantTimeEqual(hmacSha256Hex(config_.callbackSecret, body), signature)) {
        return std::nullopt;  // not authentic — ignore
    }
    const nlohmann::json payload = nlohmann::json::parse(body, nullptr, false);
    if (payload.is_discarded() || !payload.contains("invoiceId") || !payload.contains("txid")) {
        return std::nullopt;
    }
    // The callback only triggers verification; the amount is taken from the wallet.
    return verifyByTxid(
        payload.at("invoiceId").get<std::string>(), payload.at("txid").get<std::string>());
}

std::unique_ptr<PaymentGateway> makeMoneroPaymentGateway(
    const std::map<std::string, std::string>& params)
{
    MoneroPaymentGateway::Config config;
    config.url = requireParam(params, "url");
    config.user = paramOr(params, "user", "");
    config.password = paramOr(params, "password", "");
    config.accountIndex = static_cast<std::uint32_t>(std::stoul(paramOr(params, "account", "0")));
    config.minConf = static_cast<std::uint64_t>(std::stoull(paramOr(params, "minconf", "10")));
    config.callbackSecret = paramOr(params, "callback_secret", "");
    return std::make_unique<MoneroPaymentGateway>(std::move(config));
}

}  // namespace bazarish::service
