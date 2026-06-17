// Bazarish project (c) 2026
#include "MockPaymentGateway.hpp"
#include "MoneroPaymentGateway.hpp"
#include "PaymentGateway.hpp"

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <memory>
#include <string>
#include <thread>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#define CHECK_THROWS(expression)                                                       \
    do {                                                                               \
        bool thrown = false;                                                           \
        try {                                                                          \
            (void)(expression);                                                        \
        } catch (const std::exception&) {                                              \
            thrown = true;                                                             \
        }                                                                              \
        if (!thrown) {                                                                 \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d\n", __FILE__, __LINE__); \
            std::exit(1);                                                              \
        }                                                                              \
    } while (false)

using namespace bazarish::service;

namespace {

// The mock backend drives a full pending -> paid -> confirmed cycle, and
// autoconfirm settles on creation.
void testMockLifecycle()
{
    MockPaymentGateway gateway(false);
    const Invoice invoice = gateway.createInvoice({"0.01", "BTC"}, "fp:per-user-dest");
    CHECK(!invoice.id.empty());
    CHECK(invoice.payTo == "mock:" + invoice.id);
    CHECK(gateway.checkStatus(invoice.id).state == PaymentState::ePending);

    gateway.markPaid(invoice.id, "0.01", 0);
    CHECK(gateway.checkStatus(invoice.id).state == PaymentState::ePaid);

    gateway.markPaid(invoice.id, "0.01", 3);
    const PaymentStatus settled = gateway.checkStatus(invoice.id);
    CHECK(settled.state == PaymentState::eConfirmed);
    CHECK(settled.paidAmount == "0.01");
    CHECK(settled.confirmations == 3);

    CHECK_THROWS(gateway.checkStatus("no-such-invoice"));

    MockPaymentGateway autoGateway(true);
    const Invoice instant = autoGateway.createInvoice({"5", "USD"}, "ref");
    CHECK(autoGateway.checkStatus(instant.id).state == PaymentState::eConfirmed);
}

// The factory builds built-ins by type, honours a custom registration, and
// rejects unknown types.
void testFactoryAndRegistry()
{
    const std::unique_ptr<PaymentGateway> mock = makePaymentGateway({"mock", {}});
    CHECK(mock != nullptr);
    CHECK(mock->name() == "mock");
    CHECK(mock->checkStatus(mock->createInvoice({"1", "BTC"}, "r").id).state
        == PaymentState::ePending);

    const std::unique_ptr<PaymentGateway> autoMock
        = makePaymentGateway({"mock", {{"autoconfirm", "true"}}});
    CHECK(autoMock->checkStatus(autoMock->createInvoice({"1", "BTC"}, "r").id).state
        == PaymentState::eConfirmed);

    // A self-written backend plugs in by registering its own type name.
    registerPaymentGateway("my-gateway", [](const std::map<std::string, std::string>&) {
        return std::unique_ptr<PaymentGateway>(std::make_unique<MockPaymentGateway>(true));
    });
    const std::unique_ptr<PaymentGateway> custom = makePaymentGateway({"my-gateway", {}});
    CHECK(custom != nullptr);
    CHECK(custom->checkStatus(custom->createInvoice({"1", "BTC"}, "r").id).state
        == PaymentState::eConfirmed);

    CHECK_THROWS(makePaymentGateway({"does-not-exist", {}}));

    // monerod requires its connection params; the factory rejects a bare config.
    CHECK_THROWS(makePaymentGateway({"monerod", {}}));
}

// Local HMAC-SHA256 hex (mirrors the gateway) so the test can sign a webhook.
std::string hmacSha256Hex(const std::string& key, const std::string& data)
{
    EVP_MAC* const mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* const ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", digest, 0),
        OSSL_PARAM_construct_end(),
    };
    unsigned char out[EVP_MAX_MD_SIZE];
    std::size_t outLen = 0;
    EVP_MAC_init(ctx, reinterpret_cast<const unsigned char*>(key.data()), key.size(), params);
    EVP_MAC_update(ctx, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    EVP_MAC_final(ctx, out, &outLen, sizeof out);
    EVP_MAC_CTX_free(ctx);
    static const char* const kHex = "0123456789abcdef";
    std::string hex;
    for (std::size_t i = 0; i < outLen; ++i) {
        hex.push_back(kHex[out[i] >> 4]);
        hex.push_back(kHex[out[i] & 0x0f]);
    }
    return hex;
}

// A tiny stand-in for monero-wallet-rpc, so the gateway is exercised end to end
// (JSON-RPC 2.0 request construction + response parsing, the txid pull path and
// the HMAC-authenticated callback) without a real wallet.
void testMoneroAgainstStub()
{
    httplib::Server stub;
    stub.Post("/json_rpc", [](const httplib::Request& request, httplib::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body);
        const std::string method = body.at("method").get<std::string>();
        const nlohmann::json params = body.value("params", nlohmann::json::object());
        nlohmann::json result = nlohmann::json::object();

        const auto transfer = [](std::uint64_t amount, std::uint64_t conf, std::uint32_t minor) {
            return nlohmann::json{{"type", "in"}, {"amount", amount}, {"confirmations", conf},
                {"subaddr_index", {{"major", 0}, {"minor", minor}}}};
        };

        if (method == "create_address") {
            result = {{"address", "sub-addr-7"}, {"address_index", 7}};
        } else if (method == "get_transfers") {
            const std::uint32_t index = params.at("subaddr_indices").at(0).get<std::uint32_t>();
            if (index == 7) {
                result = {{"in", nlohmann::json::array({transfer(1000000, 12, 7)})}};
            } else if (index == 8) {
                result = {{"in", nlohmann::json::array({transfer(500000, 2, 8)})}};
            }  // index 9 → no "in" key → pending
        } else if (method == "get_transfer_by_txid") {
            const std::string txid = params.at("txid").get<std::string>();
            if (txid == "tx-confirmed") {
                result = {{"transfer", transfer(1000000, 12, 7)}};
            } else if (txid == "tx-wrong-sub") {
                result = {{"transfer", transfer(1000000, 12, 99)}};  // credits another subaddress
            }
        }
        const nlohmann::json reply = {{"id", "0"}, {"jsonrpc", "2.0"}, {"result", result}};
        response.set_content(reply.dump(), "application/json");
    });

    const int port = stub.bind_to_any_port("127.0.0.1");
    std::thread serverThread([&stub]() { (void)stub.listen_after_bind(); });
    while (!stub.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    MoneroPaymentGateway::Config config;
    config.url = "http://127.0.0.1:" + std::to_string(port);
    config.minConf = 10;
    config.callbackSecret = "shared-secret";
    MoneroPaymentGateway gateway(config);

    // createInvoice -> fresh subaddress; its minor index is the invoice id.
    const Invoice invoice = gateway.createInvoice({"1000000", "XMR"}, "fp:per-user-dest");
    CHECK(invoice.id == "7");
    CHECK(invoice.payTo == "sub-addr-7");

    // checkStatus across confirmed / seen-but-unconfirmed / nothing.
    const PaymentStatus confirmed = gateway.checkStatus("7");
    CHECK(confirmed.state == PaymentState::eConfirmed);
    CHECK(confirmed.paidAmount == "1000000");
    CHECK(confirmed.confirmations == 12);
    CHECK(gateway.checkStatus("8").state == PaymentState::ePaid);
    CHECK(gateway.checkStatus("9").state == PaymentState::ePending);

    // verifyByTxid (pull path): a matching txid settles; a txid crediting another
    // subaddress does not count for this invoice.
    CHECK(gateway.verifyByTxid("7", "tx-confirmed").state == PaymentState::eConfirmed);
    CHECK(gateway.verifyByTxid("7", "tx-wrong-sub").state == PaymentState::ePending);

    // parseWebhook (push path): a correctly-HMAC'd callback settles via the
    // wallet; a wrong signature is ignored.
    const std::string callbackBody = nlohmann::json{{"invoiceId", "7"}, {"txid", "tx-confirmed"}}.dump();
    const std::optional<PaymentStatus> good
        = gateway.parseWebhook(callbackBody, hmacSha256Hex("shared-secret", callbackBody));
    CHECK(good.has_value());
    CHECK(good->state == PaymentState::eConfirmed);
    CHECK(!gateway.parseWebhook(callbackBody, "deadbeef").has_value());

    stub.stop();
    serverThread.join();
}

}  // namespace

int main()
{
    testMockLifecycle();
    testFactoryAndRegistry();
    testMoneroAgainstStub();
    std::printf("TestPayments: all checks passed\n");
    return 0;
}
