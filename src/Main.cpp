// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "GrantStore.hpp"
#include "InvoiceStore.hpp"
#include "LedgerStore.hpp"
#include "PaymentGateway.hpp"
#include "PortalApi.hpp"
#include "QuotaPublisher.hpp"
#include "ServiceLifecycle.hpp"
#include "TransientPublisher.hpp"
#include "SelfHostedCaptcha.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

namespace fs = std::filesystem;

constexpr const char* kVersion = "0.0.1";
constexpr const char* kDefaultHost = "127.0.0.1";
constexpr int kDefaultPort = 8421;

void printUsage()
{
    std::printf(
        "bazarish-service-node %s\n"
        "Usage: bazarish-service-node --state <dir> --server-card <path>\n"
        "         [--listen <host> <port>] [--portal-listen <host> <port>]\n"
        "         [--payments-config <path>]\n"
        "         [--messaging <host> <port>] [--blob-storage <host> <port>]\n"
        "         [--operator-secret <secret>] [--log-level <error|warn|info|debug>]\n"
        "       bazarish-service-node --version\n"
        "\n"
        "The server card (produced by bazarish-server --i2p) binds this\n"
        "service node to its messaging server and is returned to clients on\n"
        "subscribe.\n",
        kVersion);
}

bazarish::Bytes readFileBytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return bazarish::Bytes(
        std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

// One paid service, parsed from the payments config.
struct ServiceConfig {
    bool enabled = false;
    std::string priceAtomic;  // atomic units of the settlement currency
    std::int64_t periodDays = 0;
    std::uint64_t quotaBytes = 0;  // storage only
};

// Portal onboarding presentation, parsed from the config. The message and
// links are advertised by the discovery endpoint so a client knows where to
// register; the captcha block governs free registration.
struct PortalConfig {
    std::string message;
    std::vector<std::string> links;
    bool captchaEnabled = true;
    int captchaLength = 5;
    std::int64_t captchaTtlSeconds = 300;
};

// The whole payments config. Its defaults are a local dev setup - an
// auto-confirm mock gateway and a few cheap services - so the demos and a
// no-config run work out of the box; a real deployment passes --payments-config.
struct PaymentsConfig {
    bazarish::service::PaymentGatewayConfig gateway{"mock", {{"autoconfirm", "true"}}};
    std::string settlementCurrency = "XMR";
    std::uint64_t freeStorageBytes = 10 * 1024 * 1024;
    ServiceConfig i2pDest{true, "100", 30, 0};
    ServiceConfig storage{true, "100", 30, 5ULL * 1024 * 1024 * 1024};
    PortalConfig portal;
};

ServiceConfig parseService(const nlohmann::json& service)
{
    ServiceConfig config;
    config.enabled = service.value("enabled", false);
    config.priceAtomic = service.value("priceAtomic", std::string());
    config.periodDays = service.value("periodDays", std::int64_t{0});
    config.quotaBytes = service.value("quotaBytes", std::uint64_t{0});
    return config;
}

PaymentsConfig loadPaymentsConfig(const fs::path& path)
{
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("failed to open payments config " + path.string());
    }
    const nlohmann::json doc = nlohmann::json::parse(in);

    PaymentsConfig config;
    if (doc.contains("gateway")) {
        const nlohmann::json& gateway = doc.at("gateway");
        config.gateway.type = gateway.at("type").get<std::string>();
        config.gateway.params.clear();
        if (gateway.contains("params")) {
            for (const auto& [key, value] : gateway.at("params").items()) {
                config.gateway.params[key] = value.get<std::string>();
            }
        }
    }
    config.settlementCurrency = doc.value("settlementCurrency", config.settlementCurrency);
    config.freeStorageBytes = doc.value("freeStorageBytes", config.freeStorageBytes);
    if (doc.contains("services")) {
        const nlohmann::json& services = doc.at("services");
        if (services.contains("i2pDest")) {
            config.i2pDest = parseService(services.at("i2pDest"));
        }
        if (services.contains("storage")) {
            config.storage = parseService(services.at("storage"));
        }
    }
    if (doc.contains("portal")) {
        const nlohmann::json& portal = doc.at("portal");
        config.portal.message = portal.value("message", std::string());
        if (portal.contains("links")) {
            config.portal.links = portal.at("links").get<std::vector<std::string>>();
        }
        if (portal.contains("captcha")) {
            const nlohmann::json& captcha = portal.at("captcha");
            config.portal.captchaEnabled = captcha.value("enabled", true);
            config.portal.captchaLength = captcha.value("length", 5);
            config.portal.captchaTtlSeconds = captcha.value("ttlSeconds", std::int64_t{300});
        }
    }
    return config;
}

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-service-node %s\n", kVersion);
        return 0;
    }
    if (argc < 5 || std::strcmp(argv[1], "--state") != 0
        || std::strcmp(argv[3], "--server-card") != 0) {
        printUsage();
        return 2;
    }

    const fs::path stateDir(argv[2]);
    const fs::path cardPath(argv[4]);
    std::string host = kDefaultHost;
    int port = kDefaultPort;
    std::string portalHost;
    int portalPort = 0;
    fs::path paymentsConfigPath;
    std::string messagingHost;
    int messagingPort = 0;
    std::string blobStorageHost;
    int blobStoragePort = 0;
    std::string operatorSecret;
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    for (int i = 5; i < argc;) {
        const std::string flag = argv[i];
        if (flag == "--listen" && i + 2 < argc) {
            host = argv[i + 1];
            port = std::atoi(argv[i + 2]);
            i += 3;
        } else if (flag == "--portal-listen" && i + 2 < argc) {
            portalHost = argv[i + 1];
            portalPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (flag == "--payments-config" && i + 1 < argc) {
            paymentsConfigPath = argv[i + 1];
            i += 2;
        } else if (flag == "--messaging" && i + 2 < argc) {
            messagingHost = argv[i + 1];
            messagingPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (flag == "--blob-storage" && i + 2 < argc) {
            blobStorageHost = argv[i + 1];
            blobStoragePort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (flag == "--operator-secret" && i + 1 < argc) {
            operatorSecret = argv[i + 1];
            i += 2;
        } else if (flag == "--log-level" && i + 1 < argc) {
            const std::optional<bazarish::log::Level> parsed
                = bazarish::log::levelFromString(argv[i + 1]);
            if (!parsed.has_value()) {
                printUsage();
                return 2;
            }
            logLevel = parsed.value();
            i += 2;
        } else {
            printUsage();
            return 2;
        }
    }

    bazarish::log::setComponent("service-node");
    bazarish::log::setLevel(logLevel);

    const bazarish::Bytes cardDer = readFileBytes(cardPath);
    const bazarish::ServerCard card = bazarish::ServerCard::verify(cardDer);

    // Payments/paid-services config (a single source feeding both the discovery
    // advertisement and the buy endpoints); dev defaults when no file is given.
    const PaymentsConfig payments
        = paymentsConfigPath.empty() ? PaymentsConfig{} : loadPaymentsConfig(paymentsConfigPath);

    fs::create_directories(stateDir);
    bazarish::service::SubscriptionStore store(stateDir / "store");
    bazarish::service::GrantStore grants(stateDir / "store");
    bazarish::service::LedgerStore ledger(stateDir / "store", payments.settlementCurrency);
    bazarish::service::InvoiceStore invoices(stateDir / "store" / "invoices.json");
    const std::unique_ptr<bazarish::service::PaymentGateway> gateway
        = bazarish::service::makePaymentGateway(payments.gateway);

    // Pushes a user's effective storage quota to both backends over the private
    // channel (operator secret): the messaging server (mailbox quota,
    // /v1/messaging/quota) and the blob store (blob-hosting quota,
    // /v1/storage/quota). Each is a no-op until its --messaging / --blob-storage
    // endpoint is given.
    const std::string messagingUrl = messagingPort > 0
        ? "http://" + messagingHost + ":" + std::to_string(messagingPort)
        : std::string();
    const std::string blobStorageUrl = blobStoragePort > 0
        ? "http://" + blobStorageHost + ":" + std::to_string(blobStoragePort)
        : std::string();
    const bazarish::service::QuotaPublisher messagingQuota(messagingUrl, operatorSecret);
    const bazarish::service::QuotaPublisher blobQuota(
        blobStorageUrl, operatorSecret, "/v1/storage/quota");
    const bazarish::service::TransientPublisher transientPub(messagingUrl, operatorSecret);
    const auto publishQuota
        = [&messagingQuota, &blobQuota](const std::string& user, const std::uint64_t quotaBytes) {
              messagingQuota.publish(user, quotaBytes);
              blobQuota.publish(user, quotaBytes);
          };

    // Auto-renews the term-based paid services (i2pDest with its one-step grace,
    // storage strict) from the prepaid balance, the single source of truth for
    // the i2p-dest toggle/status shared by the account API and the portal.
    const auto priceOf = [](const ServiceConfig& svc) -> std::uint64_t {
        return (svc.enabled && !svc.priceAtomic.empty())
            ? static_cast<std::uint64_t>(std::stoull(svc.priceAtomic))
            : 0;
    };
    bazarish::service::ServiceLifecycle lifecycle(grants, ledger,
        {priceOf(payments.i2pDest), payments.i2pDest.periodDays * 24 * 3600},
        {priceOf(payments.storage), payments.storage.periodDays * 24 * 3600},
        payments.storage.quotaBytes, payments.freeStorageBytes, publishQuota,
        [&transientPub](const std::string& user) { transientPub.publish(user, "", 0); });

    bazarish::service::AccountApiOptions options;
    options.serverFingerprint = card.server;
    options.serverCardDer = cardDer;
    options.settlementCurrency = payments.settlementCurrency;
    options.defaultQuotaBytes = payments.freeStorageBytes;
    options.portalMessage = payments.portal.message;
    options.portalLinks = payments.portal.links;
    options.freeRegistrationCaptcha = payments.portal.captchaEnabled;
    options.i2pDestService
        = {payments.i2pDest.enabled, payments.i2pDest.priceAtomic, payments.i2pDest.periodDays};
    options.storagePlan = {payments.storage.enabled, payments.storage.quotaBytes,
        payments.storage.priceAtomic, payments.storage.periodDays};
    options.publishQuota = publishQuota;
    options.publishI2pTransient = [&transientPub](const std::string& user,
                                      const std::string& transientB64,
                                      const std::int64_t expiresUnix) {
        transientPub.publish(user, transientB64, expiresUnix);
    };
    options.lifecycle = &lifecycle;
    bazarish::service::AccountApi api(store, grants, options);

    // The browser-facing portal (sign-in-with-key, captcha registration, ...),
    // sharing the grant store with the account API. Secrets are per-run; a
    // restart simply invalidates outstanding challenges/sessions.
    static std::unique_ptr<bazarish::service::SelfHostedCaptcha> captcha;
    static std::unique_ptr<bazarish::service::PortalApi> portal;
    static std::thread portalThread;
    if (portalPort > 0) {
        captcha = std::make_unique<bazarish::service::SelfHostedCaptcha>(
            bazarish::toHex(bazarish::randomBytes(16)), payments.portal.captchaLength,
            payments.portal.captchaTtlSeconds);
        bazarish::service::PortalApiOptions portalOptions;
        portalOptions.audience = card.server;
        portalOptions.requireCaptcha = payments.portal.captchaEnabled;
        portalOptions.challengeSecret = bazarish::toHex(bazarish::randomBytes(16));
        portalOptions.sessionSecret = bazarish::toHex(bazarish::randomBytes(16));
        portalOptions.defaultQuotaBytes = options.defaultQuotaBytes;
        portalOptions.freeSubscriptionTermSeconds = options.maxTermSeconds;
        portalOptions.settlementCurrency = payments.settlementCurrency;
        const auto addPaid = [&portalOptions](const std::string& name, const ServiceConfig& svc) {
            if (svc.enabled && !svc.priceAtomic.empty()) {
                portalOptions.paidServices[name]
                    = {static_cast<std::uint64_t>(std::stoull(svc.priceAtomic)),
                        svc.periodDays * 24 * 3600};
            }
        };
        addPaid("i2pDest", payments.i2pDest);
        addPaid("storage", payments.storage);
        portalOptions.storageQuotaBytes = payments.storage.quotaBytes;
        portalOptions.publishQuota = publishQuota;
        portalOptions.lifecycle = &lifecycle;
        portal = std::make_unique<bazarish::service::PortalApi>(
            portalOptions, *captcha, grants, ledger, invoices, *gateway);
        portalThread = std::thread(
            [portalHost, portalPort]() { portal->listen(portalHost, portalPort); });
        portalThread.detach();
        bazarish::log::info("portal on {}:{}", portalHost, portalPort);
    }

    std::printf("bazarish-service-node %s\n", kVersion);
    std::printf("bound to server: %s\n", card.server.c_str());
    std::fflush(stdout);
    bazarish::log::info("listening on {}:{} (private channel for facades)", host, port);

    if (!api.listen(host, port)) {
        bazarish::log::error("failed to listen on {}:{}", host, port);
        return 1;
    }
    return 0;
}
