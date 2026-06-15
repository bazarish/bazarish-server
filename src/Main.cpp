// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "GrantStore.hpp"
#include "InvoiceStore.hpp"
#include "LedgerStore.hpp"
#include "PaymentGateway.hpp"
#include "PortalApi.hpp"
#include "SelfHostedCaptcha.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
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
        "Usage: bazarish-service-node --state <dir> --server-card <path> "
        "[--listen <host> <port>] [--portal-listen <host> <port>]\n"
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
    if ((argc - 5) % 3 != 0) {
        printUsage();
        return 2;
    }
    for (int i = 5; i + 2 < argc; i += 3) {
        if (std::strcmp(argv[i], "--listen") == 0) {
            host = argv[i + 1];
            port = std::atoi(argv[i + 2]);
        } else if (std::strcmp(argv[i], "--portal-listen") == 0) {
            portalHost = argv[i + 1];
            portalPort = std::atoi(argv[i + 2]);
        } else {
            printUsage();
            return 2;
        }
    }

    const bazarish::Bytes cardDer = readFileBytes(cardPath);
    const bazarish::ServerCard card = bazarish::ServerCard::verify(cardDer);

    fs::create_directories(stateDir);
    bazarish::service::SubscriptionStore store(stateDir / "store");
    bazarish::service::GrantStore grants(stateDir / "store");
    bazarish::service::LedgerStore ledger(stateDir / "store", "XMR");
    bazarish::service::InvoiceStore invoices(stateDir / "store" / "invoices.json");
    // Payment backend (config-driven). Defaults to the in-process mock; a
    // deployment selecting paid services configures monerod.
    const std::unique_ptr<bazarish::service::PaymentGateway> gateway
        = bazarish::service::makePaymentGateway({"mock", {}});

    bazarish::service::AccountApiOptions options;
    options.serverFingerprint = card.server;
    options.serverCardDer = cardDer;
    bazarish::service::AccountApi api(store, grants, options);

    // The browser-facing portal (sign-in-with-key, captcha registration, …),
    // sharing the grant store with the account API. Secrets are per-run; a
    // restart simply invalidates outstanding challenges/sessions.
    static std::unique_ptr<bazarish::service::SelfHostedCaptcha> captcha;
    static std::unique_ptr<bazarish::service::PortalApi> portal;
    static std::thread portalThread;
    if (portalPort > 0) {
        captcha = std::make_unique<bazarish::service::SelfHostedCaptcha>(
            bazarish::toHex(bazarish::randomBytes(16)), 5, 300);
        bazarish::service::PortalApiOptions portalOptions;
        portalOptions.audience = card.server;
        portalOptions.challengeSecret = bazarish::toHex(bazarish::randomBytes(16));
        portalOptions.sessionSecret = bazarish::toHex(bazarish::randomBytes(16));
        portalOptions.defaultQuotaBytes = options.defaultQuotaBytes;
        portalOptions.freeSubscriptionTermSeconds = options.maxTermSeconds;
        portal = std::make_unique<bazarish::service::PortalApi>(
            portalOptions, *captcha, grants, ledger, invoices, *gateway);
        portalThread = std::thread(
            [portalHost, portalPort]() { portal->listen(portalHost, portalPort); });
        portalThread.detach();
        std::printf("portal on %s:%d\n", portalHost.c_str(), portalPort);
    }

    std::printf("bazarish-service-node %s\n", kVersion);
    std::printf("bound to server: %s\n", card.server.c_str());
    std::printf("listening on %s:%d (private channel for facades)\n", host.c_str(), port);
    std::fflush(stdout);

    if (!api.listen(host, port)) {
        std::fprintf(stderr, "failed to listen on %s:%d\n", host.c_str(), port);
        return 1;
    }
    return 0;
}
