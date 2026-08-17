// Bazarish project (c) 2026
#include "Facade.hpp"
#include "I2pFront.hpp"

#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>

namespace {

constexpr const char* kVersion = "0.0.1";
constexpr const char* kDefaultHost = "127.0.0.1";
constexpr int kDefaultPort = 8419;

void printUsage()
{
    std::printf(
        "bazarish-facade-http %s\n"
        "Usage: bazarish-facade-http --base-path <secret-uri-prefix> | --public\n"
        "                           [--listen <host> <port>]\n"
        "                           [--i2p --state <dir> [--i2p-dests <n>]]\n"
        "                           [--privacy <minimal|middle|max>] [--tunnel-quantity <n>]\n"
        "                           [--ops-listen <host> <port>]\n"
        "                           [--messaging <host> <port>]\n"
        "                           [--account <host> <port>]\n"
        "                           [--operator-fingerprint <fp>]...\n"
        "                           [--log-level <error|warn|info|debug>]\n"
        "       bazarish-facade-http --version\n"
        "\n"
        "Transparent reverse proxy: <secret>/v1/messaging/* -> messaging server,\n"
        "<secret>/v1/account/* -> service node; anything else is a 404.\n"
        "The secret prefix is mandatory: it is the only thing standing between a\n"
        "scan of the host and the clearnet API, and it reaches a client only inside\n"
        "the facade URL of the server descriptor. Use --public solely when a\n"
        "fronting proxy already publishes this facade under a secret URI.\n"
        "--i2p publishes the same API on the facade's own I2P destination(s) - the\n"
        "preferred way in: clients reach it without touching the clearnet at all.\n"
        "The keys live in --state and the addresses are stable across restarts,\n"
        "because they travel in the server descriptor. Clearnet stays up beside it\n"
        "for the bootstrap (a client with no netDb yet reseeds over it).\n"
        "--ops-listen adds a private socket serving the operator-signed /healthz\n"
        "for the admin panel; it is never published to clients.\n",
        kVersion);
}

// A base path must be a single absolute URI prefix the facade can strip:
// leading slash, no trailing slash, no query or fragment.
bool isValidBasePath(const std::string& path)
{
    if (path.empty() || path.front() != '/' || path.back() == '/') {
        return false;
    }
    return path.find_first_of("?# ") == std::string::npos;
}

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-facade-http %s\n", kVersion);
        return 0;
    }

    std::string host = kDefaultHost;
    int port = kDefaultPort;
    std::string opsHost;
    int opsPort = 0;
    bool servePublicRoot = false;
    bool enableI2p = false;
    std::filesystem::path stateDir;
    std::size_t i2pDests = 1;
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
    int tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity;
    bazarish::facade::FacadeOptions options;
    options.version = kVersion;
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    for (int i = 1; i < argc;) {
        if (std::strcmp(argv[i], "--listen") == 0 && i + 2 < argc) {
            host = argv[i + 1];
            port = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--ops-listen") == 0 && i + 2 < argc) {
            opsHost = argv[i + 1];
            opsPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--i2p") == 0) {
            enableI2p = true;
            i += 1;
        } else if (std::strcmp(argv[i], "--state") == 0 && i + 1 < argc) {
            stateDir = argv[i + 1];
            i += 2;
        } else if (std::strcmp(argv[i], "--i2p-dests") == 0 && i + 1 < argc) {
            i2pDests = static_cast<std::size_t>(std::atoi(argv[i + 1]));
            i += 2;
        } else if (std::strcmp(argv[i], "--privacy") == 0 && i + 1 < argc) {
            const std::optional<bazarish::i2p::Privacy> parsed
                = bazarish::i2p::privacyFromString(argv[i + 1]);
            if (!parsed.has_value()) {
                printUsage();
                return 2;
            }
            privacy = parsed.value();
            i += 2;
        } else if (std::strcmp(argv[i], "--tunnel-quantity") == 0 && i + 1 < argc) {
            tunnelQuantity = std::atoi(argv[i + 1]);
            i += 2;
        } else if (std::strcmp(argv[i], "--public") == 0) {
            servePublicRoot = true;
            i += 1;
        } else if (std::strcmp(argv[i], "--messaging") == 0 && i + 2 < argc) {
            options.messagingHost = argv[i + 1];
            options.messagingPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--account") == 0 && i + 2 < argc) {
            options.accountHost = argv[i + 1];
            options.accountPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--base-path") == 0 && i + 1 < argc) {
            options.basePath = argv[i + 1];
            i += 2;
        } else if (std::strcmp(argv[i], "--operator-fingerprint") == 0 && i + 1 < argc) {
            options.operatorFingerprints.emplace_back(argv[i + 1]);
            i += 2;
        } else if (std::strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
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

    if (options.basePath.empty() && !servePublicRoot) {
        std::fprintf(stderr,
            "the clearnet API must not be reachable without a secret prefix: pass\n"
            "--base-path <secret>, or --public when a fronting proxy owns the secret\n");
        return 2;
    }
    if (!options.basePath.empty() && servePublicRoot) {
        std::fprintf(stderr, "--public and --base-path contradict each other\n");
        return 2;
    }
    if (!options.basePath.empty() && !isValidBasePath(options.basePath)) {
        std::fprintf(stderr,
            "invalid --base-path: expected an absolute prefix such as /h9fd/kshdcy,\n"
            "with no trailing slash and no query\n");
        return 2;
    }

    bazarish::log::setComponent("facade-http");
    bazarish::log::setLevel(logLevel);

    bazarish::facade::Facade facade(options);
    std::printf("bazarish-facade-http %s\n", kVersion);
    std::fflush(stdout);
    bazarish::log::info("messaging -> {}:{}, account -> {}:{}", options.messagingHost,
        options.messagingPort, options.accountHost, options.accountPort);

    if (enableI2p && stateDir.empty()) {
        std::fprintf(stderr, "--i2p needs --state <dir>: the destination keys must persist,\n"
                             "their addresses travel in the server descriptor\n");
        return 2;
    }
    if (i2pDests == 0) {
        std::fprintf(stderr, "--i2p-dests must be at least 1\n");
        return 2;
    }

    std::thread opsThread;
    if (opsPort != 0) {
        if (!facade.bindOps(opsHost, opsPort)) {
            bazarish::log::error("failed to listen on {}:{} (ops)", opsHost, opsPort);
            return 1;
        }
        opsThread = std::thread([&facade]() {
            if (!facade.listenOpsAfterBind()) {
                bazarish::log::error("ops listener failed");
            }
        });
        bazarish::log::info("ops listening on {}:{}", opsHost, opsPort);
    }

    bazarish::log::info("listening on {}:{}{}", host, port,
        options.basePath.empty() ? " (no secret prefix: fronting proxy owns it)"
                                 : options.basePath);
    if (!facade.bind(host, port)) {
        bazarish::log::error("failed to listen on {}:{}", host, port);
        return 1;
    }
    std::thread httpThread([&facade]() {
        if (!facade.listenAfterBind()) {
            bazarish::log::error("listener failed");
        }
    });

    // The I2P front relays into the listener above, so it starts once that is
    // up. Its addresses are the preferred way in; clearnet stays for bootstrap.
    std::unique_ptr<bazarish::facade::I2pFront> i2pFront;
    if (enableI2p) {
        bazarish::facade::I2pFront::Options frontOptions;
        frontOptions.stateDir = stateDir;
        // A wildcard bind is reached over the loopback like any local client.
        frontOptions.localHost = host == "0.0.0.0" ? std::string("127.0.0.1") : host;
        frontOptions.localPort = port;
        frontOptions.destinations = i2pDests;
        frontOptions.privacy = privacy;
        frontOptions.tunnelQuantity = tunnelQuantity;
        i2pFront = std::make_unique<bazarish::facade::I2pFront>(frontOptions);
        bazarish::log::info("building I2P destination(s) for the facade API...");
        for (const std::string& address : i2pFront->start()) {
            std::printf("i2p facade: http://%s%s\n", address.c_str(), options.basePath.c_str());
        }
        std::fflush(stdout);
    }

    // The bind above already proved the port; from here the listener only ends
    // when the process is asked to stop.
    httpThread.join();
    i2pFront.reset();
    facade.stop();
    if (opsThread.joinable()) {
        opsThread.join();
    }
    return 0;
}
