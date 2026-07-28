// Bazarish project (c) 2026
#include "Facade.hpp"

#include <bazarish/Log.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

namespace {

constexpr const char* kVersion = "0.0.1";
constexpr const char* kDefaultHost = "127.0.0.1";
constexpr int kDefaultPort = 8419;

void printUsage()
{
    std::printf(
        "bazarish-facade-http %s\n"
        "Usage: bazarish-facade-http [--listen <host> <port>]\n"
        "                           [--messaging <host> <port>]\n"
        "                           [--account <host> <port>]\n"
        "                           [--blob-storage <host> <port>]\n"
        "                           [--base-path <secret-uri-prefix>]\n"
        "                           [--operator-fingerprint <fp>]...\n"
        "                           [--log-level <error|warn|info|debug>]\n"
        "       bazarish-facade-http --version\n"
        "\n"
        "Transparent reverse proxy: /v1/messaging/* -> messaging server,\n"
        "/v1/account/* -> service node, /v1/storage/{blob,usage} -> blob store.\n"
        "Place behind a reverse proxy that publishes it at a secret URI (or set\n"
        "--base-path).\n",
        kVersion);
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
    bazarish::facade::FacadeOptions options;
    options.version = kVersion;
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    for (int i = 1; i < argc;) {
        if (std::strcmp(argv[i], "--listen") == 0 && i + 2 < argc) {
            host = argv[i + 1];
            port = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--messaging") == 0 && i + 2 < argc) {
            options.messagingHost = argv[i + 1];
            options.messagingPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--account") == 0 && i + 2 < argc) {
            options.accountHost = argv[i + 1];
            options.accountPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--blob-storage") == 0 && i + 2 < argc) {
            options.blobStorageHost = argv[i + 1];
            options.blobStoragePort = std::atoi(argv[i + 2]);
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

    bazarish::log::setComponent("facade-http");
    bazarish::log::setLevel(logLevel);

    bazarish::facade::Facade facade(options);
    std::printf("bazarish-facade-http %s\n", kVersion);
    std::fflush(stdout);
    bazarish::log::info("messaging -> {}:{}, account -> {}:{}", options.messagingHost,
        options.messagingPort, options.accountHost, options.accountPort);
    bazarish::log::info("listening on {}:{}", host, port);

    if (!facade.listen(host, port)) {
        bazarish::log::error("failed to listen on {}:{}", host, port);
        return 1;
    }
    return 0;
}
