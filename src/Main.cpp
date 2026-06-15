// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "GrantStore.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Certificates.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

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
        "[--listen <host> <port>]\n"
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
    if (argc == 8 && std::strcmp(argv[5], "--listen") == 0) {
        host = argv[6];
        port = std::atoi(argv[7]);
    } else if (argc != 5) {
        printUsage();
        return 2;
    }

    const bazarish::Bytes cardDer = readFileBytes(cardPath);
    const bazarish::ServerCard card = bazarish::ServerCard::verify(cardDer);

    fs::create_directories(stateDir);
    bazarish::service::SubscriptionStore store(stateDir / "store");
    bazarish::service::GrantStore grants(stateDir / "store");

    bazarish::service::AccountApiOptions options;
    options.serverFingerprint = card.server;
    options.serverCardDer = cardDer;
    bazarish::service::AccountApi api(store, grants, options);

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
