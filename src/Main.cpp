// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"
#include "HttpApi.hpp"
#include "I2pFederation.hpp"
#include "TcpFederation.hpp"

#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Sam.hpp>

#include <nlohmann/json.hpp>

#include <ctime>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace {

namespace fs = std::filesystem;

constexpr const char* kVersion = "0.0.2";
constexpr const char* kDefaultHost = "127.0.0.1";
constexpr int kDefaultPort = 8420;

void printUsage()
{
    std::printf(
        "bazarish-server %s\n"
        "Usage: bazarish-server --state <directory> [--listen <host> <port>]\n"
        "          [--i2p] [--federation-listen <host> <port>]\n"
        "          [--contact-request-limit <bytes>] [--operator-secret <secret>]\n"
        "          [--privacy <minimal|middle|max>]\n"
        "       bazarish-server --version\n"
        "\n"
        "The state directory holds the server keys and the content storage;\n"
        "keys are generated on first start. The server card is always written\n"
        "to <state>/server-card.der. --i2p enables the I2P federation transport\n"
        "(requires a local SAM bridge) and adds the i2p endpoint to the card;\n"
        "without it the card carries no endpoints (local delivery only).\n"
        "--contact-request-limit <bytes> caps the tokenless contact-request\n"
        "payload. --federation-listen enables a plain-TCP federation transport\n"
        "(operator private channel / local testing). Outbound federation\n"
        "resolves peers from <state>/peers.json ({\"<server-fingerprint>\":\n"
        "\"<i2p-destination-or-host:port>\"}).\n",
        kVersion);
}

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

// Resolves a peer server fingerprint to its transport endpoint by reading
// peers.json on each call, so peers can be added without a restart. A
// missing or malformed file just yields no route.
std::optional<std::string> resolvePeer(const fs::path& peersPath, const std::string& serverFp)
{
    if (!fs::exists(peersPath)) {
        return std::nullopt;
    }
    try {
        std::ifstream in(peersPath, std::ios::binary);
        const nlohmann::json peers = nlohmann::json::parse(in);
        const auto found = peers.find(serverFp);
        if (found == peers.end()) {
            return std::nullopt;
        }
        return found->get<std::string>();
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::string readFileText(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open " + path.string());
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void writePrivateFile(const fs::path& path, const std::string& text)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to open " + path.string());
    }
    out << text;
    if (!out) {
        throw std::runtime_error("failed to write " + path.string());
    }
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);
}

// Loads the server identity from the state directory, generating it on
// first start.
bazarish::Identity loadOrCreateIdentity(const fs::path& stateDir)
{
    const fs::path path = stateDir / "identity.pem";
    if (fs::exists(path)) {
        return bazarish::Identity::fromPrivatePem(readFileText(path));
    }
    bazarish::Identity identity = bazarish::Identity::generate();
    writePrivateFile(path, identity.privatePem());
    return identity;
}

bazarish::Key loadOrCreateSealingKey(const fs::path& stateDir)
{
    const fs::path path = stateDir / "sealing.pem";
    if (fs::exists(path)) {
        return bazarish::Key::fromPrivatePem(readFileText(path));
    }
    bazarish::Key key = bazarish::Key::generateSealing();
    writePrivateFile(path, key.privatePem());
    return key;
}

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-server %s\n", kVersion);
        return 0;
    }
    if (argc < 3 || std::strcmp(argv[1], "--state") != 0) {
        printUsage();
        return 2;
    }

    const fs::path stateDir(argv[2]);
    std::string host = kDefaultHost;
    int port = kDefaultPort;
    bool enableI2p = false;
    bool enableTcpFed = false;
    std::string fedHost = kDefaultHost;
    int fedPort = 0;
    bazarish::server::DeliveryEngineOptions engineOptions;
    std::string operatorSecret;
    bazarish::I2pPrivacy privacy = bazarish::I2pPrivacy::kMax;
    for (int i = 3; i < argc;) {
        if (std::strcmp(argv[i], "--listen") == 0 && i + 2 < argc) {
            host = argv[i + 1];
            port = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--operator-secret") == 0 && i + 1 < argc) {
            operatorSecret = argv[i + 1];
            i += 2;
        } else if (std::strcmp(argv[i], "--i2p") == 0) {
            enableI2p = true;
            i += 1;
        } else if (std::strcmp(argv[i], "--federation-listen") == 0 && i + 2 < argc) {
            enableTcpFed = true;
            fedHost = argv[i + 1];
            fedPort = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--contact-request-limit") == 0 && i + 1 < argc) {
            engineOptions.contactRequestLimitBytes
                = std::strtoull(argv[i + 1], nullptr, 10);
            i += 2;
        } else if (std::strcmp(argv[i], "--privacy") == 0 && i + 1 < argc) {
            const std::optional<bazarish::I2pPrivacy> parsed
                = bazarish::i2pPrivacyFromString(argv[i + 1]);
            if (!parsed.has_value()) {
                printUsage();
                return 2;
            }
            privacy = parsed.value();
            i += 2;
        } else {
            printUsage();
            return 2;
        }
    }

    fs::create_directories(stateDir);
    const bazarish::Identity identity = loadOrCreateIdentity(stateDir);
    bazarish::Key sealing = loadOrCreateSealingKey(stateDir);

    bazarish::server::DiskStorage storage(stateDir / "storage");
    bazarish::server::DeliveryEngine engine(storage, identity.fingerprint(),
        bazarish::Key::fromPrivatePem(sealing.privatePem()), engineOptions);

    std::printf("bazarish-server %s\n", kVersion);
    std::printf("server fingerprint: %s\n", identity.fingerprint().c_str());

    // Optional I2P federation: a persistent destination, a published server
    // card and the inbound accept loop, plus outbound relay resolved from
    // peers.json. Building the SAM session blocks while tunnels build.
    std::unique_ptr<bazarish::SamSession> samSession;
    std::unique_ptr<bazarish::server::I2pFederation> federation;
    std::unique_ptr<bazarish::server::TcpFederation> tcpFederation;
    bazarish::server::RemoteDeliverFn remoteDeliver;
    std::vector<std::string> endpoints;
    if (enableI2p) {
        const fs::path destPath = stateDir / "i2p-dest.key";
        const std::string privateKeys
            = fs::exists(destPath) ? readFileText(destPath) : std::string("TRANSIENT");
        std::printf("starting I2P federation (building tunnels via SAM)...\n");
        std::fflush(stdout);
        // The SAM session id must be unique per session on the bridge, so
        // several local servers can share one router without colliding.
        const std::string sessionId = "bazarish-fed-" + identity.fingerprint().substr(0, 12);
        samSession = std::make_unique<bazarish::SamSession>(
            bazarish::SamClient::kDefaultHost, bazarish::SamClient::kDefaultPort, sessionId,
            privateKeys, bazarish::kEncryptedLeaseSetType, privacy);
        if (!fs::exists(destPath)) {
            writePrivateFile(destPath, samSession->privateDestination());
        }

        endpoints.push_back("i2p:" + samSession->publicDestination());
        std::printf("i2p destination: %s\n", samSession->publicDestination().c_str());

        // Resolver: server fingerprint -> i2p destination, from peers.json
        // (re-read per call, so peers can be added without a restart).
        const fs::path peersPath = stateDir / "peers.json";
        const auto resolve = [peersPath](const std::string& serverFp) {
            return resolvePeer(peersPath, serverFp);
        };

        federation = std::make_unique<bazarish::server::I2pFederation>(
            *samSession, engine, resolve);
        federation->start();
        remoteDeliver = federation->asRemoteDeliverFn();
    }

    // Optional TCP federation: an operator private-channel / local-testing
    // transport (not a hidden network). Inbound accept loop plus outbound
    // relay; peers resolve from peers.json ({"<server-fp>": "<host:port>"}).
    if (enableTcpFed) {
        const fs::path peersPath = stateDir / "peers.json";
        const auto resolve = [peersPath](const std::string& serverFp) {
            return resolvePeer(peersPath, serverFp);
        };

        tcpFederation
            = std::make_unique<bazarish::server::TcpFederation>(engine, resolve);
        const int boundFedPort = tcpFederation->bindAndListen(fedHost, fedPort);
        if (boundFedPort < 0) {
            std::fprintf(stderr, "failed to bind TCP federation on %s:%d\n",
                fedHost.c_str(), fedPort);
            return 1;
        }
        endpoints.push_back("tcp:" + fedHost + ":" + std::to_string(boundFedPort));
        tcpFederation->start();
        remoteDeliver = tcpFederation->asRemoteDeliverFn();
        std::printf("tcp federation listening on %s:%d\n", fedHost.c_str(), boundFedPort);
    }

    // The server card is always published: clients need the sealing key to
    // seal delivery envelopes and the service node is bound to it. Without
    // --i2p the endpoint list is empty (local delivery only, no federation).
    const bazarish::Bytes card = bazarish::ServerCard::issue(
        identity, endpoints, bazarish::Key::fromPublicDer(sealing.publicDer()), nowSeconds());
    {
        std::ofstream out(stateDir / "server-card.der", std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(card.data()),
            static_cast<std::streamsize>(card.size()));
    }

    bazarish::server::HttpApiOptions httpOptions;
    httpOptions.operatorSecret = operatorSecret;
    // Proxy-fetch blobs over I2P for clients without a local SAM bridge, via a
    // fresh transient session on the local bridge (independent of federation).
    httpOptions.blobProxyFetch
        = [](const std::string& blobHost, const std::string& blobPath) {
              return bazarish::server::fetchBlobOverI2p(bazarish::SamClient::kDefaultHost,
                  bazarish::SamClient::kDefaultPort, blobHost, blobPath);
          };
    bazarish::server::HttpApi api(storage, engine, httpOptions, std::move(remoteDeliver));

    std::printf("listening on %s:%d (private channel for facades)\n", host.c_str(), port);
    std::fflush(stdout);

    if (!api.listen(host, port)) {
        std::fprintf(stderr, "failed to listen on %s:%d\n", host.c_str(), port);
        return 1;
    }
    return 0;
}
