// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"
#include "FederationPool.hpp"
#include "FederationRateLimiter.hpp"
#include "HttpApi.hpp"
#include "I2pFederation.hpp"
#include "PerUserDestinations.hpp"

#include <bazarish/Certificates.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/Sam.hpp>

#include <httplib/httplib.h>
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
        "Usage: bazarish-server --state <directory> --i2p [--listen <host> <port>]\n"
        "          [--contact-request-limit <bytes>] [--operator-secret <secret>]\n"
        "          [--privacy <minimal|middle|max>] [--pool-size <n>]\n"
        "          [--federation-rate-limit <n>] [--service-node <url>]\n"
        "          [--log-level <error|warn|info|debug>]\n"
        "       bazarish-server --version\n"
        "\n"
        "The state directory holds the server keys and the content storage;\n"
        "keys are generated on first start. The server card is always written\n"
        "to <state>/server-card.der. --i2p is required: delivery is routed by\n"
        "I2P destination (there is no non-I2P transport); it builds the home\n"
        "destination over a local SAM bridge and adds the i2p endpoint to the\n"
        "card. A send is delivered locally when its toDest is one of this\n"
        "server's destinations, otherwise it is dialled directly over I2P.\n"
        "--contact-request-limit <bytes> caps the tokenless contact-request\n"
        "payload. --pool-size <n> brings up a free-tier address pool.\n"
        "--federation-rate-limit caps inbound I2P deliveries per connecting\n"
        "destination per 60s (default 240, 0 disables). --service-node <url>\n"
        "is the local service node (e.g. http://127.0.0.1:PORT) used to answer\n"
        "first-contact card fetches by fingerprint; without it card fetch is off.\n",
        kVersion);
}

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
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
    bazarish::server::DeliveryEngineOptions engineOptions;
    std::string operatorSecret;
    std::string serviceNodeUrl;
    bazarish::I2pPrivacy privacy = bazarish::I2pPrivacy::kMax;
    std::size_t poolSize = 0;
    std::size_t federationRateLimit = 240;  // inbound deliveries per peer dest per 60s
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
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
        } else if (std::strcmp(argv[i], "--pool-size") == 0 && i + 1 < argc) {
            poolSize = static_cast<std::size_t>(std::strtoull(argv[i + 1], nullptr, 10));
            i += 2;
        } else if (std::strcmp(argv[i], "--federation-rate-limit") == 0 && i + 1 < argc) {
            federationRateLimit = static_cast<std::size_t>(std::strtoull(argv[i + 1], nullptr, 10));
            i += 2;
        } else if (std::strcmp(argv[i], "--service-node") == 0 && i + 1 < argc) {
            serviceNodeUrl = argv[i + 1];
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

    // Delivery is routed purely by I2P destination, so the server must operate
    // one: --i2p is required (there is no non-I2P transport).
    if (!enableI2p) {
        std::fprintf(stderr,
            "I2P federation is required: rerun with --i2p (delivery is routed by I2P "
            "destination; there is no non-I2P transport).\n");
        return 2;
    }

    bazarish::log::setComponent("server-core");
    bazarish::log::setLevel(logLevel);

    fs::create_directories(stateDir);
    const bazarish::Identity identity = loadOrCreateIdentity(stateDir);
    bazarish::Key sealing = loadOrCreateSealingKey(stateDir);

    bazarish::server::DiskStorage storage(stateDir / "storage");
    bazarish::server::DeliveryEngine engine(storage, identity.fingerprint(),
        bazarish::Key::fromPrivatePem(sealing.privatePem()), engineOptions);

    std::printf("bazarish-server %s\n", kVersion);
    std::printf("server fingerprint: %s\n", identity.fingerprint().c_str());
    std::fflush(stdout);

    // Optional I2P federation: a persistent destination, a published server
    // card and the inbound accept loop, plus outbound relay resolved from
    // peers.json. Building the SAM session blocks while tunnels build.
    std::unique_ptr<bazarish::SamSession> samSession;
    std::unique_ptr<bazarish::server::FederationRateLimiter> federationLimiter;
    std::unique_ptr<bazarish::server::I2pFederation> federation;
    std::unique_ptr<bazarish::server::PerUserDestinations> perUserDests;
    std::unique_ptr<bazarish::server::FederationPool> federationPool;
    bazarish::server::RemoteDeliverFn remoteDeliver;
    bazarish::server::RemoteFetchFn remoteFetch;
    std::vector<std::string> endpoints;
    if (enableI2p) {
        const fs::path destPath = stateDir / "i2p-dest.key";
        const std::string privateKeys
            = fs::exists(destPath) ? readFileText(destPath) : std::string("TRANSIENT");
        bazarish::log::info("starting I2P federation (building tunnels via SAM)...");
        // The SAM session id must be unique per session on the bridge, so
        // several local servers can share one router without colliding.
        const std::string sessionId = "bazarish-fed-" + identity.fingerprint().substr(0, 12);
        samSession = std::make_unique<bazarish::SamSession>(
            bazarish::SamClient::kDefaultHost, bazarish::SamClient::kDefaultPort, sessionId,
            privateKeys, bazarish::kEncryptedLeaseSetType, privacy);
        if (!fs::exists(destPath)) {
            writePrivateFile(destPath, samSession->privateDestination());
        }

        // The shareable/routable address is the b33 (encrypted LeaseSet2), not
        // the raw destination — peers can only reach the encrypted leaseset via
        // the blinded b33.
        endpoints.push_back("i2p:" + samSession->routingAddress());
        std::printf("i2p destination: %s\n", samSession->routingAddress().c_str());
        std::fflush(stdout);

        // Inbound federation accountability is per-connecting-destination: one
        // limiter, shared across every accept loop (home destination, address
        // pool, per-user destinations), so a single peer cannot flood us.
        // --federation-rate-limit 0 disables it.
        if (federationRateLimit > 0) {
            federationLimiter = std::make_unique<bazarish::server::FederationRateLimiter>(
                federationRateLimit, 60);
        }

        // First-contact card fetch (op "card"): answer a peer's sealed query for
        // a local user's contact card by looking it up at the service node by
        // fingerprint. Served on every destination's accept loop (home, pool,
        // per-user) so a descriptor pointing at any of them resolves. Only when
        // --service-node is set (else CARD_UNKNOWN).
        bazarish::server::GetCardFn getCard;
        if (!serviceNodeUrl.empty()) {
            getCard = [serviceNodeUrl](const std::string& fp) -> std::optional<bazarish::Bytes> {
                httplib::Client client(serviceNodeUrl);
                client.set_connection_timeout(5);
                client.set_read_timeout(5);
                const httplib::Result res = client.Get("/v1/account/contact?user=" + fp);
                if (!res || res->status != 200) {
                    return std::nullopt;
                }
                try {
                    const nlohmann::json body = nlohmann::json::parse(res->body);
                    return bazarish::fromBase64(body.at("subscriptionCert").get<std::string>());
                } catch (const std::exception&) {
                    return std::nullopt;
                }
            };
        }

        federation = std::make_unique<bazarish::server::I2pFederation>(
            *samSession, engine, federationLimiter.get());
        federation->setGetCard(getCard);
        federation->start();
        remoteDeliver = federation->asRemoteDeliverFn();
        remoteFetch = federation->asRemoteFetchFn();

        // Paid per-user destinations: operate client-owned offline keys as the
        // user's personal federation destination. Restore any persisted ones.
        perUserDests = std::make_unique<bazarish::server::PerUserDestinations>(
            bazarish::SamClient::kDefaultHost, bazarish::SamClient::kDefaultPort,
            engine, stateDir, privacy, federationLimiter.get());
        perUserDests->setGetCard(getCard);
        perUserDests->reloadPersisted(nowSeconds());

        // Free-tier address pool: server-owned encrypted-LeaseSet (b33)
        // destinations that free users are spread across. Optional (it builds a
        // tunnel set per destination), enabled by --pool-size.
        if (poolSize > 0) {
            bazarish::log::info(
                "starting federation address pool ({} destinations; building tunnels)...", poolSize);
            federationPool = std::make_unique<bazarish::server::FederationPool>(
                bazarish::SamClient::kDefaultHost, bazarish::SamClient::kDefaultPort, engine,
                stateDir, "bazarish-pool-" + identity.fingerprint().substr(0, 8) + "-", privacy,
                poolSize, federationLimiter.get());
            federationPool->setGetCard(getCard);
            federationPool->start();
            bazarish::log::info("address pool up: {} destinations",
                federationPool->destinations().size());
        }
    }

    // The server card is always published: clients need the sealing key to
    // seal delivery envelopes and the service node is bound to it. The endpoint
    // list carries the home I2P destination (delivery is routed by destination).
    const bazarish::Bytes card = bazarish::ServerCard::issue(
        identity, endpoints, bazarish::Key::fromPublicDer(sealing.publicDer()), nowSeconds());
    {
        std::ofstream out(stateDir / "server-card.der", std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(card.data()),
            static_cast<std::streamsize>(card.size()));
    }

    bazarish::server::HttpApiOptions httpOptions;
    httpOptions.operatorSecret = operatorSecret;
    // Resolve a user's assigned serving destination + key: their personal
    // destination if they delegated one, else their pool destination if the
    // pool is enabled, else the home destination. Used to short-circuit only
    // same-destination deliveries (a send to the sender's own destination) and
    // to surface the destination to the user. samSession is always set (--i2p
    // is required); homeServingKey is the same key the engine unseals with.
    const auto homeServingKey
        = std::make_shared<bazarish::Key>(bazarish::Key::fromPrivatePem(sealing.privatePem()));
    const std::string homeDest = samSession->routingAddress();
    httpOptions.assignDestination
        = [&perUserDests, &federationPool, homeDest, homeServingKey](
              const std::string& user) -> bazarish::server::DestinationAssignment {
        // A user with a personal destination always resolves to it (its address
        // may be empty until its session builds — then no local short-circuit
        // matches and the delivery federates, which is safe).
        if (perUserDests) {
            const std::shared_ptr<bazarish::Key> key = perUserDests->servingKeyFor(user);
            if (key) {
                return {perUserDests->destinationFor(user), key};
            }
        }
        if (federationPool) {
            return {federationPool->destinationFor(user), federationPool->servingKeyFor(user)};
        }
        return {homeDest, homeServingKey};
    };
    // Proxy blob ops over I2P for clients without a local SAM bridge, via a fresh
    // transient session on the local bridge (independent of federation). Unsend
    // (DELETE) is a small whole-body op; downloads (GET) stream so a large blob is
    // never buffered whole here.
    httpOptions.blobProxyFetch = [](const std::string& method, const std::string& blobHost,
                                     const std::string& blobPath, const std::string& deleteToken) {
        return bazarish::server::fetchBlobOverI2p(bazarish::SamClient::kDefaultHost,
            bazarish::SamClient::kDefaultPort, blobHost, blobPath, method, deleteToken);
    };
    httpOptions.blobProxyDownload = [](const std::string& blobHost, const std::string& blobPath,
                                        const std::string& range) {
        return bazarish::server::openBlobDownload(bazarish::SamClient::kDefaultHost,
            bazarish::SamClient::kDefaultPort, blobHost, blobPath, range);
    };
    if (perUserDests) {
        httpOptions.provisionI2pDest = [&perUserDests](const std::string& user,
                                           const std::string& transientB64,
                                           const std::int64_t expiresUnix) {
            perUserDests->provision(user, transientB64, expiresUnix);
        };
        httpOptions.revokeI2pDest = [&perUserDests](const std::string& user) {
            perUserDests->revoke(user);
        };
    }
    bazarish::server::HttpApi api(
        storage, engine, httpOptions, std::move(remoteDeliver), std::move(remoteFetch));

    bazarish::log::info("listening on {}:{} (private channel for facades)", host, port);

    if (!api.listen(host, port)) {
        bazarish::log::error("failed to listen on {}:{}", host, port);
        return 1;
    }
    return 0;
}
