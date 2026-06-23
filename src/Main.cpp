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
#include <bazarish/I2p.hpp>
#include <bazarish/Log.hpp>

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
        "          [--contact-request-limit <bytes>] [--operator-fingerprint <fp>]...\n"
        "          [--privacy <minimal|middle|max>] [--pool-size <n>]\n"
        "          [--tunnel-quantity <n>]\n"
        "          [--federation-rate-limit <n>] [--service-node <url>]\n"
        "          [--log-level <error|warn|info|debug>]\n"
        "       bazarish-server --version\n"
        "\n"
        "The state directory holds the server keys and the content storage;\n"
        "keys are generated on first start. The server card is always written\n"
        "to <state>/server-card.der. --i2p is required: delivery is routed by\n"
        "I2P destination (there is no non-I2P transport); it builds the home\n"
        "destination on the embedded I2P router and adds the i2p endpoint to\n"
        "the card. A send is delivered locally when its toDest is one of this\n"
        "server's destinations, otherwise it is dialled directly over I2P.\n"
        "--contact-request-limit <bytes> caps the tokenless contact-request\n"
        "payload. --pool-size <n> sizes the free-tier address pool (default 10;\n"
        "0 disables it, falling free users back to the home destination).\n"
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
    std::vector<std::string> operatorFingerprints;
    std::string serviceNodeUrl;
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax;
    // Public server destinations carry inbound federation traffic, so they run a
    // full tunnel pool (load balancing across tunnels for one address); 16 is the
    // I2P ceiling. Operators on a constrained uplink can lower it.
    int tunnelQuantity = bazarish::i2p::kMaxTunnelQuantity;
    std::size_t poolSize = 10;
    std::size_t federationRateLimit = 240;  // inbound deliveries per peer dest per 60s
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    for (int i = 3; i < argc;) {
        if (std::strcmp(argv[i], "--listen") == 0 && i + 2 < argc) {
            host = argv[i + 1];
            port = std::atoi(argv[i + 2]);
            i += 3;
        } else if (std::strcmp(argv[i], "--operator-fingerprint") == 0 && i + 1 < argc) {
            operatorFingerprints.emplace_back(argv[i + 1]);
            i += 2;
        } else if (std::strcmp(argv[i], "--i2p") == 0) {
            enableI2p = true;
            i += 1;
        } else if (std::strcmp(argv[i], "--contact-request-limit") == 0 && i + 1 < argc) {
            engineOptions.contactRequestLimitBytes
                = std::strtoull(argv[i + 1], nullptr, 10);
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

    // Optional I2P federation: an embedded router, a persistent home destination,
    // a published server card and the inbound accept loop, plus outbound relay
    // resolved from peers.json.
    std::unique_ptr<bazarish::i2p::Router> router;
    std::shared_ptr<bazarish::i2p::Endpoint> homeEndpoint;
    std::shared_ptr<bazarish::i2p::Endpoint> blobEndpoint;
    std::unique_ptr<bazarish::server::FederationRateLimiter> federationLimiter;
    std::unique_ptr<bazarish::server::I2pFederation> federation;
    std::unique_ptr<bazarish::server::PerUserDestinations> perUserDests;
    std::unique_ptr<bazarish::server::FederationPool> federationPool;
    bazarish::server::RemoteDeliverFn remoteDeliver;
    bazarish::server::RemoteFetchFn remoteFetch;
    std::vector<std::string> endpoints;
    if (enableI2p) {
        const fs::path destPath = stateDir / "i2p-dest.key";
        bazarish::log::info("starting embedded I2P router + federation (building tunnels)...");
        // The embedded router (server role: relays transit). State under <state>/i2p.
        router = std::make_unique<bazarish::i2p::Router>(
            bazarish::i2p::RouterConfig{stateDir / "i2p", bazarish::i2p::Role::eServer});
        const std::string rawHome = fs::exists(destPath) ? readFileText(destPath) : std::string();
        bazarish::i2p::Keys homeKeys = rawHome.empty()
            ? bazarish::i2p::Keys::generate()
            : bazarish::i2p::Keys::fromBlob(bazarish::Bytes(rawHome.begin(), rawHome.end()));
        // Encrypted LeaseSet2 (server-owned): the shareable address is the blinded b33.
        homeEndpoint = router->createEndpoint(bazarish::i2p::EndpointConfig{
            homeKeys, bazarish::i2p::LeaseSetKind::eEncrypted, privacy, tunnelQuantity, true});
        if (!fs::exists(destPath)) {
            const bazarish::Bytes blob = homeEndpoint->privateBlob();
            writePrivateFile(destPath, std::string(blob.begin(), blob.end()));
        }
        // A separate client endpoint for proxying blob ops outbound (no inbound
        // role); connecting out does not need a published leaseset.
        blobEndpoint = router->createEndpoint(bazarish::i2p::EndpointConfig{
            bazarish::i2p::Keys::generate(), bazarish::i2p::LeaseSetKind::eEncrypted, privacy,
            bazarish::i2p::kDefaultTunnelQuantity, false});

        // The shareable/routable address is the b33 (encrypted LeaseSet2): peers
        // reach the encrypted leaseset only via the blinded b33.
        endpoints.push_back("i2p:" + homeEndpoint->routingHost());
        std::printf("i2p destination: %s\n", homeEndpoint->routingHost().c_str());
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
            *homeEndpoint, engine, federationLimiter.get());
        federation->setGetCard(getCard);
        federation->start();
        remoteDeliver = federation->asRemoteDeliverFn();
        remoteFetch = federation->asRemoteFetchFn();

        // Paid per-user destinations: operate client-owned offline keys as the
        // user's personal federation destination. Restore any persisted ones.
        perUserDests = std::make_unique<bazarish::server::PerUserDestinations>(
            router.get(), engine, stateDir, privacy, tunnelQuantity, federationLimiter.get());
        perUserDests->setGetCard(getCard);
        perUserDests->reloadPersisted(nowSeconds());

        // Free-tier address pool: server-owned encrypted-LeaseSet (b33)
        // destinations that free users are spread across. Optional (it builds a
        // tunnel set per destination), enabled by --pool-size.
        if (poolSize > 0) {
            bazarish::log::info(
                "starting federation address pool ({} destinations; building tunnels)...", poolSize);
            federationPool = std::make_unique<bazarish::server::FederationPool>(
                *router, engine, stateDir, privacy, poolSize, tunnelQuantity,
                federationLimiter.get());
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
    httpOptions.operatorFingerprints = operatorFingerprints;
    httpOptions.version = kVersion;
    // Resolve a user's assigned serving destination + key: their personal
    // destination if they delegated one, else their pool destination if the
    // pool is enabled, else the home destination. Used to short-circuit only
    // same-destination deliveries (a send to the sender's own destination) and
    // to surface the destination to the user. homeEndpoint is always set (--i2p
    // is required); homeServingKey is the same key the engine unseals with.
    const auto homeServingKey
        = std::make_shared<bazarish::Key>(bazarish::Key::fromPrivatePem(sealing.privatePem()));
    const std::string homeDest = homeEndpoint->routingHost();
    httpOptions.assignDestination
        = [&perUserDests, &federationPool, homeDest, homeServingKey](
              const std::string& user) -> bazarish::server::DestinationAssignment {
        // A user with a personal destination always resolves to it (its address
        // may be empty until its session builds - then no local short-circuit
        // matches and the delivery federates, which is safe).
        if (perUserDests) {
            const std::shared_ptr<bazarish::Key> key = perUserDests->servingKeyFor(user);
            if (key) {
                const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
                return {perUserDests->destinationFor(user), key,
                    perUserDests->stateFor(user, now)};
            }
        }
        if (federationPool) {
            return {federationPool->destinationFor(user), federationPool->servingKeyFor(user),
                "pool"};
        }
        return {homeDest, homeServingKey, "home"};
    };
    // Proxy blob ops over I2P for clients without their own embedded router, via
    // the server's dedicated blob client endpoint (independent of federation).
    // Unsend (DELETE) is a small whole-body op; downloads (GET) stream so a large
    // blob is never buffered whole here.
    httpOptions.blobProxyFetch = [blobEndpoint](const std::string& method, const std::string& blobHost,
                                     const std::string& blobPath, const std::string& deleteToken) {
        return bazarish::server::fetchBlobOverI2p(*blobEndpoint, blobHost, blobPath, method, deleteToken);
    };
    httpOptions.blobProxyDownload = [blobEndpoint](const std::string& blobHost,
                                        const std::string& blobPath, const std::string& range) {
        return bazarish::server::openBlobDownload(*blobEndpoint, blobHost, blobPath, range);
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
