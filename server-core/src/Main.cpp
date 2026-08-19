// Bazarish project (c) 2026
#include "DeliveryEngine.hpp"
#include "DiskStorage.hpp"
#include "WarmDestPool.hpp"
#include "FederationRateLimiter.hpp"
#include "EventGate.hpp"
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
#include <thread>

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
        "          [--privacy <minimal|middle|max>] [--tunnel-quantity <n>]\n"
        "          [--federation-rate-limit <n>] [--service-node <url>]\n"
        "          [--mailbox-retention <days>]\n"
        "          [--log-level <error|warn|info|debug>] [--i2p-log]\n"
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
        "payload.\n"
        "--federation-rate-limit caps inbound I2P deliveries per connecting\n"
        "destination per 60s (default 240, 0 disables). --mailbox-retention\n"
        "<days> is the TTL backstop that reclaims mail never acked by all of a\n"
        "user's devices (default 30, 0 disables); the primary cleanup is\n"
        "delete-on-all-devices-acked. --service-node <url> is the local service\n"
        "node (e.g. http://127.0.0.1:PORT) used to answer first-contact card\n"
        "fetches by fingerprint; without it card fetch is off.\n",
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
    // Warm pool of single-use transient outbound dests for anonymous card/resolve
    // fetches: target adapts between min and max with demand. 0 max disables it
    // (fetches then dial from the home dest).
    std::size_t warmPoolMin = 2;
    std::size_t warmPoolMax = 10;
    std::size_t federationRateLimit = 240;  // inbound deliveries per peer dest per 60s
    std::int64_t mailboxRetentionDays = 30;  // TTL backstop for never-fully-acked mail (0 = off)
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    // libi2pd's own logging is off by default (fresh common); --i2p-log re-enables
    // it for debugging.
    bool i2pLog = false;
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
        } else if (std::strcmp(argv[i], "--warm-pool-max") == 0 && i + 1 < argc) {
            warmPoolMax = static_cast<std::size_t>(std::strtoull(argv[i + 1], nullptr, 10));
            i += 2;
        } else if (std::strcmp(argv[i], "--federation-rate-limit") == 0 && i + 1 < argc) {
            federationRateLimit = static_cast<std::size_t>(std::strtoull(argv[i + 1], nullptr, 10));
            i += 2;
        } else if (std::strcmp(argv[i], "--mailbox-retention") == 0 && i + 1 < argc) {
            mailboxRetentionDays = std::atoll(argv[i + 1]);
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
        } else if (std::strcmp(argv[i], "--i2p-log") == 0) {
            i2pLog = true;
            ++i;
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
    // Route libi2pd's own logs into our log only when explicitly requested.
    if (i2pLog) {
        bazarish::i2p::setI2pLogging(true);
    }

    fs::create_directories(stateDir);
    const bazarish::Identity identity = loadOrCreateIdentity(stateDir);
    bazarish::Key sealing = loadOrCreateSealingKey(stateDir);

    bazarish::server::DiskStorage storage(stateDir / "storage");
    // Clients that hold a request open are woken from here: a delivery tells the
    // gate, the gate resumes the coroutine serving that client.
    bazarish::server::EventGate eventGate;
    engineOptions.onDelivered = [&eventGate](const std::string& user) { eventGate.notify(user); };
    bazarish::server::DeliveryEngine engine(storage, identity.fingerprint(),
        bazarish::Key::fromPrivatePem(sealing.privatePem()), engineOptions);

    std::printf("bazarish-server %s\n", kVersion);
    std::printf("server fingerprint: %s\n", identity.fingerprint().c_str());
    std::fflush(stdout);

    // I2P: an embedded router, a published server card, and the destinations the
    // users own. The server keeps NO destination of its own - inbound federation
    // arrives on each user's destination and outbound discovery dials from
    // one-time transients, so there is no shared address to attribute or block.
    std::unique_ptr<bazarish::i2p::Router> router;
    std::unique_ptr<bazarish::server::FederationRateLimiter> federationLimiter;
    // Declared before `federation` so it OUTLIVES it (federation holds a raw pointer
    // to the pool); the router, declared earlier, outlives the pool's warmer thread.
    std::unique_ptr<bazarish::server::WarmDestPool> warmPool;
    std::unique_ptr<bazarish::server::I2pFetch> discovery;
    std::unique_ptr<bazarish::server::PerUserDestinations> perUserDests;
    bazarish::server::RemoteDeliverFn remoteDeliver;
    bazarish::server::RemoteFetchFn remoteFetch;
    std::vector<std::string> endpoints;
    if (enableI2p) {
        bazarish::log::info("starting embedded I2P router (building tunnels)...");
        // The embedded router (server role: relays transit). State under <state>/i2p.
        router = std::make_unique<bazarish::i2p::Router>(
            bazarish::i2p::RouterConfig{stateDir / "i2p", bazarish::i2p::Role::eServer});

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
        // fingerprint. Served on the home and per-user accept loops so a
        // descriptor pointing at either resolves. Only when
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


        // Warm pool of single-use transient dests: a card/resolve fetch always
        // dials from a fresh one-time dest (anonymous, never reused), and the pool
        // just hides the tunnel build. With --warm-pool-max 0 each fetch builds
        // its own and waits for it.
        if (warmPoolMax > 0) {
            bazarish::server::WarmDestPool::Options warmOptions;
            warmOptions.minSize = std::min(warmPoolMin, warmPoolMax);
            warmOptions.maxSize = warmPoolMax;
            warmOptions.privacy = privacy;
            warmOptions.tunnelQuantity = tunnelQuantity;
            warmPool = std::make_unique<bazarish::server::WarmDestPool>(*router, warmOptions);
            warmPool->start();
            bazarish::log::info("warm one-time dest pool up (target {}..{})", warmOptions.minSize,
                warmOptions.maxSize);
        }
        // Discovery (card/resolve) dials from a one-time dest; user-to-user
        // delivery dials from each sender's own serving dest (below). Neither
        // uses a shared server address, because there is none.
        discovery = std::make_unique<bazarish::server::I2pFetch>(*router, warmPool.get());
        remoteFetch = discovery->asRemoteFetchFn();

        // The destinations the users own: client-owned offline keys operated as
        // each user's federation destination. Restore any persisted ones.
        perUserDests = std::make_unique<bazarish::server::PerUserDestinations>(
            router.get(), engine, stateDir, privacy, tunnelQuantity, federationLimiter.get());
        perUserDests->setGetCard(getCard);
        perUserDests->reloadPersisted(nowSeconds());

        // Outbound user-to-user federation dials the recipient FROM the sender's
        // own serving destination - the server has no shared address to fall back
        // on - so the recipient acks back to that dest. Resolved per send from the
        // sender's serving dest carried on the delivery job.
        bazarish::server::PerUserDestinations* const perUser = perUserDests.get();
        remoteDeliver = [perUser](const std::string& senderDest, const std::string& toDest,
                            const bazarish::Bytes& sealed, const bazarish::Bytes& payload,
                            const bazarish::server::FederationPhaseFn& onPhase)
            -> bazarish::server::RemoteDeliveryResult {
            std::shared_ptr<bazarish::i2p::Endpoint> from;
            if (perUser) {
                from = perUser->endpointForDest(senderDest);
            }
            if (!from) {
                // No serving endpoint for this sender (its destination has not
                // built yet, or the account is not activated): leave it for retry.
                bazarish::log::info(
                    "fed-out: no serving endpoint for sender {}", senderDest.substr(0, 12));
                bazarish::server::RemoteDeliveryResult unreachable;
                unreachable.reachable = false;
                return unreachable;
            }
            return bazarish::server::federationDeliver(*from, toDest, sealed, payload, onPhase);
        };
    }

    // The server card is always published: clients need the sealing key to seal
    // delivery envelopes and the service node is bound to it. It carries NO
    // transport endpoint: the server has no address of its own to advertise -
    // users are reached at their own destinations, and the way in for clients is
    // the facade, whose addresses live in the server descriptor.
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
    // Report the same default quota the delivery engine enforces, so the
    // storage-usage endpoint matches what a user without an override actually gets.
    httpOptions.defaultQuotaBytes = engineOptions.defaultQuotaBytes;
    httpOptions.mailboxRetentionSeconds
        = mailboxRetentionDays > 0 ? mailboxRetentionDays * 24 * 3600 : 0;
    // Resolve a user's serving destination + key: their own destination, or
    // nothing. There is deliberately no shared fallback - a user without a
    // destination is simply not served yet, because any shared address would
    // make every user behind it provably co-located. Used to short-circuit only
    // same-destination deliveries (a send to the sender's own destination) and
    // to surface the destination to the user.
    if (router) {
        httpOptions.reseedSample
            = [](const std::size_t count) { return bazarish::i2p::sampleRouterInfos(count); };
    }
    httpOptions.assignDestination
        = [&perUserDests](const std::string& user) -> bazarish::server::DestinationAssignment {
        // The address may be empty until the session builds - then no local
        // short-circuit matches and the delivery federates, which is safe.
        if (perUserDests) {
            const std::shared_ptr<bazarish::Key> key = perUserDests->servingKeyFor(user);
            if (key) {
                const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
                return {perUserDests->destinationFor(user), key,
                    perUserDests->stateFor(user, now)};
            }
        }
        return {std::string(), nullptr, "none"};
    };
    // Proxy blob ops over I2P for clients without their own embedded router, via
    // the server's dedicated blob client endpoint (independent of federation).
    // Unsend (DELETE) is a small whole-body op; downloads (GET) stream so a large
    // blob is never buffered whole here.
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

    // The long-poll face is a route on the same server now, so there is one port,
    // one parser and one set of limits.
    api.setEventGate(&eventGate);

    // Wire delivery acknowledgement (no shared address - per-user federation).
    // When a serving destination stores a federated message it sends a
    // delivered-ack, signed with THAT destination's own per-destination signing
    // key (passed in by the serving accept loop, never the server root identity),
    // back to the sender's serving dest, dialled FROM the destination that
    // received the delivery. So two users this server hosts on different
    // destinations share no ack signer and cannot be clustered as co-located. The
    // sender receives it on its own serving accept loop and marks the matching
    // attempt delivered (amber). The signature is computed on the serving thread;
    // only the network send is detached so serving stays responsive.
    bazarish::server::AckSenderFn ackSender
        = [](bazarish::i2p::Endpoint& from, const std::string& toDest,
              const std::string& messageId, const bazarish::Key& signingKey) {
              const bazarish::Bytes sig = bazarish::sign(
                  signingKey, bazarish::Bytes(messageId.begin(), messageId.end()));
              const bazarish::Bytes pub = signingKey.publicDer();
              bazarish::i2p::Endpoint* const fromPtr = &from;
              std::thread([fromPtr, toDest, messageId, sig, pub]() {
                  bazarish::server::federationSendAck(*fromPtr, toDest, messageId, pub, sig);
              }).detach();
          };
    const auto onAck
        = [&api](const std::string& messageId) { api.markDeliveredByMessageId(messageId); };
    if (perUserDests) {
        perUserDests->setAckSender(ackSender);
        perUserDests->setOnAck(onAck);
    }

    bazarish::log::info("listening on {}:{} (private channel for facades)", host, port);

    if (!api.listen(host, port)) {
        bazarish::log::error("failed to listen on {}:{}", host, port);
        return 1;
    }
    return 0;
}
