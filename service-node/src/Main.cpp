// Bazarish project (c) 2026
#include "AccountApi.hpp"
#include "GrantStore.hpp"
#include "PortalApi.hpp"
#include "NodeSettings.hpp"
#include "OperatorPush.hpp"
#include "SubscriptionStore.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Certificates.hpp>
#include <bazarish/ConfigFile.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PrivateFile.hpp>
#include <bazarish/Restart.hpp>
#include <bazarish/ServerDescriptor.hpp>

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
#include <set>
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
        "Usage: bazarish-service-node --config <path>\n"
        "       bazarish-service-node --config <path> --fingerprint\n"
        "       bazarish-service-node --version\n"
        "\n"
        "Everything this node runs on is in the config file: where its state\n"
        "lives, the server card that binds it to its messaging server, the\n"
        "addresses it listens on and reaches, who may act as operator, and what\n"
        "new accounts get. Nothing is settable twice - a flag that could override\n"
        "the file would mean two answers to the same question.\n"
        "--fingerprint prints this node's operator fingerprint (creating its\n"
        "identity if needed) and exits, so the messaging server can be started\n"
        "with it already authorised before this node runs.\n",
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

using bazarish::readFileText;
using bazarish::writePrivateFile;

// Loads the service node's own signing identity from the state directory,
// generating it on first start. The node signs its operator pushes (quota,
// transient) with it, and a backend authorises it by fingerprint.
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

// Portal onboarding presentation, parsed from the config. The message and
// links are advertised by the discovery endpoint so a client knows where to
// register.
struct PortalConfig {
    std::string message;
    // What the portal calls itself and where a user reaches it, in the words the
    // client shows before a login is signed. The address is what the user has in
    // the address bar, so it is the link they were given unless the operator
    // fronts the portal under another one.
    std::string name;
    std::string address;
    // What signing in here is called, in the client's badge: whose account the
    // signature opens.
    std::string role;
    std::vector<std::string> links;
    // This server's facade URLs - I2P addresses, where clients talk to it - shown
    // in the cabinet as part of the server descriptor a client pastes to connect
    // (client failover order).
    std::vector<std::string> facades;
    // Clearnet addresses a client with no router yet asks for a slice of netdb.
    // They carry nothing else.
    std::vector<std::string> reseeds;
};

// Who may be served on this node. Open registration serves an account the
// moment it is created; approval registration creates it frozen and waits for
// the operator. `message` is what a frozen user is shown - how to reach the
// operator to finish registration - and `idleDeleteDays` is how long an account
// is kept with no destination delegated here before it is deleted. That covers
// a client that stopped running, a registration nobody redeemed and an account
// no operator approved: the delegation is the only sign of life a server has.
struct RegistrationConfig {
    bool requireApproval = false;
    std::string message;
    std::int64_t idleDeleteDays = 180;
};

// The node's own config. Nothing here is for sale - the only knobs are the
// storage quota every account gets, how the portal presents itself, and who may
// register.
// Where the node runs and what it runs on. Everything a command line used to
// carry lives here, so there is one place to look and one place to change.
struct NodeConfig {
    std::string stateDir;
    std::string serverCard;
    bazarish::ConfigView::Endpoint listen{kDefaultHost, kDefaultPort};
    bazarish::ConfigView::Endpoint portalListen;
    std::string portalAssets;
    bazarish::ConfigView::Endpoint messaging;
    std::vector<std::string> operators;
    bazarish::log::Level logLevel = bazarish::log::Level::eInfo;
    // The level as the operator spelled it, so the panel can show and change the
    // same word rather than a number nobody wrote.
    std::string logLevelText = "info";
    std::uint64_t freeStorageBytes = 50 * 1024 * 1024;
    PortalConfig portal;
    RegistrationConfig registration;
    // Lets the two address lists hold each other's kind - a clearnet facade, an
    // I2P reseed. Nonsense in a deployment, and exactly what a stand on a LAN
    // needs. The client has a switch by the same name.
    bool allowFacadeWithoutI2pForDevPurposes = false;
};

NodeConfig loadNodeConfig(const fs::path& path)
{
    const nlohmann::json doc = bazarish::ConfigFile(path).read();
    const bazarish::ConfigView view(doc);

    NodeConfig config;
    config.stateDir = view.text("state");
    config.serverCard = view.text("serverCard");
    if (const std::optional<bazarish::ConfigView::Endpoint> listen = view.endpoint("listen");
        listen.has_value()) {
        config.listen = *listen;
    }
    if (const std::optional<bazarish::ConfigView::Endpoint> portal
        = view.endpoint("portal.listen");
        portal.has_value()) {
        config.portalListen = *portal;
    }
    config.portalAssets = view.text("portal.assets");
    if (const std::optional<bazarish::ConfigView::Endpoint> messaging
        = view.endpoint("messaging");
        messaging.has_value()) {
        config.messaging = *messaging;
    }
    config.operators = view.list("operators");
    if (const std::string level = view.text("logLevel"); !level.empty()) {
        const std::optional<bazarish::log::Level> parsed = bazarish::log::levelFromString(level);
        if (!parsed.has_value()) {
            throw std::runtime_error("config: logLevel is not a level");
        }
        config.logLevel = *parsed;
        config.logLevelText = level;
    }
    config.freeStorageBytes = doc.value("freeStorageBytes", config.freeStorageBytes);
    if (doc.contains("portal")) {
        const nlohmann::json& portal = doc.at("portal");
        config.portal.message = portal.value("message", std::string());
        config.portal.name = portal.value("name", std::string());
        config.portal.address = portal.value("address", std::string());
        config.portal.role = portal.value("role", std::string());
        if (portal.contains("links")) {
            config.portal.links = portal.at("links").get<std::vector<std::string>>();
        }
        if (portal.contains("facades")) {
            config.portal.facades = portal.at("facades").get<std::vector<std::string>>();
        }
        if (portal.contains("reseeds")) {
            config.portal.reseeds = portal.at("reseeds").get<std::vector<std::string>>();
        }
    }
    config.allowFacadeWithoutI2pForDevPurposes
        = doc.value("allowFacadeWithoutI2pForDevPurposes", false);
    if (doc.contains("registration")) {
        const nlohmann::json& registration = doc.at("registration");
        config.registration.requireApproval
            = registration.value("requireApproval", config.registration.requireApproval);
        config.registration.message = registration.value("message", std::string());
        config.registration.idleDeleteDays
            = registration.value("idleDeleteDays", config.registration.idleDeleteDays);
    }
    return config;
}

// The words this portal signs under until an operator changes them. The address
// has no default worth inventing: it is the one thing the user checks against
// their address bar, so an unset one stops the portal instead.
bazarish::service::LoginConsumer portalConsumer(const NodeConfig& config)
{
    const char* const kDefaultPortalName = "Bazarish service node";
    const char* const kDefaultPortalRole = "Account owner";
    bazarish::service::LoginConsumer consumer;
    consumer.name = config.portal.name.empty() ? kDefaultPortalName : config.portal.name;
    consumer.place = config.portal.address.empty()
        ? (config.portal.links.empty() ? std::string() : config.portal.links.front())
        : config.portal.address;
    consumer.role = config.portal.role.empty() ? kDefaultPortalRole : config.portal.role;
    return consumer;
}

}  // namespace

int main(const int argc, const char** argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("bazarish-service-node %s\n", kVersion);
        return 0;
    }
    if (argc < 3 || std::strcmp(argv[1], "--config") != 0) {
        printUsage();
        return 2;
    }
    const fs::path configPath(argv[2]);
    NodeConfig nodeConfig;
    try {
        nodeConfig = loadNodeConfig(configPath);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "config: %s\n", error.what());
        return 2;
    }
    if (nodeConfig.stateDir.empty() || nodeConfig.serverCard.empty()) {
        std::fprintf(stderr, "config: \"state\" and \"serverCard\" are required\n");
        return 2;
    }
    const fs::path stateDir(nodeConfig.stateDir);

    // The messaging server must authorise this node's operator fingerprint, but
    // this node cannot start before that server has written its card. This mode
    // breaks the cycle: it materialises the identity and prints the fingerprint,
    // so the server can be started with it already configured.
    if (argc == 4 && std::strcmp(argv[3], "--fingerprint") == 0) {
        fs::create_directories(stateDir);
        std::printf("%s\n", loadOrCreateIdentity(stateDir).fingerprint().c_str());
        return 0;
    }
    if (argc != 3) {
        printUsage();
        return 2;
    }

    const fs::path cardPath(nodeConfig.serverCard);
    const std::string host = nodeConfig.listen.host;
    const int port = nodeConfig.listen.port;
    const std::string portalHost = nodeConfig.portalListen.host;
    const int portalPort = nodeConfig.portalListen.port;
    const fs::path portalAssets(nodeConfig.portalAssets);
    const std::string messagingHost = nodeConfig.messaging.host;
    const int messagingPort = nodeConfig.messaging.port;
    const std::vector<std::string> operatorFingerprints = nodeConfig.operators;
    const bazarish::log::Level logLevel = nodeConfig.logLevel;

    bazarish::log::setComponent("service-node");
    bazarish::log::setLevel(logLevel);

    const bazarish::Bytes cardDer = readFileBytes(cardPath);
    const bazarish::ServerCard card = bazarish::ServerCard::verify(cardDer);

    fs::create_directories(stateDir);
    // The service node's own signing identity: it signs its operator pushes
    // (quota, transient) so the backends authorise it by fingerprint. Print the
    // fingerprint so the operator can list it in each backend's
    // --operator-fingerprint.
    const bazarish::Identity nodeIdentity = loadOrCreateIdentity(stateDir);
    std::printf("service-node operator fingerprint: %s\n", nodeIdentity.fingerprint().c_str());
    bazarish::service::SubscriptionStore store(stateDir / "store");
    bazarish::service::GrantStore grants(stateDir / "store");
    // The private channel carries what this node owns and the messaging server
    // must obey: the user's delegated transient and the quota their subscription
    // granted (else the messaging server would answer with its own default and
    // the user would see a different number than the portal promised).
    const std::string messagingUrl = messagingPort > 0
        ? "http://" + messagingHost + ":" + std::to_string(messagingPort)
        : std::string();
    const bazarish::service::OperatorPush operatorPush(messagingUrl, nodeIdentity);
    // The same channel, for the pushes made while a device waits on the answer.
    // Those run on one of the account API's handful of io threads, so they are
    // given a single attempt: retrying inline would hold that thread for close to
    // two minutes whenever the messaging server is busy, and starve every other
    // request the node has - a device that was refused asks again by itself.
    const bazarish::service::OperatorPush promptPush(messagingUrl, nodeIdentity,
        bazarish::service::OperatorPush::kPromptAttempts);

    bazarish::service::AccountApiOptions options;
    options.serverFingerprint = card.server;
    options.serverCardDer = cardDer;
    options.version = kVersion;
    if (nodeConfig.allowFacadeWithoutI2pForDevPurposes) {
        bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
        bazarish::log::warn("facades and reseeds may hold each other's kind: development only");
    }
    options.operatorFingerprints = operatorFingerprints;
    // One live set of knobs for the account API and the portal, written back to
    // the config file the node was started with, so what an operator changes in
    // the panel is what the node reads at the next start.
    const auto settings = std::make_shared<bazarish::service::NodeSettings>(configPath,
        bazarish::service::NodeSettings::Values{
            .requireApproval = nodeConfig.registration.requireApproval,
            .registrationMessage = nodeConfig.registration.message,
            .portalMessage = nodeConfig.portal.message,
            .loginConsumer = portalConsumer(nodeConfig),
            .facades = nodeConfig.portal.facades,
            .reseeds = nodeConfig.portal.reseeds,
            .portalLinks = nodeConfig.portal.links,
            .logLevel = nodeConfig.logLevelText,
            .listenHost = nodeConfig.listen.host,
            .listenPort = nodeConfig.listen.port,
            .portalListenHost = nodeConfig.portalListen.host,
            .portalListenPort = nodeConfig.portalListen.port,
            .messagingHost = nodeConfig.messaging.host,
            .messagingPort = nodeConfig.messaging.port,
            .defaultQuotaBytes = nodeConfig.freeStorageBytes,
            .idleDeleteDays = nodeConfig.registration.idleDeleteDays});
    options.settings = settings;
    options.defaultQuotaBytes = nodeConfig.freeStorageBytes;
    options.portalMessage = nodeConfig.portal.message;
    options.portalLinks = nodeConfig.portal.links;
    options.registration = nodeConfig.registration.requireApproval
        ? bazarish::service::AccountApiOptions::Registration::eApproval
        : bazarish::service::AccountApiOptions::Registration::eOpen;
    options.registrationMessage = nodeConfig.registration.message;
    options.publishI2pTransient = [&promptPush](const std::string& user,
                                      const std::string& transientB64,
                                      const std::int64_t expiresUnix) {
        return promptPush.publish(user, transientB64, expiresUnix);
    };
    options.forgetMailbox
        = [&promptPush](const std::string& user) { return promptPush.forgetMailbox(user); };
    options.prepareServingKey = [&promptPush](const std::string& user) {
        return promptPush.prepareServingKey(user);
    };
    options.commitServingKey = [&promptPush](const std::string& user) {
        return promptPush.commitServingKey(user);
    };
    options.publishQuota = [&promptPush](const std::string& user,
                               const std::uint64_t quotaBytes) {
        if (!promptPush.publishQuota(user, quotaBytes)) {
            // Not fatal to the subscription - but the user would then be served the
            // messaging server's own default and see a figure nobody promised them.
            bazarish::log::warn("quota not pushed for {}: the messaging server refused it",
                bazarish::log::redact(user));
        }
    };
    // The two daemons are restarted together, so the messaging server may still be
    // binding its port. Waited for once, here, rather than discovered by the first
    // push spending its retries on a socket that is not listening yet.
    constexpr std::chrono::seconds kBackendWaitBudget{60};
    (void)operatorPush.waitReachable(kBackendWaitBudget);
    // Quotas the messaging server may have missed: an account registered before
    // this node started pushing them would be served the messaging server's own
    // default, and the user would see a figure nobody promised. Pushing them at
    // start costs one request each.
    for (const bazarish::service::SubscriptionStore::Account& account : store.allAccounts()) {
        if (!operatorPush.publishQuota(account.user, account.quotaBytes)) {
            bazarish::log::warn("quota for {} not reconciled at start",
                bazarish::log::redact(account.user));
        }
    }

    // Filled in once the API exists; the handler reads the slot when called.
    const auto restartHook = std::make_shared<std::function<void()>>();
    options.requestRestart = [restartHook]() {
        if (*restartHook) {
            (*restartHook)();
        }
    };

    bazarish::service::AccountApi api(store, grants, options);

    static std::unique_ptr<bazarish::service::PortalApi> portal;
    static std::thread portalThread;

    // Stopping happens on the switch's own thread: a handler must not stop the
    // server it is still answering on. The portal is stopped with it - its
    // serving thread waits on a condition variable this process would otherwise
    // destroy underneath it on the way out.
    bazarish::RestartSwitch restart([&api]() {
        if (portal) {
            portal->stop();
        }
        api.stop();
    });
    *restartHook = [&restart]() { restart.request(); };

    // The browser-facing portal (sign-in-with-key, which is the registration),
    // sharing the grant store with the account API. Secrets are per-run; a
    // restart simply invalidates outstanding challenges/sessions.
    if (portalPort > 0) {
        if (portalAssets.empty()) {
            bazarish::log::error("--portal-listen needs --portal-assets: the portal serves its "
                                 "pages from files, not from the binary");
            return 2;
        }
        bazarish::service::PortalApiOptions portalOptions;
        portalOptions.serverFingerprint = card.server;
        // Where the archive comes from. The portal publishes it because the
        // portal is what the clearnet reaches; the messaging server packs it
        // because that is where the netDb is.
        portalOptions.reseedArchiveUrl
            = messagingUrl.empty() ? std::string() : messagingUrl + "/internal/i2pseeds.su3";
        // Who the portal says it is, for the client to show before a user signs
        // a login. Its own words: a name a user recognises and the address they
        // opened, which is the link the node advertises unless the operator
        // fronts it under another one.
        portalOptions.consumer = settings->get().loginConsumer;
        if (portalOptions.consumer.place.empty()) {
            bazarish::log::error("--portal-listen needs portal.address (or portal.links): a "
                                 "portal that will not say where it lives asks users to sign "
                                 "for a name they cannot check");
            return 2;
        }
        // The server descriptor a client pastes to connect: this server's
        // fingerprint plus its configured facade URLs, shown in the cabinet.
        portalOptions.serverDescriptor = bazarish::encodeServerDescriptor(
            {card.server, nodeConfig.portal.facades, nodeConfig.portal.reseeds});
        portalOptions.challengeSecret = bazarish::toHex(bazarish::randomBytes(16));
        portalOptions.sessionSecret = bazarish::toHex(bazarish::randomBytes(16));
        portalOptions.defaultQuotaBytes = options.defaultQuotaBytes;
        portalOptions.requiresApproval = nodeConfig.registration.requireApproval;
        portalOptions.registrationMessage = nodeConfig.registration.message;
        portalOptions.assetsDirectory = portalAssets;
        portalOptions.settings = settings;
        // The mailbox and the devices belong to the messaging server; the portal
        // asks it, signed as this node.
        portalOptions.accountUsage = [&operatorPush](const std::string& user)
            -> std::optional<bazarish::service::PortalApiOptions::Usage> {
            const std::optional<bazarish::service::OperatorPush::AccountUsage> usage
                = operatorPush.accountUsage(user);
            if (!usage.has_value()) {
                return std::nullopt;
            }
            return bazarish::service::PortalApiOptions::Usage{
                usage->usedBytes, usage->quotaBytes, usage->devices};
        };
        // A user ending their own account: the same teardown unsubscribing does.
        portalOptions.deleteAccount = [&store, &grants, &operatorPush](const std::string& user) {
            store.deleteAccount(user);
            operatorPush.publish(user, std::string(), 0);
            grants.erase(user);
            bazarish::log::info("account deleted by its owner: {}", bazarish::log::redact(user));
        };
        try {
            portal = std::make_unique<bazarish::service::PortalApi>(portalOptions, grants);
        } catch (const std::exception& error) {
            bazarish::log::error("portal not started: {}", error.what());
            return 2;
        }
        portalThread = std::thread(
            [portalHost, portalPort]() { portal->listen(portalHost, portalPort); });
        portalThread.detach();
        bazarish::log::info("portal on {}:{}", portalHost, portalPort);
    }

    // An account lives while its owner keeps a destination delegated here. One
    // that stopped - a client nobody runs any more, a registration nobody
    // redeemed, an account no operator approved - is dropped after the idle
    // window, so a dead account does not hold a fingerprint and a quota forever.
    static std::thread sweepThread;
    sweepThread = std::thread([&grants, &store, settings,
                                  revoke = [&operatorPush](const std::string& user) {
                                      return operatorPush.publish(user, std::string(), 0);
                                  }]() {

        while (true) {
            std::this_thread::sleep_for(std::chrono::hours(1));
            const std::int64_t idleDays = settings->get().idleDeleteDays;
            if (idleDays <= 0) {
                continue;  // the operator keeps them forever
            }
            const std::int64_t idleSeconds = idleDays * bazarish::kSecondsPerDay;
            const std::int64_t now = bazarish::nowSeconds();
            // Registrations that never became accounts are known to the grant
            // store only; served accounts are known to both.
            std::set<std::string> users;
            for (const std::string& user : grants.allUsers()) {
                users.insert(user);
            }
            for (const auto& account : store.allAccounts()) {
                users.insert(account.user);
            }
            for (const std::string& user : users) {
                const std::optional<bazarish::service::SubscriptionStore::Account> account
                    = store.getAccount(user);
                std::int64_t since = 0;
                if (account.has_value() && account->delegatedAt != 0) {
                    since = account->delegatedAt;
                } else if (account.has_value() && account->registeredAt != 0) {
                    since = account->registeredAt;
                } else if (const std::optional<bazarish::service::GrantStore::Approval> approval
                    = grants.peekApproval(user);
                    approval.has_value()) {
                    since = approval->requestedAt;
                } else if (const std::optional<bazarish::service::GrantStore::SubscriptionGrant>
                        grant
                    = grants.peekSubscription(user);
                    grant.has_value()) {
                    since = grant->grantedAt;
                }
                if (since == 0 || since + idleSeconds > now) {
                    continue;
                }
                // A ban outlives the account it removed, so only the account goes.
                (void)revoke(user);
                grants.erase(user);  // a ban is stored apart and stays
                store.deleteAccount(user);
                bazarish::log::info("swept idle account {}", user.substr(0, 12));
            }
        }
    });
    sweepThread.detach();

    std::printf("bazarish-service-node %s\n", kVersion);
    std::printf("bound to server: %s\n", card.server.c_str());
    std::fflush(stdout);
    bazarish::log::info("listening on {}:{} (private channel for facades)", host, port);

    if (!api.listen(host, port)) {
        if (restart.requested()) {
            return bazarish::kRestartExitCode;
        }
        bazarish::log::error("failed to listen on {}:{}", host, port);
        return 1;
    }
    return restart.requested() ? bazarish::kRestartExitCode : 0;
}
